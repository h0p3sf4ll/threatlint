"""Local Semgrep execution, fixture proof gates, publishing, and rule merging."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from threatlint import semgrep_rule_text


def _login_verified(executable, env) -> bool:
    token = env.get("SEMGREP_APP_TOKEN")
    if token:
        from threatlint.tls import ssl_context  # noqa: PLC0415
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_args, **_kwargs):
                return None
        opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl_context()))
        request = urllib.request.Request("https://semgrep.dev/api/agent/deployments/current", headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        with opener.open(request, timeout=25) as response:
            payload = json.loads(response.read(100001))
        deployment = payload.get("deployment") if isinstance(payload, dict) else None
        return isinstance(deployment, dict) and type(deployment.get("id")) is int
    login = subprocess.run([executable, "show", "deployment", "--json"], capture_output=True, text=True,
                           timeout=30, check=False, env=env, shell=False)
    if login.returncode:
        return False
    try:
        payload = json.loads(login.stdout)
    except ValueError:
        return False
    if not isinstance(payload, dict):
        return False
    deployment = payload.get("deployment")
    identifier = payload.get("id") if "id" in payload else deployment.get("id") if isinstance(deployment, dict) else None
    return type(identifier) is int


def _pro_candidates(executable: str) -> list[Path]:
    """Common pip, pipx, Homebrew, and Windows package layouts, plus PATH."""
    suffix = ".exe" if os.name == "nt" else ""
    name = "semgrep-core-proprietary" + suffix
    candidates = []
    on_path = shutil.which(name)
    if on_path:
        candidates.append(Path(on_path))
    entry = Path(executable).resolve()
    for root in (entry.parent, entry.parent.parent):
        candidates.append(root / name)
        for pattern in ("lib/python*/site-packages/semgrep/bin/" + name,
                        "libexec/lib/python*/site-packages/semgrep/bin/" + name,
                        "Lib/site-packages/semgrep/bin/" + name):
            candidates.extend(root.glob(pattern))
    return list(dict.fromkeys(candidates))


def engine_status(*, environment) -> dict:
    """Inspect installed binaries only; no login check, download, or repository scan."""
    executable = shutil.which("semgrep")
    status = {"cli_version": None, "pro_ready": False}
    if not executable:
        return status
    env = environment()
    env.update(SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
    try:
        result = subprocess.run([executable, "--version"], capture_output=True, text=True,
                                timeout=15, check=False, env=env, shell=False)
        if result.returncode or not result.stdout.strip():
            return status
        version = result.stdout.strip().splitlines()[0]
        status["cli_version"] = version
        for binary in _pro_candidates(executable):
            stamp = binary.parent / "pro-installed-by.txt"
            if not binary.is_file() or not os.access(binary, os.X_OK) or not stamp.is_file():
                continue
            if stamp.read_text(encoding="utf-8").strip() != version:
                continue
            check = subprocess.run([str(binary), "-pro_version"], capture_output=True, text=True,
                                   timeout=15, check=False, env=env, shell=False)
            if check.returncode == 0:
                status["pro_ready"] = True
                break
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        pass
    return status


def run(args, cwd=None, token=None, *, environment, error_type):
    executable = shutil.which("semgrep")
    if not executable:
        raise error_type("Semgrep CLI is required to validate the tuned rule")
    env = environment()
    env["SEMGREP_SEND_METRICS"] = "off"
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    if env.get("AWS_CA_BUNDLE"):
        env.setdefault("REQUESTS_CA_BUNDLE", env["AWS_CA_BUNDLE"])
    if token:
        env["SEMGREP_APP_TOKEN"] = token
    # Keep arguments separate and disable shell interpretation; do not shell-quote argv.
    return subprocess.run(
        [executable, *args], cwd=cwd, capture_output=True, text=True,
        timeout=600, check=False, env=env, shell=False,
    )


def scanner_status(*, environment, token=None) -> dict:
    """Verify the current login and a tiny Pro scan before selecting an engine.

    Binary presence alone does not establish account access. The smoke test uses
    synthetic source, never the user's repository, and returns no credential data.
    """
    status = engine_status(environment=environment)
    status.update(engine="oss", authenticated=False, pro_enabled=None,
                  descriptor="Semgrep Community Edition — Pro access not verified")
    if not status["cli_version"]:
        status.update(engine=None, descriptor="Semgrep is not installed on this runner")
        return status
    env = environment()
    env.update(SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
    if token:
        env["SEMGREP_APP_TOKEN"] = token
    executable = shutil.which("semgrep")
    try:
        if not _login_verified(executable, env):
            return status
        status["authenticated"] = True
        if not status["pro_ready"]:
            status["descriptor"] = "Semgrep Community Edition — logged in; install the matching Pro engine to verify Pro access"
            return status
        with tempfile.TemporaryDirectory(prefix="threatlint-pro-check-") as work:
            root = Path(work)
            (root / "rule.json").write_text(json.dumps({"rules": [{"id": "threatlint-pro-check", "languages": ["python"],
                "message": "Synthetic engine check", "severity": "INFO", "pattern": "print(...)"}]}), encoding="utf-8")
            (root / "check.py").write_text("print('synthetic')\n", encoding="utf-8")
            check = subprocess.run([executable, "scan", "--pro", "--config", str(root / "rule.json"), "--json",
                                    "--metrics", "off", "--disable-version-check", str(root / "check.py")],
                                   capture_output=True, text=True, timeout=45, check=False, env=env, shell=False)
            payload = json.loads(check.stdout or "{}")
            if check.returncode == 0 and not payload.get("errors") and payload.get("results"):
                status.update(engine="pro", pro_enabled=True,
                              descriptor="Semgrep Pro — current login and Pro engine verified; cross-file analysis enabled")
            else:
                status["descriptor"] = "Semgrep Community Edition — Pro verification failed for this login"
    except (OSError, ValueError, subprocess.TimeoutExpired):
        status["descriptor"] = "Semgrep Community Edition — Pro verification unavailable"
    return status


def matches(config, target, line, exact=False, *, run, pro_flags, error_type):
    result = run(["scan", *pro_flags(), "--config", config, "--json", "--quiet", "--metrics", "off",
                  "--disable-version-check", "--no-secrets-validation", target])
    if result.returncode != 0:
        raise error_type("Semgrep scan failed; no tuning coverage or engine fallback was assumed")
    try:
        payload = json.loads(result.stdout)
        if payload.get("errors"):
            raise error_type("Semgrep reported scan errors; tuning coverage is not established")
        found = [item["start"]["line"] for item in payload.get("results", [])]
    except (ValueError, KeyError):
        raise error_type(f"Semgrep could not scan with {config}: {(result.stderr or result.stdout).strip()[-300:]}") from None
    return [value for value in found if line is None or (value == line if exact else abs(value - line) <= 3)]


def _write_fixture(work, rule_id, target_file, rule_yaml, fixtures):
    fixture_path = work / semgrep_rule_text.fixture_name(rule_id, target_file)
    fixture_path.write_text(fixtures, encoding="utf-8")
    if semgrep_rule_text.needs_named_fixture(rule_yaml, target_file):
        fixture_path = work / "as-named" / Path(target_file).name
        fixture_path.parent.mkdir()
        fixture_path.write_text(fixtures, encoding="utf-8")
    return fixture_path


def _check_original(original_path, scan_path, expect, avoid, *, matches, error_type):
    hits = set(matches(str(original_path), str(scan_path), None))
    if not set(avoid) <= hits:
        raise error_type("The original rule does not fire on the `ok` fixture lines, so they do not model this false positive")
    if not set(expect) <= hits:
        raise error_type("The original rule misses a `ruleid` fixture line; the fixtures do not reflect the original rule")


def _check_location(original_path, rule_path, target_file, line, *, matches, error_type):
    local = {"reproduced": False, "dropped": None}
    if target_file and Path(target_file).exists() and original_path and line:
        if matches(str(original_path), target_file, line, exact=True):
            local["reproduced"] = True
            local["dropped"] = not matches(str(rule_path), target_file, line, exact=True)
            if not local["dropped"]:
                raise error_type("The tuned rule still reports the false-positive location; not deploying it")
    return local


def validate_tuned_rule(rule_yaml, original_rule, target_file, line, fixtures="", token=None, *,
                        run, pro_flags, matches, original_rule_yaml, fixture_lines, error_type):
    """Require valid YAML, passing fixtures, original-rule coverage, and any reproducible local drop."""
    work = Path(tempfile.mkdtemp(prefix="threatlint-rule-"))
    ids = re.findall(r"(?m)^\s*-\s*id:\s*([\w.-]+)", rule_yaml)
    if len(ids) != 1:
        raise error_type("The tuned rule must contain exactly one rule")
    rule_id = ids[0]
    rule_path = work / f"{rule_id}.yaml"
    rule_path.write_text(rule_yaml, encoding="utf-8")
    check = run(["--validate", "--config", str(rule_path), "--metrics", "off"])
    if check.returncode != 0:
        raise error_type(f"Tuned rule is not valid: {(check.stderr or check.stdout).strip()[-300:]}")
    if not fixtures:
        raise error_type("The report has no `**Tuned rule fixtures**:` block; a tuning is deployed only when fixtures prove it")
    scan_path = _write_fixture(work, rule_id, target_file, rule_yaml, fixtures)
    test = run(["--test", *pro_flags(), "--metrics", "off", str(work)])
    if test.returncode != 0 or "All tests passed" not in test.stdout:
        raise error_type(f"Tuned rule fixtures did not pass: {(test.stdout or test.stderr).strip()[-400:]}")
    expect, avoid = fixture_lines(fixtures, rule_id)
    if not expect or not avoid:
        raise error_type("Fixtures need at least one `ruleid` (true positive kept) and one `ok` (the false positive) line")
    original_text = original_rule_yaml(original_rule, token) if token else ""
    original_path = None
    if original_text:
        original_path = work / "original" / "original.yaml"
        original_path.parent.mkdir()
        original_path.write_text(original_text, encoding="utf-8")
        _check_original(original_path, scan_path, expect, avoid, matches=matches, error_type=error_type)
    local = _check_location(original_path, rule_path, target_file, line, matches=matches, error_type=error_type)
    return {"id": rule_id, "path": str(rule_path), "fixtures": True, "original_checked": bool(original_text), **local}


def publish(rule_path, token, *, run, error_type):
    directory = Path(tempfile.mkdtemp(prefix="threatlint-publish-"))
    shutil.copy(rule_path, directory / Path(rule_path).name)
    result = run(["publish", "--visibility=org_private", str(directory)], token=token)
    output = f"{result.stdout}\n{result.stderr}"
    if result.returncode != 0:
        raise error_type(f"semgrep publish failed: {output.strip()[-300:]}")
    match = re.search(r"/r/([\w.:-]+)", output) or re.search(r"(?:rule|path)[^\w]+([\w-]+\.[\w.-]+)", output, re.I)
    if not match:
        raise error_type(f"semgrep publish did not report the rule path: {output.strip()[-300:]}")
    return match.group(1)


def merge_exclusions(proposed: str, live: str, base: str = "") -> str | None:
    """Three-way merge against the original; reject missing ancestry and conflicting edits."""
    if not base:
        return None
    rule_id = re.search(r"(?m)^\s*-\s*id:\s*(\S+)", proposed)
    work = Path(tempfile.mkdtemp(prefix="threatlint-merge-"))
    try:
        for name, text in (("proposed", proposed), ("base", base), ("live", live)):
            (work / name).write_text(semgrep_rule_text.normalize_for_merge(text), encoding="utf-8")
        result = subprocess.run(["git", "merge-file", "-p", str(work / "proposed"), str(work / "base"), str(work / "live")],
                                capture_output=True, text=True, timeout=60, check=False)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if result.returncode != 0 or "<<<<<<<" in result.stdout:
        return None
    merged = result.stdout
    return merged.replace("RULE_ID", rule_id.group(1), 1) if rule_id else merged
