"""Local Semgrep execution, fixture proof gates, publishing, and rule merging."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from threatlint import semgrep_rule_text


def run(args, cwd=None, token=None, *, environment, error_type):
    executable = shutil.which("semgrep")
    if not executable:
        raise error_type("Semgrep Community Edition is required to validate the tuned rule")
    env = environment()
    env["SEMGREP_SEND_METRICS"] = "off"
    if env.get("AWS_CA_BUNDLE"):
        env.setdefault("REQUESTS_CA_BUNDLE", env["AWS_CA_BUNDLE"])
    if token:
        env["SEMGREP_APP_TOKEN"] = token
    # Keep arguments separate and disable shell interpretation; do not shell-quote argv.
    return subprocess.run(
        [executable, *args], cwd=cwd, capture_output=True, text=True,
        timeout=600, check=False, env=env, shell=False,
    )


def matches(config, target, line, exact=False, *, run, pro_flags, error_type):
    result = run(["scan", *pro_flags(), "--config", config, "--json", "--quiet", "--metrics", "off", target])
    try:
        found = [item["start"]["line"] for item in json.loads(result.stdout).get("results", [])]
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
