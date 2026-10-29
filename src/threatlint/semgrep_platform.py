"""Semgrep AppSec Platform: API token setup and false-positive rule tuning.

  threatlint semgrep login [--token-stdin]   validate and save the Semgrep API token
  threatlint semgrep status | logout

Token resolution: SEMGREP_APP_TOKEN, then the saved token (OS credential store via `keyring`, else
~/.threatlint/semgrep.json, owner-only; shared with the Workbench), then AWS Parameter Store
the Parameter Store name in THREATLINT_SEMGREP_TOKEN_PARAMETER (or ~/.threatlint/org.json) with the user's AWS CLI profile.

Rule tuning (`tune_rule`) for a confirmed SAST or Secrets false positive. The public API cannot edit a
rule in place, so the tuned rule replaces the original in the policy:
  1. validate the tuned rule locally: `semgrep --validate`, its fixtures with `semgrep --test`, the original
     rule (downloaded with the org token) firing on the same fixtures, and the flagged file when local
     analysis can reproduce it;
  2. publish it as an org-private rule (`semgrep publish --visibility=org_private`);
  3. add it to every policy that runs the original rule, in the original rule's mode;
  4. disable the original rule in those policies.
Nothing is changed in Semgrep unless step 1 passes; no human approval is required. The rollback is printed
(re-enable the original, disable the tuned rule).
"""

from __future__ import annotations

import base64  # noqa: F401 - kept for parity with ado_login
import getpass
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from threatlint import org_config
from threatlint import servicenow as sn
from threatlint.tls import ssl_context, tool_env

API = os.environ.get("THREATLINT_SEMGREP_API", "https://semgrep.dev").rstrip("/")
KEYRING_SERVICE = "threatlint-semgrep"
_TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]{20,200}")
PRODUCT_POLICY = {"sast": "PRODUCT_TYPE_SAST", "secrets": "PRODUCT_TYPE_SECRETS"}


class SemgrepError(RuntimeError):
    """A user-actionable failure; messages never contain the token."""


# ── Token ─────────────────────────────────────────────────────────────────────

def store_path() -> Path:
    return Path(os.environ.get("THREATLINT_HOME") or Path.home() / ".threatlint") / "semgrep.json"


def _keyring():
    try:
        import keyring  # noqa: PLC0415 - optional
        keyring.get_keyring()
        return keyring
    except Exception:  # noqa: BLE001
        return None


def _read_store() -> dict:
    try:
        return json.loads(store_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_token(token: str, deployment: str = "") -> str:
    keyring = _keyring()
    record = {"deployment": deployment, "storage": "keyring" if keyring else "file"}
    if keyring:
        keyring.set_password(KEYRING_SERVICE, "token", token)
    else:
        record["token"] = token
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(record, handle)
    if os.name != "nt":
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return "the OS credential store" if keyring else str(path)


def saved_token() -> tuple[str, str]:
    record = _read_store()
    if record.get("storage") == "keyring":
        keyring = _keyring()
        value = keyring.get_password(KEYRING_SERVICE, "token") if keyring else None
        return (value, "OS credential store") if value else ("", "")
    return (record.get("token", ""), str(store_path())) if record.get("token") else ("", "")


def token_parameter() -> str:
    """Parameter Store name of the Semgrep token; empty when not configured (see org_config)."""
    return org_config.value("semgrepTokenParameter")


def parameter_store_token(profile: str | None) -> str:
    aws = shutil.which("aws")
    if not aws or not token_parameter():
        return ""
    result = subprocess.run([aws, "ssm", "get-parameter", "--name", token_parameter(), "--with-decryption", "--region", sn.AWS_REGION,
                             "--query", "Parameter.Value", "--output", "text", *(["--profile", profile] if profile else [])],
                            capture_output=True, text=True, timeout=60, check=False, env=tool_env())
    return result.stdout.strip() if result.returncode == 0 else ""


def resolve_token(profile: str | None = None) -> tuple[str, str]:
    if os.environ.get("SEMGREP_APP_TOKEN"):
        return os.environ["SEMGREP_APP_TOKEN"], "SEMGREP_APP_TOKEN"
    token, source = saved_token()
    if token:
        return token, source
    token = parameter_store_token(profile)
    if token:
        return token, f"Parameter Store {token_parameter()}"
    raise SemgrepError("No Semgrep API token. Run `threatlint semgrep login` (or `threatlint setup`), set SEMGREP_APP_TOKEN, "
                       "or sign in with `threatlint aws login` to read it from Parameter Store.")


# ── API ───────────────────────────────────────────────────────────────────────

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ssl_context()))


_HTTP_TIMEOUT_S = int(os.environ.get("THREATLINT_SEMGREP_TIMEOUT", "120"))
_RETRIES = 3


def call(path: str, token: str, *, method: str = "GET", body: dict | None = None) -> dict:
    """One Semgrep API call. Timeouts and 5xx/429 answers are retried with backoff: policy and publish calls on a
    large deployment are slow, and a transient failure must not leave a proven tuning undeployed."""
    import time  # noqa: PLC0415
    for attempt in range(1, _RETRIES + 1):
        request = urllib.request.Request(f"{API}{path}", method=method, data=json.dumps(body).encode() if body is not None else None,
                                         headers={"Authorization": f"Bearer {token}", "Accept": "application/json",
                                                  **({"Content-Type": "application/json"} if body is not None else {})})
        try:
            with _OPENER.open(request, timeout=_HTTP_TIMEOUT_S) as response:  # noqa: S310 - fixed HTTPS host
                raw = response.read()
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 500, 502, 503, 504) and attempt < _RETRIES:
                time.sleep(2 ** attempt)
                continue
            raise _http_error(exc, path) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt < _RETRIES:
                time.sleep(2 ** attempt)
                continue
            raise SemgrepError(f"Semgrep request failed after {_RETRIES} attempts: {exc}") from exc
        except ValueError as exc:
            raise SemgrepError(f"Semgrep request failed: {exc}") from exc
    raise SemgrepError("Semgrep request failed")


def _http_error(exc, path: str) -> SemgrepError:
    hint = {401: " Check the Semgrep token.", 403: " The token needs the Web API scope.", 404: " Not found.",
            410: " This deployment uses the newer policies model."}.get(exc.code, "")
    return SemgrepError(f"Semgrep returned HTTP {exc.code} for {path.split('?')[0]}.{hint}")


def deployment(token: str, wanted: str = "") -> dict:
    """{id, slug, name} for the deployment: by numeric ID or slug (--semgrep-deployment, THREATLINT_SEMGREP_DEPLOYMENT,
    or org.json), else the token's only deployment. The v1 findings/triage API takes the slug; policies take the ID."""
    deployments = call("/api/v1/deployments", token).get("deployments", [])
    wanted = wanted or org_config.value("semgrepDeployment")
    chosen = [item for item in deployments if not wanted or wanted in (item.get("slug"), str(item.get("id")))]
    if len(chosen) != 1:
        raise SemgrepError("The token can access several Semgrep deployments; pass --semgrep-deployment" if chosen else f"The token cannot access Semgrep deployment {wanted}")
    return chosen[0]


# ── Rule tuning ───────────────────────────────────────────────────────────────

def tuned_rule_from_report(report: str) -> str:
    """The YAML block the FP reviewer placed after `**Tuned rule**:`; empty when it proposed none."""
    match = re.search(r"\*\*Tuned rule\*\*:\s*\n+```ya?ml\n(.*?)\n```", report, re.S)
    return match.group(1).strip() + "\n" if match else ""


def _semgrep(args: list[str], cwd: str | None = None, token: str | None = None) -> subprocess.CompletedProcess:
    semgrep = shutil.which("semgrep")
    if not semgrep:
        raise SemgrepError("Semgrep Community Edition is required to validate the tuned rule")
    env = tool_env()
    env["SEMGREP_SEND_METRICS"] = "off"
    if env.get("AWS_CA_BUNDLE"):
        env.setdefault("REQUESTS_CA_BUNDLE", env["AWS_CA_BUNDLE"])
    if token:
        env["SEMGREP_APP_TOKEN"] = token
    return subprocess.run([semgrep, *args], cwd=cwd, capture_output=True, text=True, timeout=600, check=False, env=env)


def _pro_flags() -> list[str]:
    """Pro engine flags when it is installed (--pro also enables the Pro-only languages: Apex, Elixir, ...)."""
    return ["--pro"] if _semgrep(["scan", "--pro", "--version"]).returncode == 0 else []


def _matches(config: str, target: str, line: int | None, exact: bool = False) -> list[int]:
    """Lines the config reports in target: all of them, or those within 3 lines of `line` (exactly `line` when exact)."""
    pro = _pro_flags()
    result = _semgrep(["scan", *pro, "--config", config, "--json", "--quiet", "--metrics", "off", target])
    try:
        found = [item["start"]["line"] for item in json.loads(result.stdout).get("results", [])]
    except (ValueError, KeyError):
        raise SemgrepError(f"Semgrep could not scan with {config}: {(result.stderr or result.stdout).strip()[-300:]}") from None
    return [value for value in found if line is None or (value == line if exact else abs(value - line) <= 3)]


def original_rule_yaml(rule: str, token: str) -> str:
    """The original rule's YAML, including Pro rules, fetched with the org token (`r/<rule>` needs a login)."""
    request = urllib.request.Request(f"{API}/c/r/{urllib.parse.quote(rule, safe='.')}", headers={"Authorization": f"Bearer {token}"})
    try:
        with _OPENER.open(request, timeout=_HTTP_TIMEOUT_S) as response:  # noqa: S310 - fixed HTTPS host
            text = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError) as exc:
        raise SemgrepError(f"Could not download {rule}: {exc}") from exc
    if not re.search(r"(?m)^\s*-\s*id:", text):
        raise SemgrepError(f"Semgrep returned no rule body for {rule} (the token may lack access to it)")
    return text


def _fixture_lines(fixtures: str, rule_id: str) -> tuple[list[int], list[int]]:
    """Lines expected to match (ruleid) and not to match (ok), as `semgrep --test` reads them."""
    expect, avoid = [], []
    lines = fixtures.splitlines()
    for number, line in enumerate(lines, start=1):
        marker = re.search(r"(ruleid|ok):\s*([\w.,\s-]+?)\s*(?:-->|\*/)?\s*$", line) or re.search(r"(ruleid|ok):\s*([\w.,\s-]+)", line)
        if marker and rule_id in [part.strip() for part in marker.group(2).split(",")]:
            # As in `semgrep --test`: a marker alone on its line annotates the next line; a trailing marker, its own line.
            own_line = bool(line[:marker.start()].strip(" \t/#*-<!"))
            (expect if marker.group(1) == "ruleid" else avoid).append(number if own_line else number + 1)
    return expect, avoid


def validate_tuned_rule(rule_yaml: str, original_rule: str, target_file: str, line: int | None, fixtures: str = "",
                        token: str | None = None) -> dict:
    """Prove the tuned rule is safe to deploy, without human approval:

    1. `semgrep --validate` accepts it;
    2. its fixtures pass `semgrep --test` (rule and fixture side by side with the same name, the layout Semgrep
       requires; other layouts crash Semgrep 1.107), so every `ruleid` (true positive) still fires and every
       `ok` (the false-positive shape) is quiet;
    3. the ORIGINAL rule fires on the `ok` lines, so the fixtures really model the false positive, and still
       fires on the `ruleid` lines, so the tuning only removed what it claims to;
    4. when the local engine can reproduce the finding in the flagged file, the tuned rule no longer reports it.
       Interfile Pro taint often cannot be reproduced locally; that alone does not block deployment, because
       steps 2–3 already prove the behaviour on the same code shape.
    """
    work = Path(tempfile.mkdtemp(prefix="threatlint-rule-"))
    ids = re.findall(r"(?m)^\s*-\s*id:\s*([\w.-]+)", rule_yaml)
    if len(ids) != 1:
        raise SemgrepError("The tuned rule must contain exactly one rule")
    rule_id = ids[0]
    rule_path = work / f"{rule_id}.yaml"
    rule_path.write_text(rule_yaml, encoding="utf-8")
    check = _semgrep(["--validate", "--config", str(rule_path), "--metrics", "off"])
    if check.returncode != 0:
        raise SemgrepError(f"Tuned rule is not valid: {(check.stderr or check.stdout).strip()[-300:]}")
    if not fixtures:
        raise SemgrepError("The report has no `**Tuned rule fixtures**:` block; a tuning is deployed only when fixtures prove it")
    suffix = Path(target_file).suffix or (".dockerfile" if Path(target_file).name.lower().startswith("dockerfile") else ".txt")
    # A YAML fixture would overwrite the rule file itself; Semgrep pairs `<rule>.yaml` with `<rule>.test.yaml`.
    fixture_path = work / f"{rule_id}{'.test' if suffix.lower() in ('.yaml', '.yml') else ''}{suffix}"
    fixture_path.write_text(fixtures, encoding="utf-8")
    # A rule whose `paths.include` names a file (e.g. Info.plist) only scans files with that name, so the
    # original-rule check scans a copy of the fixture under the flagged file's own name.
    scan_path = fixture_path
    # Files such as Dockerfile have no extension; Semgrep recognises them by name, so scan a copy named like the target.
    named_only = bool(target_file) and not Path(target_file).suffix
    if (named_only or re.search(r"(?m)^\s+include:\s*\n\s+-\s*['\"]?[^*\n]+['\"]?\s*$", rule_yaml)) and target_file:
        scan_path = work / "as-named" / Path(target_file).name
        scan_path.parent.mkdir()
        scan_path.write_text(fixtures, encoding="utf-8")
    test = _semgrep(["--test", *_pro_flags(), "--metrics", "off", str(work)])
    if test.returncode != 0 or "All tests passed" not in test.stdout:
        raise SemgrepError(f"Tuned rule fixtures did not pass: {(test.stdout or test.stderr).strip()[-400:]}")
    expect, avoid = _fixture_lines(fixtures, rule_id)
    if not expect or not avoid:
        raise SemgrepError("Fixtures need at least one `ruleid` (true positive kept) and one `ok` (the false positive) line")
    original_text = original_rule_yaml(original_rule, token) if token else ""
    if original_text:
        original_path = work / "original" / "original.yaml"
        original_path.parent.mkdir()
        original_path.write_text(original_text, encoding="utf-8")
        hits = set(_matches(str(original_path), str(scan_path), None))
        if not set(avoid) <= hits:
            raise SemgrepError("The original rule does not fire on the `ok` fixture lines, so they do not model this false positive")
        if not set(expect) <= hits:
            raise SemgrepError("The original rule misses a `ruleid` fixture line; the fixtures do not reflect the original rule")
    local = {"reproduced": False, "dropped": None}
    if target_file and Path(target_file).exists():
        source = work / "original" / "original.yaml" if original_text else None
        if source and line and _matches(str(source), target_file, line, exact=True):
            local["reproduced"] = True
            local["dropped"] = not _matches(str(rule_path), target_file, line, exact=True)
            if not local["dropped"]:
                raise SemgrepError("The tuned rule still reports the false-positive location; not deploying it")
    return {"id": rule_id, "path": str(rule_path), "fixtures": True, "original_checked": bool(original_text), **local}


def publish(rule_path: str, token: str) -> str:
    """Publish as an org-private rule; returns the rule's registry path."""
    directory = Path(tempfile.mkdtemp(prefix="threatlint-publish-"))
    shutil.copy(rule_path, directory / Path(rule_path).name)
    result = _semgrep(["publish", "--visibility=org_private", str(directory)], token=token)
    output = f"{result.stdout}\n{result.stderr}"
    if result.returncode != 0:
        raise SemgrepError(f"semgrep publish failed: {output.strip()[-300:]}")
    match = re.search(r"/r/([\w.:-]+)", output) or re.search(r"(?:rule|path)[^\w]+([\w-]+\.[\w.-]+)", output, re.I)
    if not match:
        raise SemgrepError(f"semgrep publish did not report the rule path: {output.strip()[-300:]}")
    return match.group(1)


def _policy_rules(dep_id: str, policy_id: str, token: str) -> list[dict]:
    rules, cursor = [], ""
    for _ in range(20):
        query = urllib.parse.urlencode({"limit": 2000, **({"cursor": cursor} if cursor else {})})
        data = call(f"/api/policies/v1/deployments/{dep_id}/{policy_id}/rules?{query}", token)
        rules += data.get("rules", [])
        cursor = data.get("cursor") or ""
        if not cursor:
            break
    return rules


def _same_rule(path: str, rule: str) -> bool:
    return path == rule or path.endswith("." + rule) or rule.endswith("." + path)


def _products(kind: str) -> list[str]:
    """The AVIT's own product first, then the other: a Semgrep Code rule (e.g. secrets-in-config-file) can raise a Secrets AVIT."""
    return [PRODUCT_POLICY[kind], *(p for k, p in PRODUCT_POLICY.items() if k != kind)]


def replace_in_policies(token: str, dep: dict, kind: str, original_rule: str, tuned_path: str) -> list[dict]:
    """Add the tuned rule in the original's mode and disable the original, in every policy that runs it."""
    all_policies = call(f"/api/policies/v1/deployments/{dep['id']}", token).get("policies", [])
    for product in _products(kind):
        changes = _replace_in(token, dep, [p for p in all_policies if p.get("productType") == product], original_rule, tuned_path)
        if changes:
            return changes
    raise SemgrepError(f"No policy runs {original_rule}; nothing to replace (the tuned rule is published but not enabled)")


def _replace_in(token: str, dep: dict, policies: list[dict], original_rule: str, tuned_path: str) -> list[dict]:
    changes = []
    for policy in policies:
        rules = _policy_rules(str(dep["id"]), str(policy["id"]), token)
        original = [rule for rule in rules if _same_rule(str(rule.get("path", "")), original_rule) and rule.get("policyMode") != "MODE_DISABLED"]
        for rule in original:
            mode = rule.get("policyMode", "MODE_MONITOR")
            base = f"/api/policies/v1/deployments/{dep['id']}/{policy['id']}/rules"
            call(f"{base}/{urllib.parse.quote(tuned_path, safe='.')}", token, method="PUT", body={"policyMode": mode})
            call(f"{base}/{urllib.parse.quote(rule['path'], safe='.')}", token, method="PUT", body={"policyMode": "MODE_DISABLED"})
            changes.append({"policy": policy.get("name"), "policy_id": policy["id"], "original": rule["path"], "tuned": tuned_path, "mode": mode})
    return changes


def disable_originals(token: str, dep: dict, kind: str, original_rule: str) -> list[dict]:
    """Disable the original wherever its tuned rule is enabled in the same policy (it can be re-enabled after tuning)."""
    leaf, changes = original_rule.rsplit(".", 1)[-1], []
    for policy in call(f"/api/policies/v1/deployments/{dep['id']}", token).get("policies", []):
        if policy.get("productType") not in _products(kind):
            continue
        rules = _policy_rules(str(dep["id"]), str(policy["id"]), token)
        if not any(str(rule.get("path", "")).endswith(f"{leaf}.tuned") and rule.get("policyMode") != "MODE_DISABLED" for rule in rules):
            continue
        for rule in rules:
            path = str(rule.get("path", ""))
            if not path.endswith(".tuned") and _same_rule(path, original_rule) and rule.get("policyMode") != "MODE_DISABLED":
                call(f"/api/policies/v1/deployments/{dep['id']}/{policy['id']}/rules/{urllib.parse.quote(path, safe='.')}", token,
                     method="PUT", body={"policyMode": "MODE_DISABLED"})
                changes.append({"policy": policy.get("name"), "original": path, "mode": rule.get("policyMode")})
    return changes


def existing_tuning(token: str, dep: dict, kind: str, original_rule: str) -> list[dict]:
    """Policies already running a Threatlint-tuned version of this rule (rule path ends with `<rule-name>.tuned`)."""
    leaf = original_rule.rsplit(".", 1)[-1]
    found = []
    for policy in call(f"/api/policies/v1/deployments/{dep['id']}", token).get("policies", []):
        if policy.get("productType") not in _products(kind):
            continue
        for rule in _policy_rules(str(dep["id"]), str(policy["id"]), token):
            path = str(rule.get("path", ""))
            if path.endswith(f"{leaf}.tuned") and rule.get("policyMode") != "MODE_DISABLED":
                found.append({"policy": policy.get("name"), "tuned": path, "mode": rule.get("policyMode")})
    return found


_EXCLUSION = re.compile(r"^\s*-?\s*(pattern-not(?:-inside|-regex)?|metavariable-regex|pattern-sanitizers|regex):")


def _exclusions(rule_yaml: str) -> list[str]:
    """Exclusion and sanitizer lines of a rule, compared without indentation."""
    return [line.strip() for line in rule_yaml.splitlines() if _EXCLUSION.match(line)]


def merge_exclusions(proposed: str, live: str, base: str = "") -> str | None:
    """Combine a reviewer's tuned rule with a live tuned rule that changed since the reviewer read it.

    A three-way merge (`git merge-file`) of proposal and live rule against their common ancestor, the
    original rule, keeps both sets of changes. Without an ancestor, or when the two edit the same lines, it
    returns None so the proposal is rejected rather than guessed at. The merged rule still runs the proof gate."""
    if not base:
        return None
    rule_id = re.search(r"(?m)^\s*-\s*id:\s*(\S+)", proposed)
    def normal(text: str) -> str:
        # Compare rule bodies only: the id and the registry metadata differ between the three by design.
        text = re.sub(r"(?m)^(\s*-\s*id:\s*)\S+", lambda m: m.group(1) + "RULE_ID", text, count=1)
        lines, out, skipping, indent = text.splitlines(), [], False, 0
        for line in lines:
            if re.match(r"^\s+semgrep\.dev:\s*$", line) or re.match(r"^\s+(source|shortlink|rule-origin-note):", line):
                skipping, indent = True, len(line) - len(line.lstrip())
                continue
            if skipping and (not line.strip() or len(line) - len(line.lstrip()) > indent):
                continue
            skipping = False
            out.append(line)
        return "\n".join(out) + "\n"
    work = Path(tempfile.mkdtemp(prefix="threatlint-merge-"))
    try:
        for name, text in (("proposed", proposed), ("base", base), ("live", live)):
            (work / name).write_text(normal(text), encoding="utf-8")
        result = subprocess.run(["git", "merge-file", "-p", str(work / "proposed"), str(work / "base"), str(work / "live")],
                                capture_output=True, text=True, timeout=60, check=False)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if result.returncode != 0 or "<<<<<<<" in result.stdout:
        return None
    merged = result.stdout
    return merged.replace("RULE_ID", rule_id.group(1), 1) if rule_id else merged


def tune_rule(report: str, kind: str, original_rule: str, target_file: str, line: int | None, token: str, dep: dict,
              out=sys.stdout) -> list[dict]:
    """Make sure the scanner stops reporting this false positive, without human approval but only with proof.

    - Not yet tuned: the reviewer's tuned rule (a clone of the original plus the narrowest exclusion) is proven,
      published org-private as `<deployment>.<rule>.tuned`, enabled where the original ran, and the original disabled.
    - Already tuned: if the live tuned rule no longer reports the flagged line, nothing changes. Otherwise the
      reviewer's rule must extend the live tuned rule (keep every exclusion it has), is proven the same way, and is
      republished under the same id, so the policies pick up the new version."""
    already = existing_tuning(token, dep, kind, original_rule)
    live_yaml = ""
    if already:
        live_path = already[0]["tuned"]
        live_yaml = original_rule_yaml(live_path, token)
        work = Path(tempfile.mkdtemp(prefix="threatlint-live-"))
        (work / "live.yaml").write_text(live_yaml, encoding="utf-8")
        still = target_file and os.path.exists(target_file) and line and _matches(str(work / "live.yaml"), target_file, line, exact=True)
        shutil.rmtree(work, ignore_errors=True)
        if not still:
            for item in already:
                print(f"  ✓ {item['policy']} already runs {item['tuned']} ({item['mode']}), which no longer reports this line; no change needed", file=out)
            _report_disabled(disable_originals(token, dep, kind, original_rule), out)
            return []
        print(f"  ! The live tuned rule {live_path} still reports this line; extending it", file=out)
    rule_yaml = tuned_rule_from_report(report)
    if not rule_yaml:
        raise SemgrepError("The report has no `**Tuned rule**:` block, so the rule was not changed. Re-run the review: "
                           "a false positive on a SAST or Secrets rule must come with a proven tuned rule")
    if live_yaml:
        missing = [item for item in _exclusions(live_yaml) if item not in _exclusions(rule_yaml)]
        if missing:
            merged = merge_exclusions(rule_yaml, live_yaml, original_rule_yaml(original_rule, token))
            if merged and not [item for item in _exclusions(live_yaml) if item not in _exclusions(merged)]:
                print(f"  ! The live tuned rule gained {len(missing)} exclusion(s) since this proposal was written; merged them in (the proof gate still runs)", file=out)
                rule_yaml, missing = merged, []
        if missing:
            raise SemgrepError(f"The proposed rule drops {len(missing)} exclusion(s) the live tuned rule has (e.g. `{missing[0][:80]}`); "
                               "it must extend the live tuned rule, not replace it")
    fixtures = ""
    fixture = re.search(r"\*\*Tuned rule fixtures\*\*:\s*\n+```\w*\n(.*?)\n```", report, re.S)
    if fixture:
        fixtures = fixture.group(1) + "\n"
    checked = validate_tuned_rule(rule_yaml, original_rule, target_file, line, fixtures, token)
    where = "and no longer reports the flagged line" if checked["dropped"] else "(the flagged line needs interfile analysis, so the fixtures are the proof)"
    print(f"  ✓ Tuned rule {checked['id']} is valid, keeps every true-positive fixture, drops the false-positive shape{', matches the original rule,' if checked['original_checked'] else ''} {where}", file=out)
    tuned_path = publish(checked["path"], token)
    print(f"  ✓ Published org-private rule {tuned_path}{' (new version of the live tuned rule)' if live_yaml else ''}", file=out)
    if live_yaml:
        _report_disabled(disable_originals(token, dep, kind, original_rule), out)
        return [{"policy": item["policy"], "tuned": tuned_path, "mode": item["mode"], "original": original_rule} for item in already]
    changes = replace_in_policies(token, dep, kind, original_rule, tuned_path)
    for change in changes:
        print(f"  ✓ {change['policy']}: {change['tuned']} enabled ({change['mode']}); {change['original']} disabled", file=out)
    print("    Rollback: set the original rule back to its mode and disable the tuned rule in the same policy.", file=out)
    return changes


def _report_disabled(changes: list[dict], out) -> None:
    for change in changes:
        print(f"  ✓ {change['policy']}: {change['original']} was still enabled ({change['mode']}) beside its tuned rule; disabled", file=out)


def rule_base(rule: str, kind: str, token: str, dep: dict) -> tuple[str, str]:
    """(YAML, label) the reviewer should tune: the live tuned rule when one is deployed, else the original."""
    live = existing_tuning(token, dep, kind, rule) if kind in PRODUCT_POLICY else []
    if live:
        return original_rule_yaml(live[0]["tuned"], token), f"live tuned rule {live[0]['tuned']} (extend it; keep every exclusion it has)"
    return original_rule_yaml(rule, token), f"original rule {rule}"


# ── CLI ───────────────────────────────────────────────────────────────────────

def login(token: str = "", deployment_slug: str = "", from_stdin: bool = False, profile: str | None = None) -> str:
    if from_stdin:
        token = sys.stdin.readline().strip()
    if not token:
        token = parameter_store_token(profile)
        if token:
            print(f"  Read the Semgrep token from Parameter Store {token_parameter()}.")
    if not token:
        if not sys.stdin.isatty():
            raise SemgrepError("No terminal to prompt for the Semgrep token; pipe it with --token-stdin")
        print("Create a Web API token in Semgrep AppSec Platform → Settings → Tokens.")
        token = getpass.getpass("Semgrep API token (input hidden): ").strip()
    if not _TOKEN.fullmatch(token):
        raise SemgrepError("That does not look like a Semgrep API token")
    dep = deployment(token, deployment_slug)
    where = save_token(token, str(dep.get("id", "")))
    return f"{where} (deployment {dep.get('name') or dep.get('slug')})"


def add_semgrep_parser(sub) -> None:
    p = sub.add_parser("semgrep", help="Set up the Semgrep AppSec Platform API token")
    actions = p.add_subparsers(dest="semgrep_command", required=True)
    login_parser = actions.add_parser("login", help="Validate and save the Semgrep API token")
    login_parser.add_argument("--token-stdin", action="store_true", help="Read the token from standard input")
    login_parser.add_argument("--deployment", default="", help="Deployment slug when the token can access several")
    login_parser.add_argument("--aws-profile", help="Read the token from Parameter Store with this AWS profile first")
    actions.add_parser("status", help="Show where the token comes from (never prints it)")
    base = actions.add_parser("rule-base", help="Write the rule a false-positive tuning should start from (live tuned rule, else the original)")
    base.add_argument("rule", help="Semgrep rule ID from the AVIT")
    base.add_argument("--kind", choices=sorted(PRODUCT_POLICY), required=True)
    base.add_argument("-o", "--output", required=True, help="File to write the rule YAML to")
    base.add_argument("--aws-profile")
    actions.add_parser("logout", help="Remove the saved token")


def cmd_semgrep(args) -> int:
    try:
        if args.semgrep_command == "login":
            print(f"✓ Semgrep token validated and saved to {login('', args.deployment, args.token_stdin, args.aws_profile)}")
        elif args.semgrep_command == "rule-base":
            token = resolve_token(args.aws_profile)[0]
            yaml_text, label = rule_base(args.rule, args.kind, token, deployment(token))
            Path(args.output).write_text(f"# Tuning base: {label}\n{yaml_text}", encoding="utf-8")
            print(f"✓ Wrote the {label} to {args.output}")
        elif args.semgrep_command == "status":
            try:
                _token, source = resolve_token()
                print(f"Semgrep token: {source}")
            except SemgrepError as exc:
                print(str(exc))
        else:
            keyring = _keyring()
            if keyring:
                try:
                    keyring.delete_password(KEYRING_SERVICE, "token")
                except Exception:  # noqa: BLE001
                    pass
            store_path().unlink(missing_ok=True)
            print("✓ Saved Semgrep token removed")
        return 0
    except (SemgrepError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
