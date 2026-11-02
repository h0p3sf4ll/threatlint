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
from threatlint import semgrep_rule_text
from threatlint import semgrep_policies
from threatlint import semgrep_engine
from threatlint import semgrep_cli
from threatlint.semgrep_engine import merge_exclusions
from threatlint.semgrep_policies import (
    PRODUCT_POLICY, TUNED_MODE, products as _products, same_rule as _same_rule, tunes as _tunes,
)
from threatlint.semgrep_rule_text import (
    EXCLUSION as _EXCLUSION,
    fixture_lines as _fixture_lines,
    tuned_rule_from_report,
)
from threatlint.tls import ssl_context, tool_env

API = os.environ.get("THREATLINT_SEMGREP_API", "https://semgrep.dev").rstrip("/")
KEYRING_SERVICE = "threatlint-semgrep"
_TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]{20,200}")


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

def _semgrep(args: list[str], cwd: str | None = None, token: str | None = None) -> subprocess.CompletedProcess:
    return semgrep_engine.run(args, cwd, token, environment=tool_env, error_type=SemgrepError)


def _pro_flags() -> list[str]:
    """Pro engine flags when it is installed (--pro also enables the Pro-only languages: Apex, Elixir, ...)."""
    return ["--pro"] if _semgrep(["scan", "--pro", "--version"]).returncode == 0 else []


def _matches(config: str, target: str, line: int | None, exact: bool = False) -> list[int]:
    """Lines the config reports in target: all of them, or those within 3 lines of `line` (exactly `line` when exact)."""
    return semgrep_engine.matches(config, target, line, exact, run=_semgrep, pro_flags=_pro_flags, error_type=SemgrepError)


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


def validate_tuned_rule(rule_yaml: str, original_rule: str, target_file: str, line: int | None, fixtures: str = "",
                        token: str | None = None) -> dict:
    """Prove validity, fixture coverage, and any reproducible local false-positive drop."""
    return semgrep_engine.validate_tuned_rule(
        rule_yaml, original_rule, target_file, line, fixtures, token, run=_semgrep, pro_flags=_pro_flags,
        matches=_matches, original_rule_yaml=original_rule_yaml, fixture_lines=_fixture_lines, error_type=SemgrepError,
    )


def publish(rule_path: str, token: str) -> str:
    """Publish as an org-private rule; returns the rule's registry path."""
    return semgrep_engine.publish(rule_path, token, run=_semgrep, error_type=SemgrepError)


def _policy_rules(dep_id: str, policy_id: str, token: str) -> list[dict]:
    return semgrep_policies.policy_rules(dep_id, policy_id, token, call=call)


def replace_in_policies(token: str, dep: dict, kind: str, original_rule: str, tuned_path: str) -> list[dict]:
    """Add the tuned rule in monitor mode and disable the original, in every policy that runs it."""
    return semgrep_policies.replace_in_policies(
        token, dep, kind, original_rule, tuned_path, call=call, replace_in=_replace_in, error_type=SemgrepError,
    )


def _replace_in(token: str, dep: dict, policies: list[dict], original_rule: str, tuned_path: str) -> list[dict]:
    return semgrep_policies.replace_in(
        token, dep, policies, original_rule, tuned_path, call=call, policy_rules=_policy_rules, mode=TUNED_MODE,
    )


def disable_originals(token: str, dep: dict, kind: str, original_rule: str) -> list[dict]:
    """Disable the original wherever its tuned rule is enabled in the same policy (it can be re-enabled after tuning)."""
    return semgrep_policies.disable_originals(token, dep, kind, original_rule, call=call, policy_rules=_policy_rules)


def existing_tuning(token: str, dep: dict, kind: str, original_rule: str) -> list[dict]:
    """Policies already running a Threatlint-tuned version of this rule (`[<deployment>.]<rule id>.tuned`)."""
    return semgrep_policies.existing_tuning(token, dep, kind, original_rule, call=call, policy_rules=_policy_rules)


def _exclusions(rule_yaml: str) -> list[str]:
    """Exclusion and sanitizer lines of a rule, compared without indentation."""
    return semgrep_rule_text.exclusions(rule_yaml, _EXCLUSION)


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
    fixtures = semgrep_rule_text.fixtures_from_report(report)
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
    for change in changes:
        print(f"    Rollback: set {change['original']} back to {change['original_mode']} and disable the tuned rule in {change['policy']}.", file=out)
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
    return semgrep_cli.login(
        token, deployment_slug, from_stdin, profile, parameter_token=parameter_store_token,
        parameter_name=token_parameter, deployment=deployment, save_token=save_token,
        token_pattern=_TOKEN, error_type=SemgrepError,
    )


def add_semgrep_parser(sub) -> None:
    semgrep_cli.add_semgrep_parser(sub, products=PRODUCT_POLICY)


def _logout() -> None:
    semgrep_cli.logout(keyring=_keyring(), store_path=store_path(), service=KEYRING_SERVICE)


def cmd_semgrep(args) -> int:
    return semgrep_cli.cmd_semgrep(
        args, login=login, resolve_token=resolve_token, rule_base=rule_base,
        deployment=deployment, logout=_logout, error_type=SemgrepError,
    )
