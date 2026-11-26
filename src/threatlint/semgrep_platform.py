"""Semgrep AppSec Platform: API token setup and false-positive rule tuning.

  threatlint semgrep login [--token-stdin]   validate and save the Semgrep API token
  threatlint semgrep status | logout

Token resolution: SEMGREP_APP_TOKEN, then the saved token (OS credential store via `keyring`, else
~/.threatlint/semgrep.json, owner-only; shared with the Workbench), then the native Semgrep
login in ~/.semgrep/settings.yml (or SEMGREP_SETTINGS_FILE), then AWS Parameter Store
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
Unified deployments support project-scoped detection exceptions, not legacy policy modes. A proven new rule
can replace a directly selected original for the exact project; a verified open Semgrep finding can also
identify a ruleset-supplied original. Unified extensions publish a fresh private version and switch only the project
(see docs/semgrep-policies.md).
"""

from __future__ import annotations

import base64  # noqa: F401 - kept for parity with ado_login
import json
import os
import re
import shutil  # noqa: F401 - the public engine adapter retains the executable lookup seam
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from threatlint import org_config, parameter_store, semgrep_credentials
from threatlint import semgrep_rule_text
from threatlint import semgrep_policies, semgrep_unified
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

    def __init__(self, message, *, status=None, api_code=None, tuning_write_uncertain=False):
        super().__init__(message)
        self.status = status
        self.api_code = api_code
        self.tuning_write_uncertain = tuning_write_uncertain


# ── Token ─────────────────────────────────────────────────────────────────────

def store_path() -> Path:
    return Path(os.environ.get("THREATLINT_HOME") or Path.home() / ".threatlint") / "semgrep.json"


def _keyring():
    # Web profiles must not read or write the host user's shared OS credential store.
    if os.environ.get("THREATLINT_PROFILE_WORKER") == "1":
        return None
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
    parameter = token_parameter()
    if not parameter:
        return ""
    try:
        return parameter_store.read_parameter(parameter, profile=profile, region=org_config.aws_region())
    except parameter_store.ParameterStoreError as exc:
        raise SemgrepError(str(exc)) from None


def resolve_token(profile: str | None = None) -> tuple[str, str]:
    if os.environ.get("SEMGREP_APP_TOKEN"):
        return os.environ["SEMGREP_APP_TOKEN"], "SEMGREP_APP_TOKEN"
    token, source = semgrep_credentials.native_token()
    if token:
        return token, source
    token, source = saved_token()
    if token:
        return token, source
    token = parameter_store_token(profile)
    if token:
        return token, f"Parameter Store {token_parameter()}"
    raise SemgrepError("No Semgrep API token. Run `semgrep login` or `threatlint semgrep login` (or `threatlint setup`), set SEMGREP_APP_TOKEN, "
                       "or sign in with `threatlint aws login` to read it from Parameter Store.")


# ── API ───────────────────────────────────────────────────────────────────────

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ssl_context()))


_HTTP_TIMEOUT_S = int(os.environ.get("THREATLINT_SEMGREP_TIMEOUT", "120"))
_RETRIES = 3


def call(path: str, token: str, *, method: str = "GET", body: dict | None = None,
         headers: dict | None = None) -> dict:
    """One Semgrep API call. Timeouts and 5xx/429 answers are retried with backoff: policy and publish calls on a
    large deployment are slow. Conditional Unified writes are never replayed after an uncertain result."""
    import time  # noqa: PLC0415
    if headers and set(headers) != {"If-Match"}:
        raise SemgrepError("Only the If-Match additional header is supported")
    attempts = 1 if method == "PUT" and headers else _RETRIES
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(f"{API}{path}", method=method, data=json.dumps(body).encode() if body is not None else None,
                                         headers={"Authorization": f"Bearer {token}", "Accept": "application/json",
                                                  **({"Content-Type": "application/json"} if body is not None else {}),
                                                  **(headers or {})})
        try:
            with _OPENER.open(request, timeout=_HTTP_TIMEOUT_S) as response:  # noqa: S310 - fixed HTTPS host
                raw = response.read()
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 500, 502, 503, 504) and attempt < attempts:
                time.sleep(2 ** attempt)
                continue
            raise _http_error(exc, path) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt < attempts:
                time.sleep(2 ** attempt)
                continue
            raise SemgrepError(f"Semgrep request failed after {attempts} attempts: {exc}") from exc
        except ValueError as exc:
            raise SemgrepError(f"Semgrep request failed: {exc}") from exc
    raise SemgrepError("Semgrep request failed")


def _http_error(exc, path: str) -> SemgrepError:
    hint = {401: " Check the Semgrep token.", 403: " The token needs the Web API scope.", 404: " Not found.",
            410: " This deployment uses the newer policies model."}.get(exc.code, "")
    try:
        payload = json.loads(exc.read())
        api_code = payload.get("code") if isinstance(payload, dict) else None
    except (OSError, ValueError):
        api_code = None
    return SemgrepError(f"Semgrep returned HTTP {exc.code} for {path.split('?')[0]}.{hint}",
                        status=exc.code, api_code=api_code)


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
    if token is None:
        try:
            token = resolve_token()[0]
        except SemgrepError:
            pass  # Explicit --pro scans still fail; never silently select the OSS engine.
    return semgrep_engine.run(args, cwd, token, environment=tool_env, error_type=SemgrepError)


def _pro_flags() -> list[str]:
    """Require Pro for rule proof; never silently downgrade to Community Edition."""
    return engine_flags()


def engine_status() -> dict:
    return semgrep_engine.engine_status(environment=tool_env)


def engine_flags(engine: str = "pro") -> list[str]:
    if engine == "oss":
        return ["--oss-only"]
    if engine != "pro":
        raise SemgrepError("Semgrep engine must be pro or oss")
    if not engine_status().get("pro_ready"):
        raise SemgrepError("Matching Semgrep Pro engine is unavailable. Run `semgrep install-semgrep-pro` using your Semgrep login; no Community Edition fallback was used.")
    return ["--pro"]


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
                        token: str | None = None, *, work: Path | None = None) -> dict:
    """Prove validity, fixture coverage, and any reproducible local false-positive drop."""
    return semgrep_engine.validate_tuned_rule(
        rule_yaml, original_rule, target_file, line, fixtures, token, run=_semgrep, pro_flags=_pro_flags,
        matches=_matches, original_rule_yaml=original_rule_yaml, fixture_lines=_fixture_lines, error_type=SemgrepError,
        work=work,
    )


def publish(rule_path: str, token: str) -> str:
    """Publish as an org-private rule; returns the rule's registry path."""
    return semgrep_engine.publish(rule_path, token, run=_semgrep, error_type=SemgrepError)


def _policy_rules(dep_id: str, policy_id: str, token: str) -> list[dict]:
    return semgrep_policies.policy_rules(dep_id, policy_id, token, call=call)


def policy_reads(token: str, dep: dict) -> list[dict]:
    """Legacy policy records or complete Unified snapshots, selected only on legacy HTTP 410."""
    return semgrep_policies.policy_reads(token, dep, call=call, error_type=SemgrepError)


def replace_in_policies(token: str, dep: dict, kind: str, original_rule: str, tuned_path: str, *,
                        project: str | None = None, mode: str = TUNED_MODE) -> list[dict]:
    """Replace a legacy rule, or explicitly opt into Unified project detection with mode='include'."""
    return semgrep_policies.replace_in_policies(
        token, dep, kind, original_rule, tuned_path, call=call, replace_in=_replace_in, error_type=SemgrepError,
        project=project, mode=mode,
    )


def _replace_in(token: str, dep: dict, policies: list[dict], original_rule: str, tuned_path: str, *,
                project: str | None = None, mode: str = TUNED_MODE) -> list[dict]:
    return semgrep_policies.replace_in(
        token, dep, policies, original_rule, tuned_path, call=call, policy_rules=_policy_rules, mode=mode,
        project=project, error_type=SemgrepError,
    )


def disable_originals(token: str, dep: dict, kind: str, original_rule: str, *,
                      project: str | None = None) -> list[dict]:
    """Disable the original wherever its tuned rule is enabled in the same policy (it can be re-enabled after tuning)."""
    return semgrep_policies.disable_originals(token, dep, kind, original_rule, call=call, policy_rules=_policy_rules,
                                             project=project, error_type=SemgrepError)


def existing_tuning(token: str, dep: dict, kind: str, original_rule: str, *,
                    project: str | None = None) -> list[dict]:
    """Policies already running a Threatlint-tuned version of this rule (`[<deployment>.]<rule id>.tuned`)."""
    return semgrep_policies.existing_tuning(token, dep, kind, original_rule, call=call, policy_rules=_policy_rules,
                                           project=project, error_type=SemgrepError)


def _exclusions(rule_yaml: str) -> list[str]:
    """Exclusion and sanitizer lines of a rule, compared without indentation."""
    return semgrep_rule_text.exclusions(rule_yaml, _EXCLUSION)


def _require_legacy_selection(token, dep, kind, original_rule):
    if kind not in PRODUCT_POLICY:
        raise SemgrepError(f"Semgrep {kind} findings do not have a tunable Code or Secrets rule")
    for policy in policy_reads(token, dep):
        if policy.get("unified"):
            raise SemgrepError("Unified rule tuning requires a current policy snapshot and an exact project name")
        if policy.get("productType") in _products(kind):
            rules = _policy_rules(str(dep["id"]), str(policy["id"]), token)
            if any(_same_rule(str(rule.get("path", "")), original_rule) and rule.get("policyMode") != "MODE_DISABLED"
                   for rule in rules):
                return
    raise SemgrepError(f"No directly selected rule runs {original_rule}; the rule was not published")


def _unified_target(policies, kind, original, project, already, verified):
    """Return the exact snapshot and original path to switch, and whether the original still runs."""
    if kind not in PRODUCT_POLICY or not isinstance(project, str) or not project.strip():
        raise SemgrepError("Unified rule tuning requires a Code or Secrets finding and an exact project name")
    direct, ruleset = [], None
    for policy in policies:
        bundle = policy["snapshot"]["bundle"]
        active = semgrep_unified.enabled(bundle, project, same_rule=_same_rule)
        live = [rule for rule in active if _tunes(rule, original)]
        known = [item for item in already if item.get("policy_id") == policy["id"]]
        if sorted(live) != sorted(item["tuned"] for item in known) or any(
            item["state_version"] != policy["snapshot"]["state_version"] for item in known
        ):
            raise SemgrepError("The active Unified tuning changed during review; prepare a new proposal")
        if already and not known:
            continue
        exceptions = [item for item in bundle["exceptions"] if item.get("project") == project and item["rule_type"] == "rule"]
        rule_paths = set(bundle["rules"] + bundle["disabled"]).union(item["rule"] for item in exceptions)
        originals = [rule for rule in rule_paths if _same_rule(rule, original)]
        if len(originals) > 1:
            raise SemgrepError("Several Unified rules match the original; use its unambiguous registry path")
        rule = originals[0] if originals else original
        included = rule in active
        eligible_pack = bool(bundle["rulesets"]) and rule not in bundle["disabled"] and not any(
            item["rule"] == rule and item["exception_type"] == "exclude" for item in exceptions)
        target = policy, rule, included or eligible_pack
        if live or included:
            direct.append(target)
        elif verified and eligible_pack and policy["productType"] == PRODUCT_POLICY[kind]:
            ruleset = target
    if len(direct) > 1:
        raise SemgrepError("Several Unified products select this rule; resolve its product before publication")
    target = direct[0] if direct else ruleset
    if target is None:
        raise SemgrepError(f"No directly selected Unified rule runs {original} for {project}; the rule was not published")
    semgrep_unified.check_scope(target[0]["snapshot"]["bundle"], project, [target[1], *(i["tuned"] for i in already)],
                                same_rule=_same_rule, error_type=SemgrepError)
    return target


def _versioned_proposal(rule_yaml, fixtures, original, deployment_slug):
    """Give a Unified publication a fresh registry identity; leave fixture source and detection logic intact."""
    proposal_id = f"{original}.tuned"
    base = semgrep_policies.original_id(original)
    if base != original and deployment_slug:
        base = base.removeprefix(f"{deployment_slug}.")
    version = f"{base}.tl-{uuid.uuid4().hex}.tuned"
    declaration = re.compile(r"(?m)^([ \t]*-[ \t]*id:[ \t]*)" + re.escape(proposal_id) + r"(?=[ \t]*(?:#.*)?$)")
    yaml, count = declaration.subn(lambda match: match[1] + version, rule_yaml)
    if count != 1:
        raise SemgrepError("The tuned rule ID must equal the original rule ID plus .tuned")
    # A marker can name several rules. Replace just this exact token inside its ID list.
    token = re.compile(r"(?<![\w.-])" + re.escape(proposal_id) + r"(?![\w.-])")
    markers = re.compile(r"((?:#|//|<!--|/\*|\(\*|--|;|%)[ \t]*(?:ruleid|ok):[ \t]*)([\w., \t-]+)")
    return yaml, markers.sub(lambda m: m[1] + token.sub(version, m[2]), fixtures), version


def live_rule_matches(rule_yaml: str, target_file: str, line: int | None) -> list[int] | None:
    """Scan one exact line with live rule source. An unavailable check returns None."""
    if not target_file or not os.path.exists(target_file) or not line:
        return None
    with tempfile.TemporaryDirectory(prefix="threatlint-live-", ignore_cleanup_errors=True) as work:
        config = Path(work) / "live.yaml"
        config.write_text(rule_yaml, encoding="utf-8")
        return _matches(str(config), target_file, line, exact=True)


def _legacy_policy_writes(operation, *args, **kwargs):
    """Legacy replacements can fail between independently acknowledged policy mutations."""
    try:
        return operation(*args, **kwargs)
    except SemgrepError as exc:
        exc.tuning_write_uncertain = True
        raise


def _proposal_for_live_rule(report, live_yaml, original_rule, token, out):
    rule_yaml = tuned_rule_from_report(report)
    if not rule_yaml:
        raise SemgrepError("The report has no `**Tuned rule**:` block, so the rule was not changed. Re-run the review: "
                           "a false positive on a SAST or Secrets rule must come with a proven tuned rule")
    if live_yaml:
        existing, proposed = _exclusions(live_yaml), set(_exclusions(rule_yaml))
        missing = [item for item in existing if item not in proposed]
        if missing:
            merged = merge_exclusions(rule_yaml, live_yaml, original_rule_yaml(original_rule, token))
            if merged and set(existing).issubset(_exclusions(merged)):
                print(f"  ! The live tuned rule gained {len(missing)} exclusion(s) since this proposal was written; merged them in (the proof gate still runs)", file=out)
                rule_yaml, missing = merged, []
        if missing:
            raise SemgrepError(f"The proposed rule drops {len(missing)} exclusion(s) the live tuned rule has; "
                               "it must extend the live tuned rule, not replace it")
    return rule_yaml


def _publish_proven(path, original_rule, token, dep, expected_path):
    if expected_path:
        # semgrep publish picks the token's current deployment, independently of the policy URL.
        response = call("/api/agent/deployments/current", token)
        current = response.get("deployment") if isinstance(response, dict) else None
        if not isinstance(current, dict) or str(current.get("id", "")) != str(dep["id"]):
            raise SemgrepError("The publishing token selects a different Semgrep deployment from the project's policy")
    try:
        tuned_path = publish(path, token)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SemgrepError("Semgrep private publication did not return a receipt; verify the registry before retrying",
                           tuning_write_uncertain=True) from exc
    except SemgrepError as exc:
        exc.tuning_write_uncertain = True
        raise
    if expected_path and tuned_path.lower() != expected_path.lower():
        raise SemgrepError("Semgrep returned a different private rule or deployment; no detection policy was changed",
                           tuning_write_uncertain=True)
    if not _tunes(tuned_path, original_rule):
        raise SemgrepError("Semgrep published a rule path that does not identify the expected tuned rule; no policy was changed",
                           tuning_write_uncertain=True)
    return tuned_path


def tune_rule(report: str, kind: str, original_rule: str, target_file: str, line: int | None, token: str, dep: dict,
              out=sys.stdout, *, project: str | None = None, verified_finding: bool = False,
              allow_live_shortcut: bool = True) -> list[dict]:
    """Make sure the scanner stops reporting this false positive, without human approval but only with proof.

    Legacy policies use a stable tuned rule and monitor mode. Unified policies select
    a fresh private version in one project's detection policy after the exact version passes proof."""
    scope = {"project": project} if project is not None else {}
    already = existing_tuning(token, dep, kind, original_rule, **scope)
    unified = None
    if project or any(item.get("unified") for item in already):
        policies = [policy for policy in policy_reads(token, dep) if policy.get("unified")]
        if policies:
            unified = _unified_target(policies, kind, original_rule, project, already, verified_finding)
        elif any(item.get("unified") for item in already):
            raise SemgrepError("Unified policies changed during tuning; prepare a new proposal")
    live_yaml = ""
    if already:
        live_path = already[0]["tuned"]
        live_yaml = original_rule_yaml(live_path, token)
        still = live_rule_matches(live_yaml, target_file, line) if allow_live_shortcut else None
        if still == []:
            for item in already:
                print(f"  ✓ {item['policy']} already runs {item['tuned']} ({item['mode']}), which covers the flagged line", file=out)
            if unified:
                policy, original, enabled = unified
                repairs = []
                if enabled and original != live_path:
                    repairs = semgrep_unified.apply(token, dep, policy, original, live_path, project,
                                                    call=call, same_rule=_same_rule, error_type=SemgrepError)
                else:
                    endpoint = semgrep_unified.path(dep["id"], policy["id"])
                    current = semgrep_unified.snapshot(call(endpoint, token), policy["id"], SemgrepError)
                    if current != policy["snapshot"]:
                        raise SemgrepError("The active detection policy changed during the live rule check")
            else:
                repairs = _legacy_policy_writes(disable_originals, token, dep, kind, original_rule, **scope)
            _report_disabled(repairs, out)
            print(f"  ✓ Rule tuning verified: {live_path} covers the flagged line", file=out)
            return [change for change in repairs if "rollback" in change]
        if still is None:
            print(f"  ! The live tuned rule {live_path} cannot be checked against the flagged line; validating an extension", file=out)
        else:
            print(f"  ! The live tuned rule {live_path} still reports this line; extending it", file=out)
    rule_yaml = _proposal_for_live_rule(report, live_yaml, original_rule, token, out)
    fixtures = semgrep_rule_text.fixtures_from_report(report)
    expected_path = ""
    if unified:
        policy, original, _ = unified
        slug = dep.get("slug") or policy["snapshot"]["bundle"].get("deployment_slug")
        if not slug:
            raise SemgrepError("The Unified policy does not identify a deployment slug for private publication")
        rule_yaml, fixtures, version = _versioned_proposal(rule_yaml, fixtures, original_rule, slug)
        expected_path = f"{slug}.{version}"
    checked = validate_tuned_rule(rule_yaml, original_rule, target_file, line, fixtures, token)
    if not already and not unified:
        _require_legacy_selection(token, dep, kind, original_rule)
    where = "and no longer reports the flagged line" if checked["dropped"] else "(the flagged line needs interfile analysis, so the fixtures are the proof)"
    print(f"  ✓ Tuned rule {checked['id']} is valid, keeps every true-positive fixture, drops the false-positive shape{', matches the original rule,' if checked['original_checked'] else ''} {where}", file=out)
    tuned_path = _publish_proven(checked["path"], original_rule, token, dep, expected_path)
    print(f"  ✓ Published org-private rule {tuned_path}{' (new version of the live tuned rule)' if live_yaml else ''}", file=out)
    if unified:
        if live_yaml and original_rule_yaml(already[0]["tuned"], token) != live_yaml:
            raise SemgrepError("The live tuned rule changed during proof; the new version was not selected")
        changes = semgrep_unified.apply(token, dep, policy, original, tuned_path, project,
                                        previous=already[0]["tuned"] if already else "",
                                        call=call, same_rule=_same_rule, error_type=SemgrepError)
    elif live_yaml:
        _report_disabled(_legacy_policy_writes(disable_originals, token, dep, kind, original_rule, **scope), out)
        print(f"  ✓ Rule tuning verified: updated active rule {tuned_path}", file=out)
        return [{"policy": item["policy"], "tuned": tuned_path, "mode": item["mode"], "original": original_rule} for item in already]
    else:
        changes = _legacy_policy_writes(replace_in_policies, token, dep, kind, original_rule, tuned_path,
                                        mode=TUNED_MODE, **scope)
    for change in changes:
        print(f"  ✓ {change['policy']}: {change['tuned']} enabled ({change['mode']}); {change['original']} disabled", file=out)
        if change.get("rollback"):
            print(f"    Rollback: restore the returned policy bundle with If-Match {change['rollback']['if_match']}.", file=out)
        else:
            print(f"    Rollback: set {change['original']} back to {change['original_mode']} and disable the tuned rule in {change['policy']}.", file=out)
    print(f"  ✓ Rule tuning verified: {tuned_path} selected in the detection policy", file=out)
    return changes


def _report_disabled(changes: list[dict], out) -> None:
    for change in changes:
        print(f"  ✓ {change['policy']}: {change['original']} was still enabled ({change['mode']}) beside its tuned rule; disabled", file=out)


def rule_base(rule: str, kind: str, token: str, dep: dict, *, project: str | None = None) -> tuple[str, str]:
    """(YAML, label) the reviewer should tune: the live tuned rule when one is deployed, else the original."""
    scope = {"project": project} if project is not None else {}
    live = existing_tuning(token, dep, kind, rule, **scope) if kind in PRODUCT_POLICY else []
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
