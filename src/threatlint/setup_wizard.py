"""`threatlint setup`: one-time, interactive setup of every integration the AVIT workflow uses.

Steps 2-4 are required for `/fp-review <AVIT>` and the Workbench batch; each is skipped when it is already
configured, and can be re-run on its own. `threatlint setup --check` reports what is missing without prompting.
  1. AWS IAM Identity Center sign-in in a private browser window   (threatlint aws login)
  2. ServiceNow instance URL and OAuth client, saved for the CLI and Workbench (~/.threatlint/servicenow.json)
  3. Azure DevOps PAT with Code: Read                                (threatlint ado login)
  4. Semgrep API token                                               (threatlint semgrep login)
  5. GitHub App, optional, for GitHub clones, PR comments, and issues (threatlint github login)
Secrets are typed with hidden input or read from Parameter Store; they are never echoed.
"""

from __future__ import annotations

import getpass
import json
import os
import stat
import sys
import types
from pathlib import Path

from threatlint import ado_login, github_app, org_config, parameter_store, semgrep_platform, servicenow


class SetupError(RuntimeError):
    """A setup prerequisite failed; dependent steps must not prompt for credentials."""


def _yes(question: str) -> bool:
    return input(f"{question} [Y/n] ").strip().lower() in ("", "y", "yes")


def _save_servicenow(instance: str, client_id: str, client_secret: str) -> Path:
    path = Path(os.environ.get("THREATLINT_HOME") or Path.home() / ".threatlint") / "servicenow.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump({"instance": instance, "clientId": client_id, "clientSecret": client_secret}, handle, indent=2)
    if os.name != "nt":
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return path


def step_aws(profile: str) -> bool:
    from threatlint import aws_login  # noqa: PLC0415
    current = aws_login.existing_profile(profile)
    if current and _yes(f"AWS profile '{profile}' exists. Sign in now (opens a private browser window)?") or not current and _yes("Set up AWS SSO sign-in?"):
        status = aws_login.cmd_aws(types.SimpleNamespace(profile=profile, start_url=os.environ.get(aws_login.START_URL_ENV, ""),
                                                        sso_region=os.environ.get(aws_login.SSO_REGION_ENV, ""), account_id=None, role=None))
        if status:
            raise SetupError("AWS sign-in failed. Fix the error above and rerun `threatlint setup`; integration setup has stopped.")
        return True
    return False


def step_org_config(profile: str, parameter: str = "", region: str | None = None, *, ask: bool = False) -> None:
    parameter = parameter or org_config.value("orgParameter")
    if not parameter and ask and not any(org_config.value(key) for key in
                                        ("snowClientIdParameter", "snowClientSecretParameter", "semgrepTokenParameter", "adoPatParameter")):
        parameter = input("AWS parameter containing shared setup settings (leave blank for manual setup): ").strip()
    if parameter:
        where = org_config.bootstrap(parameter, profile=profile, region=region)
        print(f"✓ Shared setup settings loaded from Parameter Store and saved to {where}")


def _snow_instance(saved: dict[str, str]) -> str:
    return os.environ.get(servicenow.INSTANCE_ENV, "").strip() or saved.get("instance", "") or org_config.value("snowInstance")


def step_servicenow(profile: str) -> None:
    saved = servicenow.saved_config()
    instance = _snow_instance(saved)
    env_id = os.environ.get(servicenow.CLIENT_ID_ENV, "").strip()
    env_secret = os.environ.get(servicenow.CLIENT_SECRET_ENV, "").strip()
    if bool(env_id) != bool(env_secret):
        raise servicenow.ServiceNowError("Set both THREATLINT_SNOW_CLIENT_ID and THREATLINT_SNOW_CLIENT_SECRET, or unset both to use Parameter Store.")
    if instance == saved.get("instance") and saved.get("clientId") and saved.get("clientSecret") and not env_id:
        print(f"✓ ServiceNow: {saved['instance']} (saved)")
        return
    if env_id:
        client_id, client_secret = env_id, env_secret
    elif saved.get("clientId") and saved.get("clientSecret"):
        client_id, client_secret = saved["clientId"], saved["clientSecret"]
    elif any(servicenow.client_parameters()):
        # A configured lookup must succeed. Never hide access/SSO/region errors behind secret prompts.
        client_id, client_secret = servicenow.read_parameter_store(profile)
        print("  Read the ServiceNow OAuth client from Parameter Store.")
    else:
        print("No ServiceNow Parameter Store names are configured. Load shared settings with --org-parameter to read credentials from AWS.")
        client_id = input("ServiceNow client ID: ").strip()
        client_secret = getpass.getpass("ServiceNow client secret (input hidden): ").strip()
    instance = servicenow.validate_instance_url(instance or input("ServiceNow instance URL (https://<instance>.service-now.com): ").strip())
    servicenow.access_token(instance, client_id, client_secret)
    print(f"✓ ServiceNow credentials validated and saved to {_save_servicenow(instance, client_id, client_secret)}")


def step_ado(profile: str | None = None) -> None:
    organizations = org_config.values("adoOrganizations")
    parameter = org_config.value("adoPatParameter")
    if parameter and not organizations:
        raise ado_login.AdoLoginError("Set adoOrganizations in the shared setup settings before reading the Azure DevOps PAT from Parameter Store.")
    if organizations:
        missing = [organization for organization in organizations if not ado_login.load(organization)[0]]
        if parameter and missing:
            pat = parameter_store.read_parameter(parameter, profile=profile)
            for organization in missing:
                ado_login.validate(organization, pat)
            for organization in missing:
                where = ado_login.save(organization, pat)
                print(f"✓ Azure DevOps PAT read from Parameter Store, validated and saved to {where} for {organization}")
        else:
            for organization in missing:
                print(f"✓ Azure DevOps PAT validated and saved to {ado_login.prompt_and_save(organization)} for {organization}")
        if not missing:
            print("✓ Azure DevOps PAT: configured for every selected organization")
        return
    _pat, source = ado_login.load()
    if source:
        print(f"✓ Azure DevOps PAT: {source}")
        return
    print("An Azure DevOps PAT (Code: Read) is required to clone AVIT repositories.")
    print(f"✓ Azure DevOps PAT validated and saved to {ado_login.prompt_and_save()}")


def step_semgrep(profile: str) -> None:
    token = os.environ.get("SEMGREP_APP_TOKEN", "").strip()
    if not token:
        token, source = semgrep_platform.saved_token()
        if token:
            print(f"✓ Semgrep token: {source}")
            return
        if semgrep_platform.token_parameter():
            token = semgrep_platform.parameter_store_token(profile)
    print(f"✓ Semgrep token validated and saved to {semgrep_platform.login(token=token, profile=profile)}")


def step_github() -> None:
    """Optional: a GitHub App replaces personal GitHub tokens for clones, PR comments, issues, and API calls."""
    if github_app.configured():
        print(f"✓ GitHub App: configured ({github_app.load_config()['source']})")
        return
    current = github_app.source()
    if input(f"Set up a GitHub App for GitHub access{' (now: ' + current + ')' if current else ''}? [y/N] ").strip().lower() not in ("y", "yes"):
        print("  Skipped. Run `threatlint github login` later; see docs/github-app.md.")
        return
    path, count, _owner = github_app.login()
    print(f"✓ GitHub App validated ({count} repositor{'y' if count == 1 else 'ies'}) and saved to {path}")


def optional_check() -> list[tuple[str, str, str]]:
    """Optional integrations, reported by --check but not required for it to pass."""
    return [("GitHub credential", github_app.source(), "threatlint github login  (or Workbench → Settings → GitHub)")]


def check(profile: str | None = None) -> list[tuple[str, str, str]]:
    """(name, where it comes from or '', the command that fixes it) for each required credential. Never prints a value."""
    saved = servicenow.saved_config()
    snow = ("THREATLINT_SNOW_CLIENT_ID / THREATLINT_SNOW_CLIENT_SECRET" if _snow_instance(saved) and os.environ.get("THREATLINT_SNOW_CLIENT_ID") and os.environ.get("THREATLINT_SNOW_CLIENT_SECRET")
            else "~/.threatlint/servicenow.json" if saved.get("instance") and saved.get("clientId") and saved.get("clientSecret") else "")
    if not snow and _snow_instance(saved) and all(servicenow.client_parameters()):
        try:
            servicenow.read_parameter_store(profile)
            snow = "AWS Parameter Store"
        except servicenow.ServiceNowError:
            pass
    organizations = org_config.values("adoOrganizations")
    if organizations:
        ado = "configured for every selected organization" if all(ado_login.load(org)[0] for org in organizations) else ""
    else:
        _pat, ado = ado_login.load()
    try:
        semgrep = semgrep_platform.resolve_token(profile)[1]
    except semgrep_platform.SemgrepError:
        semgrep = ""
    return [("ServiceNow OAuth client", snow, "threatlint setup  (or Workbench → Settings → ServiceNow)"),
            ("Azure DevOps PAT", ado, "threatlint ado login --organization <org>  (or Workbench → Settings → Azure DevOps)"),
            ("Semgrep API token", semgrep, "threatlint semgrep login  (or Workbench → Settings → Semgrep)")]


def cmd_check(args) -> int:
    results = check(args.aws_profile)
    if args.json:
        print(json.dumps([{"name": name, "configured": bool(source), "source": source or None, "fix": fix} for name, source, fix in results]))
    else:
        for name, source, fix in results:
            print(f"✓ {name}: {source}" if source else f"✗ {name}: not configured. Run: {fix}")
        for name, source, fix in optional_check():
            print(f"✓ {name}: {source}" if source else f"- {name} (optional): not configured. Run: {fix}")
    return 0 if all(source for _name, source, _fix in results) else 1


def add_setup_parser(sub) -> None:
    p = sub.add_parser("setup", help="One-time setup: AWS SSO, ServiceNow, Azure DevOps PAT, Semgrep token, and (optional) GitHub App")
    p.add_argument("--aws-profile", default="appsec", help="AWS CLI profile (default: appsec)")
    p.add_argument("--org-parameter", metavar="NAME", default="", help="AWS Parameter Store JSON parameter containing shared setup settings (or THREATLINT_ORG_PARAMETER)")
    p.add_argument("--aws-region", metavar="REGION", help="AWS region for setup parameters (or THREATLINT_AWS_REGION; default: us-west-2)")
    p.add_argument("--check", action="store_true", help="Report which required credentials are missing, without prompting")
    p.add_argument("--json", action="store_true", help="With --check, print the result as JSON")


def cmd_setup(args) -> int:
    region = getattr(args, "aws_region", None)
    parameter = getattr(args, "org_parameter", "") or org_config.value("orgParameter")
    try:
        if region:
            os.environ[org_config.ENV["awsRegion"]] = parameter_store.validate_region(region)
        if parameter:
            parameter_store.validate_reference(parameter, args.aws_profile, region)
    except parameter_store.ParameterStoreError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if getattr(args, "check", False):
        return cmd_check(args)
    if not sys.stdin.isatty():
        print("ERROR: `threatlint setup` is interactive; run it in a terminal", file=sys.stderr)
        return 1
    from threatlint import aws_login  # noqa: PLC0415
    errors = (SetupError, parameter_store.ParameterStoreError, aws_login.AwsLoginError, servicenow.ServiceNowError,
              ado_login.AdoLoginError, semgrep_platform.SemgrepError, github_app.GitHubAppError, OSError)
    print("\n── AWS sign-in ──")
    try:
        signed_in = step_aws(args.aws_profile)
        step_org_config(args.aws_profile, parameter, region, ask=signed_in)
    except errors as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    steps = (("ServiceNow", lambda: step_servicenow(args.aws_profile)), ("Azure DevOps", lambda: step_ado(args.aws_profile)),
             ("Semgrep", lambda: step_semgrep(args.aws_profile)), ("GitHub App (optional)", step_github))
    failed = []
    for name, step in steps:
        print(f"\n── {name} ──")
        try:
            step()
        except errors as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            failed.append(name)
    missing = [name for name, source, _fix in check(args.aws_profile) if not source]
    failed += [name for name in missing if name not in failed]
    print("\nSetup complete." if not failed else f"\nSetup finished with errors in: {', '.join(failed)}. Re-run `threatlint setup` after fixing them.")
    return 1 if failed else 0
