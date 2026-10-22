"""`threatlint setup`: one-time, interactive setup of every integration the AVIT workflow uses.

Each step is skipped when it is already configured, and can be re-run on its own:
  1. AWS IAM Identity Center sign-in in a private browser window   (threatlint aws login)
  2. ServiceNow instance URL and OAuth client, saved for the CLI and Workbench (~/.threatlint/servicenow.json)
  3. Azure DevOps PAT with Code: Read                                (threatlint ado login)
  4. Semgrep API token                                               (threatlint semgrep login)
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

from threatlint import ado_login, semgrep_platform, servicenow


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


def step_aws(profile: str) -> None:
    from threatlint import aws_login  # noqa: PLC0415
    current = aws_login.existing_profile(profile)
    if current and _yes(f"AWS profile '{profile}' exists. Sign in now (opens a private browser window)?") or not current and _yes("Set up AWS SSO sign-in?"):
        aws_login.cmd_aws(types.SimpleNamespace(profile=profile, start_url=os.environ.get(aws_login.START_URL_ENV, ""),
                                                sso_region=os.environ.get(aws_login.SSO_REGION_ENV, ""), account_id=None, role=None))


def step_servicenow(profile: str) -> None:
    saved = servicenow.saved_config()
    if saved.get("instance") and saved.get("clientId") and saved.get("clientSecret"):
        print(f"✓ ServiceNow: {saved['instance']} (saved)")
        return
    instance = servicenow.validate_instance_url(input("ServiceNow instance URL (https://<instance>.service-now.com): ").strip())
    try:
        client_id, client_secret = servicenow.read_parameter_store(profile)
        print("  Read the ServiceNow OAuth client from Parameter Store.")
    except servicenow.ServiceNowError:
        client_id = input("ServiceNow client ID: ").strip()
        client_secret = getpass.getpass("ServiceNow client secret (input hidden): ").strip()
    servicenow.access_token(instance, client_id, client_secret)
    print(f"✓ ServiceNow credentials validated and saved to {_save_servicenow(instance, client_id, client_secret)}")


def step_ado() -> None:
    _pat, source = ado_login.load()
    if source:
        print(f"✓ Azure DevOps PAT: {source}")
        return
    if _yes("Set up an Azure DevOps PAT (Code: Read) for cloning AVIT repositories?"):
        print(f"✓ Azure DevOps PAT validated and saved to {ado_login.prompt_and_save()}")


def step_semgrep(profile: str) -> None:
    try:
        _token, source = semgrep_platform.resolve_token(profile)
        if source != "SEMGREP_APP_TOKEN" and "Parameter Store" not in source:
            print(f"✓ Semgrep token: {source}")
            return
    except semgrep_platform.SemgrepError:
        pass
    print(f"✓ Semgrep token validated and saved to {semgrep_platform.login(profile=profile)}")


def add_setup_parser(sub) -> None:
    p = sub.add_parser("setup", help="One-time setup: AWS SSO, ServiceNow, Azure DevOps PAT, and Semgrep token")
    p.add_argument("--aws-profile", default="appsec", help="AWS CLI profile (default: appsec)")


def cmd_setup(args) -> int:
    if not sys.stdin.isatty():
        print("ERROR: `threatlint setup` is interactive; run it in a terminal", file=sys.stderr)
        return 1
    steps = (("AWS sign-in", lambda: step_aws(args.aws_profile)), ("ServiceNow", lambda: step_servicenow(args.aws_profile)),
             ("Azure DevOps", step_ado), ("Semgrep", lambda: step_semgrep(args.aws_profile)))
    failed = []
    for name, step in steps:
        print(f"\n── {name} ──")
        try:
            step()
        except (servicenow.ServiceNowError, ado_login.AdoLoginError, semgrep_platform.SemgrepError, OSError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            failed.append(name)
    print("\nSetup complete." if not failed else f"\nSetup finished with errors in: {', '.join(failed)}. Re-run `threatlint setup` after fixing them.")
    return 1 if failed else 0
