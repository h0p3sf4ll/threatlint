"""Azure DevOps credentials for checkouts, source browsing, and remediation PRs.

When adoPatParameter is configured, the service account PAT is read from AWS Parameter Store on demand,
only for adoOrganizations. It takes precedence over personal environment/local PATs and is never saved
locally. A failed lookup never falls back to another identity.

  threatlint ado login --organization ORG [--pat-stdin]     validate and save a PAT (Code: Read) for ORG
  threatlint ado status                                     list organizations with a PAT and their source
  threatlint ado logout [--organization ORG]                remove one organization's PAT, or all

One PAT is kept per organization, so several organizations can be cloned from; each clone uses the PAT
saved for its own organization, falling back to an `az login` token for an organization with none.

The PAT is validated against the organization before it is saved. It is kept in the OS credential
store when the optional `keyring` package is installed (macOS Keychain, Windows Credential Manager,
Secret Service on Linux), otherwise in ~/.threatlint/ado.json (%USERPROFILE%\\.threatlint\\ado.json on
Windows) readable only by the current user. Without a configured service account, THREATLINT_ADO_PAT,
AZURE_DEVOPS_EXT_PAT, and SYSTEM_ACCESSTOKEN take precedence over saved personal PATs.
"""

from __future__ import annotations

import getpass
import json
import os
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path

from threatlint import org_config, parameter_store
from threatlint.ado_payloads import AdoLoginError, _ORG, _PAT, store_payload, store_records, validation_request

ENV_NAMES = ("THREATLINT_ADO_PAT", "AZURE_DEVOPS_EXT_PAT", "SYSTEM_ACCESSTOKEN")
KEYRING_SERVICE = "threatlint-azure-devops"
SERVICE_ACCOUNT_SOURCE = "AWS Parameter Store (service account)"
PAT_HELP = ("Create a PAT at https://dev.azure.com/<organization>/_usersSettings/tokens with scope Code: Read "
            "(and Work Items: Read & write if you also close ADO items).")


def store_path() -> Path:
    return Path(os.environ.get("THREATLINT_HOME") or Path.home() / ".threatlint") / "ado.json"


def _keyring():
    try:
        import keyring  # noqa: PLC0415 - optional dependency
        keyring.get_keyring()
        return keyring
    except Exception:  # noqa: BLE001 - any backend failure means "not available"
        return None


def _urlopen(request, timeout):
    from threatlint.tls import ssl_context  # noqa: PLC0415
    return urllib.request.urlopen(request, timeout=timeout, context=ssl_context())  # noqa: S310 - fixed HTTPS host


def validate(organization: str, pat: str, opener=_urlopen) -> None:
    """A PAT that can list projects in the organization; ADO answers bad tokens with a 203 sign-in page."""
    request = validation_request(organization, pat)
    try:
        with opener(request, timeout=30) as response:  # noqa: S310 - fixed HTTPS host
            body = response.read()
            if response.status != 200 or not body.lstrip().startswith(b"{"):
                raise AdoLoginError(f"Azure DevOps did not accept the PAT for {organization}. {PAT_HELP}")
    except urllib.error.HTTPError as exc:
        reason = {401: "the PAT is invalid or expired", 403: "the PAT lacks access to this organization"}.get(exc.code, f"HTTP {exc.code}")
        raise AdoLoginError(f"Azure DevOps rejected the PAT: {reason}. {PAT_HELP}") from exc
    except urllib.error.URLError as exc:
        raise AdoLoginError(f"Could not reach Azure DevOps: {exc.reason}") from exc


def _read_store() -> dict[str, dict]:
    """Saved PAT records keyed by lower-case organization. Reads the older single-PAT file as one entry."""
    try:
        data = json.loads(store_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return store_records(data)


def _write_store(records: dict[str, dict]) -> None:
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Create with owner-only permissions; on Windows the user profile ACL already limits access.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(store_payload(records), handle)
    if os.name != "nt":
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def save(organization: str, pat: str) -> str:
    """Store the PAT for this organization, alongside PATs for other organizations; returns where it was stored."""
    records, keyring, key = _read_store(), _keyring(), organization.lower()
    if keyring:
        keyring.set_password(KEYRING_SERVICE, f"pat:{key}", pat)
        records[key] = {"organization": organization, "storage": "keyring", "keyring_user": f"pat:{key}"}
    else:
        records[key] = {"organization": organization, "storage": "file", "pat": pat}
    _write_store(records)
    return "the OS credential store" if keyring else str(store_path())


def _secret(record: dict) -> tuple[str, str]:
    if record.get("storage") == "keyring":
        keyring = _keyring()
        pat = keyring.get_password(KEYRING_SERVICE, record.get("keyring_user") or "pat") if keyring else None
        return (pat, "OS credential store") if pat else ("", "")
    return (record.get("pat", ""), str(store_path())) if record.get("pat") else ("", "")


def organizations() -> list[str]:
    """Organizations served by the configured credential source; never resolves a secret."""
    shared = service_account_config()
    if shared["parameter"]:
        return shared["organizations"]
    return [record.get("organization") or key for key, record in _read_store().items()]


def _validate_service_account(parameter: str, organizations: list[str], profile: str | None, region: str) -> None:
    if not parameter:
        raise AdoLoginError("Configure adoPatParameter or THREATLINT_ADO_PAT_PARAMETER for the Azure DevOps service account.")
    if not organizations or any(not _ORG.fullmatch(organization) for organization in organizations):
        raise AdoLoginError("Set adoOrganizations to valid Azure DevOps organization names before using the service account.")
    try:
        parameter_store.validate_reference(parameter, profile=profile, region=region)
    except parameter_store.ParameterStoreError as exc:
        raise AdoLoginError(str(exc)) from None


def service_account_config() -> dict:
    """Public configuration metadata only; no SSM call or local secret lookup."""
    organizations = list({name.lower(): name for name in org_config.values("adoOrganizations")}.values())
    config = {"parameter": org_config.value("adoPatParameter"), "organizations": organizations,
              "profile": org_config.aws_profile(), "region": org_config.aws_region()}
    try:
        _validate_service_account(**config)
    except AdoLoginError:
        config["configured"] = False
    else:
        config["configured"] = True
    return config


def _read_service_account(parameter: str, profile: str | None, region: str) -> str:
    try:
        pat = parameter_store.read_parameter(parameter, profile=profile, region=region).strip()
    except parameter_store.ParameterStoreError as exc:
        raise AdoLoginError(f"Azure DevOps service account: {exc}") from None
    if not _PAT.fullmatch(pat):
        raise AdoLoginError("The Azure DevOps service account parameter does not contain a valid PAT.")
    return pat


def service_account_pat(organization: str, profile: str | None = None) -> tuple[str, str]:
    """Require the SSM service account for an allowed organization; never use a personal fallback."""
    config = service_account_config()
    selected_profile = config["profile"] if profile is None else profile
    _validate_service_account(config["parameter"], config["organizations"], selected_profile, config["region"])
    if not isinstance(organization, str) or organization.lower() not in {name.lower() for name in config["organizations"]}:
        raise AdoLoginError("The Azure DevOps organization is not allowed by adoOrganizations for the service account.")
    return _read_service_account(config["parameter"], selected_profile, config["region"]), SERVICE_ACCOUNT_SOURCE


def public_status() -> dict:
    """Report credential source metadata without retrieving a PAT from SSM or the keyring."""
    shared = service_account_config()
    if shared["parameter"]:
        sources = [{"name": organization, "source": SERVICE_ACCOUNT_SOURCE} for organization in shared["organizations"]] if shared["configured"] else []
        return {"hasPat": shared["configured"], "source": SERVICE_ACCOUNT_SOURCE if shared["configured"] else None,
                "organizations": sources, "serviceAccount": shared}
    env = next((name for name in ENV_NAMES if os.environ.get(name)), "")
    sources = []
    for key, record in _read_store().items():
        source = env or ("OS credential store" if record.get("storage") == "keyring" else str(store_path()) if record.get("pat") else "")
        if source:
            sources.append({"name": record.get("organization") or key, "source": source})
    source = env or "; ".join(dict.fromkeys(item["source"] for item in sources)) or None
    return {"hasPat": bool(source), "source": source, "organizations": sources, "serviceAccount": shared}


def configure_service_account(parameter: str, organizations: list[str], profile: str | None = None,
                              region: str | None = None) -> Path:
    """Validate the selected service account everywhere, then save only its references and scope."""
    selected_profile = org_config.aws_profile() if profile is None else profile
    selected_region = org_config.aws_region() if region is None else region
    organizations = list({name.strip().lower(): name.strip() for name in organizations}.values())
    _validate_service_account(parameter, organizations, selected_profile, selected_region)
    pat = _read_service_account(parameter, selected_profile, selected_region)
    for organization in organizations:
        validate(organization, pat)
    updates = {"adoPatParameter": parameter, "adoOrganizations": organizations, "awsRegion": selected_region}
    if selected_profile is not None:
        updates["awsProfile"] = selected_profile
    try:
        return org_config.update_metadata(updates)
    except parameter_store.ParameterStoreError as exc:
        raise AdoLoginError(str(exc)) from None


def load(organization: str = "", profile: str | None = None) -> tuple[str, str]:
    """(PAT, source label); ('', '') when none is configured.

    A configured SSM service account wins. Otherwise use an environment PAT or the PAT saved for the
    organization. Missing/denied service account access raises instead of switching identities."""
    shared = service_account_config()
    if shared["parameter"]:
        return service_account_pat(organization or next(iter(shared["organizations"]), ""), profile)
    for name in ENV_NAMES:
        if os.environ.get(name):
            return os.environ[name], name
    records = _read_store()
    if organization:
        record = records.get(organization.lower())
        return _secret(record) if record else ("", "")
    return next((found for found in map(_secret, records.values()) if found[0]), ("", ""))


def logout(organization: str = "") -> bool:
    """Remove the PAT for one organization, or every saved PAT."""
    records, keyring = _read_store(), _keyring()
    key = organization.lower()
    targets = ({key: records[key]} if key in records else {}) if organization else records
    if not targets:
        return False
    for record in targets.values():
        if keyring and record.get("storage") == "keyring":
            try:
                keyring.delete_password(KEYRING_SERVICE, record.get("keyring_user") or "pat")
            except Exception:  # noqa: BLE001 - nothing stored
                pass
    remaining = {name: value for name, value in records.items() if name not in targets}
    if remaining:
        _write_store(remaining)
    else:
        store_path().unlink(missing_ok=True)
    return True


def prompt_and_save(organization: str = "", pat_from_stdin: bool = False) -> str:
    """Interactive (or --pat-stdin) setup used by `ado login` and by checkout when no PAT exists."""
    if not organization:
        if not sys.stdin.isatty():
            raise AdoLoginError("Pass --organization when not running interactively")
        organization = input("Azure DevOps organization (e.g. contoso): ").strip()
    if pat_from_stdin:
        pat = sys.stdin.readline().strip()
    else:
        if not sys.stdin.isatty():
            raise AdoLoginError("No terminal to prompt for the PAT. Run `threatlint ado login` in a terminal, or pipe it with --pat-stdin")
        print(PAT_HELP)
        pat = getpass.getpass("Azure DevOps PAT (input hidden): ").strip()
    validate(organization, pat)
    return save(organization, pat)


# ── CLI ───────────────────────────────────────────────────────────────────────

def add_ado_parser(sub) -> None:
    p = sub.add_parser("ado", help="Set up an Azure DevOps PAT for cloning AVIT repositories")
    actions = p.add_subparsers(dest="ado_command", required=True)
    login = actions.add_parser("login", help="Validate and save a PAT (Code: Read)")
    login.add_argument("--organization", default="", help="Azure DevOps organization, e.g. contoso")
    login.add_argument("--pat-stdin", action="store_true", help="Read the PAT from standard input instead of prompting")
    status = actions.add_parser("status", help="Show credential source metadata without retrieving or printing PATs")
    status.add_argument("--json", action="store_true", help="Return source and service account configuration as JSON")
    shared = actions.add_parser("service-account", help="Validate an AWS Parameter Store PAT and save only its configuration")
    shared.add_argument("--parameter", required=True, help="SSM parameter name or ARN containing the service account PAT")
    shared.add_argument("--organization", action="append", required=True, help="Allowed Azure DevOps organization; repeat for each")
    shared.add_argument("--aws-profile", default=None, help="AWS profile with parameter access (or configured awsProfile)")
    shared.add_argument("--region", default=None, help="AWS region containing the parameter (or configured awsRegion)")
    # The Workbench reads a saved PAT over a pipe to open its source connection; not for interactive use.
    token = actions.add_parser("token", help="Print a saved PAT to a pipe (for the Workbench; refuses a terminal)")
    token.add_argument("--organization", required=True)
    token.add_argument("--aws-profile", default=None)
    logout_parser = actions.add_parser("logout", help="Remove a saved PAT (one organization, or all)")
    logout_parser.add_argument("--organization", default="", help="Remove only this organization's PAT")


def cmd_ado(args) -> int:
    try:
        if args.ado_command == "login":
            organization = args.organization.strip()
            where = prompt_and_save(organization, args.pat_stdin)
            print(f"✓ PAT validated and saved to {where}{' for ' + organization if organization else ''}")
        elif args.ado_command == "service-account":
            where = configure_service_account(args.parameter, args.organization, args.aws_profile, args.region)
            print(f"✓ Azure DevOps service account validated; configuration saved to {where}. The PAT is not stored locally.")
        elif args.ado_command == "token":
            if sys.stdout.isatty():
                raise AdoLoginError("Refusing to print a PAT to a terminal")
            profile = getattr(args, "aws_profile", None)
            pat = (load(args.organization.strip(), profile=profile) if profile is not None else load(args.organization.strip()))[0]
            if not pat:
                raise AdoLoginError(f"No PAT saved for {args.organization}")
            sys.stdout.write(pat)
        elif args.ado_command == "status":
            status = public_status()
            if getattr(args, "json", False):
                print(json.dumps(status))
            else:
                lines = [f"Azure DevOps PAT: {item['source']} · {item['name']}" for item in status["organizations"]]
                if status["hasPat"] and not lines:
                    lines.append(f"Azure DevOps PAT: {status['source']} (all organizations)")
                print("\n".join(lines) if lines else "No Azure DevOps PAT configured. Configure a service account or run `threatlint ado login --organization <org>`.")
        else:
            organization = args.organization.strip()
            print(("✓ Saved PAT removed" + (f" for {organization}" if organization else "")) if logout(organization) else "No saved PAT")
        return 0
    except (AdoLoginError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
