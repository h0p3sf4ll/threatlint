"""Azure DevOps personal access token setup so `threatlint avit checkout` can clone ADO repositories.

  threatlint ado login --organization ORG [--pat-stdin]     validate and save a PAT (Code: Read) for ORG
  threatlint ado status                                     list organizations with a PAT and their source
  threatlint ado logout [--organization ORG]                remove one organization's PAT, or all

One PAT is kept per organization, so several organizations can be cloned from; each clone uses the PAT
saved for its own organization, falling back to an `az login` token for an organization with none.

The PAT is validated against the organization before it is saved. It is kept in the OS credential
store when the optional `keyring` package is installed (macOS Keychain, Windows Credential Manager,
Secret Service on Linux), otherwise in ~/.threatlint/ado.json (%USERPROFILE%\\.threatlint\\ado.json on
Windows) readable only by the current user. THREATLINT_ADO_PAT, AZURE_DEVOPS_EXT_PAT, and
SYSTEM_ACCESSTOKEN take precedence when set.
"""

from __future__ import annotations

import base64
import getpass
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ENV_NAMES = ("THREATLINT_ADO_PAT", "AZURE_DEVOPS_EXT_PAT", "SYSTEM_ACCESSTOKEN")
KEYRING_SERVICE = "threatlint-azure-devops"
_ORG = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,49}")
_PAT = re.compile(r"[A-Za-z0-9._~+/=-]{20,200}")
PAT_HELP = ("Create a PAT at https://dev.azure.com/<organization>/_usersSettings/tokens with scope Code: Read "
            "(and Work Items: Read & write if you also close ADO items).")


class AdoLoginError(RuntimeError):
    """A user-actionable failure; messages never contain the PAT."""


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
    if not _ORG.fullmatch(organization):
        raise AdoLoginError("Enter the Azure DevOps organization name (e.g. contoso), not a URL")
    if not _PAT.fullmatch(pat):
        raise AdoLoginError("That does not look like an Azure DevOps PAT")
    request = urllib.request.Request(f"https://dev.azure.com/{urllib.parse.quote(organization)}/_apis/projects?$top=1&api-version=7.1",
                                     headers={"Authorization": "Basic " + base64.b64encode(f":{pat}".encode()).decode(), "Accept": "application/json"})
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
    if not isinstance(data, dict):
        return {}
    if isinstance(data.get("organizations"), dict):
        return {key: value for key, value in data["organizations"].items() if isinstance(value, dict)}
    if data.get("storage"):  # single-PAT format; its keyring entry is under the username "pat"
        return {str(data.get("organization") or "").lower(): {**data, "keyring_user": "pat"}}
    return {}


def _write_store(records: dict[str, dict]) -> None:
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Create with owner-only permissions; on Windows the user profile ACL already limits access.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    # Also keep the single-PAT keys at the top level, so older Threatlint copies (e.g. a desktop app not yet
    # updated) still find their PAT and do not rewrite the file in the old format.
    legacy = next((record for record in records.values() if record.get("keyring_user") in ("pat", None)), next(iter(records.values()), {}))
    top = {key: legacy[key] for key in ("organization", "storage", "pat") if key in legacy}
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump({**top, "organizations": records}, handle)
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
    """Organizations with a saved PAT (never the PATs themselves)."""
    return [record.get("organization") or key for key, record in _read_store().items()]


def load(organization: str = "") -> tuple[str, str]:
    """(PAT, source label); ('', '') when none is configured.

    An environment PAT wins. Otherwise the PAT saved for `organization`; with no organization given, the
    only (or first) saved PAT. A PAT saved for one organization is never returned for another."""
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
    actions.add_parser("status", help="Show which organizations have a PAT and where each comes from (never prints them)")
    # The Workbench reads a saved PAT over a pipe to open its source connection; not for interactive use.
    token = actions.add_parser("token", help="Print a saved PAT to a pipe (for the Workbench; refuses a terminal)")
    token.add_argument("--organization", required=True)
    logout_parser = actions.add_parser("logout", help="Remove a saved PAT (one organization, or all)")
    logout_parser.add_argument("--organization", default="", help="Remove only this organization's PAT")


def cmd_ado(args) -> int:
    try:
        if args.ado_command == "login":
            organization = args.organization.strip()
            where = prompt_and_save(organization, args.pat_stdin)
            print(f"✓ PAT validated and saved to {where}{' for ' + organization if organization else ''}")
        elif args.ado_command == "token":
            if sys.stdout.isatty():
                raise AdoLoginError("Refusing to print a PAT to a terminal")
            pat = load(args.organization.strip())[0]
            if not pat:
                raise AdoLoginError(f"No PAT saved for {args.organization}")
            sys.stdout.write(pat)
        elif args.ado_command == "status":
            env = next((name for name in ENV_NAMES if os.environ.get(name)), "")
            saved = [(org, load(org)[1]) for org in organizations()]
            lines = ([f"Azure DevOps PAT: {env} (all organizations)"] if env else []) + [f"Azure DevOps PAT: {source} · {org}" for org, source in saved if source]
            print("\n".join(lines) if lines else "No Azure DevOps PAT configured. Run `threatlint ado login --organization <org>`.")
        else:
            organization = args.organization.strip()
            print(("✓ Saved PAT removed" + (f" for {organization}" if organization else "")) if logout(organization) else "No saved PAT")
        return 0
    except (AdoLoginError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
