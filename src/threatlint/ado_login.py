"""Azure DevOps personal access token setup so `threatlint avit checkout` can clone ADO repositories.

  threatlint ado login [--organization ORG] [--pat-stdin]   validate and save a PAT (Code: Read)
  threatlint ado status                                     show where the PAT comes from
  threatlint ado logout                                     remove the saved PAT

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


def save(organization: str, pat: str) -> str:
    """Store the PAT; returns where it was stored."""
    keyring = _keyring()
    if keyring:
        keyring.set_password(KEYRING_SERVICE, "pat", pat)
        record = {"organization": organization, "storage": "keyring"}
    else:
        record = {"organization": organization, "storage": "file", "pat": pat}
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Create with owner-only permissions; on Windows the user profile ACL already limits access.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(record, handle)
    if os.name != "nt":
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return "the OS credential store" if keyring else str(path)


def load() -> tuple[str, str]:
    """(PAT, source label); ('', '') when none is configured."""
    for name in ENV_NAMES:
        if os.environ.get(name):
            return os.environ[name], name
    try:
        record = json.loads(store_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "", ""
    if record.get("storage") == "keyring":
        keyring = _keyring()
        pat = keyring.get_password(KEYRING_SERVICE, "pat") if keyring else None
        return (pat, "OS credential store") if pat else ("", "")
    return (record.get("pat", ""), str(store_path())) if record.get("pat") else ("", "")


def logout() -> bool:
    keyring = _keyring()
    if keyring:
        try:
            keyring.delete_password(KEYRING_SERVICE, "pat")
        except Exception:  # noqa: BLE001 - nothing stored
            pass
    try:
        store_path().unlink()
        return True
    except FileNotFoundError:
        return False


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
    actions.add_parser("status", help="Show where the PAT comes from (never prints it)")
    actions.add_parser("logout", help="Remove the saved PAT")


def cmd_ado(args) -> int:
    try:
        if args.ado_command == "login":
            where = prompt_and_save(args.organization.strip(), args.pat_stdin)
            print(f"✓ PAT validated and saved to {where}")
        elif args.ado_command == "status":
            _pat, source = load()
            print(f"Azure DevOps PAT: {source}" if source else "No Azure DevOps PAT configured. Run `threatlint ado login`.")
        else:
            print("✓ Saved PAT removed" if logout() else "No saved PAT")
        return 0
    except (AdoLoginError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
