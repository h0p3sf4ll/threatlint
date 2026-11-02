"""Pure Azure DevOps request and credential-store payload transformations."""

from __future__ import annotations

import base64
import re
import urllib.parse
import urllib.request

_ORG = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,49}")
_PAT = re.compile(r"[A-Za-z0-9._~+/=-]{20,200}")


class AdoLoginError(RuntimeError):
    """A user-actionable failure; messages never contain the PAT."""


def validation_request(organization: str, pat: str) -> urllib.request.Request:
    """Validate local inputs before constructing a request to the fixed ADO host."""
    if not _ORG.fullmatch(organization):
        raise AdoLoginError("Enter the Azure DevOps organization name (e.g. contoso), not a URL")
    if not _PAT.fullmatch(pat):
        raise AdoLoginError("That does not look like an Azure DevOps PAT")
    return urllib.request.Request(
        f"https://dev.azure.com/{urllib.parse.quote(organization)}/_apis/projects?$top=1&api-version=7.1",
        headers={"Authorization": "Basic " + base64.b64encode(f":{pat}".encode()).decode(), "Accept": "application/json"},
    )


def store_records(data: object) -> dict[str, dict]:
    """Normalize current and legacy store payloads without reading credentials."""
    if not isinstance(data, dict):
        return {}
    if isinstance(data.get("organizations"), dict):
        return {key: value for key, value in data["organizations"].items() if isinstance(value, dict)}
    if data.get("storage"):
        return {str(data.get("organization") or "").lower(): {**data, "keyring_user": "pat"}}
    return {}


def store_payload(records: dict[str, dict]) -> dict:
    """Keep legacy single-PAT fields alongside the organization-keyed records."""
    legacy = next(
        (record for record in records.values() if record.get("keyring_user") in ("pat", None)),
        next(iter(records.values()), {}),
    )
    top = {key: legacy[key] for key in ("organization", "storage", "pat") if key in legacy}
    return {**top, "organizations": records}
