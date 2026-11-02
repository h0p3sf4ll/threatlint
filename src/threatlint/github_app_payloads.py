"""Pure GitHub App input validation and unsigned JWT construction."""

from __future__ import annotations

import base64
import json
import re
import urllib.parse

_APP_ID = re.compile(r"[A-Za-z0-9.]{1,64}")
_INSTALLATION_ID = re.compile(r"[0-9]{1,20}")


class GitHubAppError(RuntimeError):
    """A user-actionable failure; messages never contain IDs, paths, keys, or tokens."""


def validate_api_url(url: str) -> str:
    parts = urllib.parse.urlsplit((url or "").strip())
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise GitHubAppError("The GitHub API URL must be an https:// URL without credentials, query, or fragment")
    return urllib.parse.urlunsplit(("https", parts.netloc, parts.path.rstrip("/"), "", ""))


def _validate_ids(app_id: str, installation_id: str) -> None:
    if not _APP_ID.fullmatch(app_id or ""):
        raise GitHubAppError("The GitHub App ID is not valid (digits, or the App's client ID)")
    if not _INSTALLATION_ID.fullmatch(installation_id or ""):
        raise GitHubAppError("The GitHub App installation ID must be digits")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwt_signing_input(app_id: str, issued: int, backdate: int, lifetime: int) -> bytes:
    """Encode the deterministic JWT portion; signing remains in the auth module."""
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps(
        {"iat": issued - backdate, "exp": issued + lifetime, "iss": app_id}, separators=(",", ":"),
    ).encode())
    return f"{header}.{payload}".encode("ascii")
