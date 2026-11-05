"""Trusted GitHub origins and host-scoped credentials for AVIT repository actions.

Only local settings select the API host. AVIT content and repository responses
cannot redirect credentials to another host. App authentication fails closed.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import urllib.parse

from threatlint import github_app, github_app_config, tls
from threatlint.github_app_payloads import GitHubAppError

_TOKEN_ENV = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z")
_GHE_API = re.compile(r"api\.([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.ghe\.com\Z")


def _endpoints(url: str) -> dict[str, str]:
    invalid = "Configure a valid GitHub HTTPS API URL: api.github.com, api.SUBDOMAIN.ghe.com, or an Enterprise Server host ending in /api/v3"
    if not isinstance(url, str) or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url):
        raise GitHubAppError(invalid)
    try:
        parts = urllib.parse.urlsplit(url)
        host, port = parts.hostname or "", parts.port
    except ValueError:
        raise GitHubAppError(invalid) from None
    if (parts.scheme != "https" or not host or len(host) > 253 or not _HOST.fullmatch(host)
            or parts.username is not None or parts.password is not None or parts.query or parts.fragment
            or "?" in url or "#" in url or port not in (None, 443)
            or parts.netloc.lower() not in (host, host + ":443")):
        raise GitHubAppError(invalid)
    path = parts.path
    if host == "api.github.com":
        if path not in ("", "/"):
            raise GitHubAppError(invalid)
        return {"api_url": "https://api.github.com", "web_url": "https://github.com", "hostname": "github.com"}
    residency = _GHE_API.fullmatch(host)
    if residency:
        if path not in ("", "/"):
            raise GitHubAppError(invalid)
        web_host = f"{residency[1]}.ghe.com"
        return {"api_url": f"https://{host}", "web_url": f"https://{web_host}", "hostname": web_host}
    if host == "github.com" or host.endswith(".ghe.com") or path not in ("/api/v3", "/api/v3/"):
        raise GitHubAppError(invalid)
    return {"api_url": f"https://{host}/api/v3", "web_url": f"https://{host}", "hostname": host}


def endpoints() -> dict[str, str]:
    """Canonical API URL, web origin, and CLI hostname from trusted configuration."""
    saved = github_app_config.saved_config()
    api = os.environ.get(github_app_config.API_URL_ENV, "").strip() or saved.get("apiUrl") or github_app_config.DEFAULT_API_URL
    return _endpoints(api)


def _gh_cli_token(hostname: str) -> str:
    executable = shutil.which("gh")
    if not executable:
        return ""
    # gh applies its own token-env precedence, including GH_TOKEN for *.ghe.com.
    # Our explicit selection above has already handled the configured host.
    env = tls.tool_env({key: value for key, value in os.environ.items() if key not in _TOKEN_ENV})
    try:
        result = subprocess.run([executable, "auth", "token", "--hostname", hostname],
                                capture_output=True, text=True, timeout=30, check=False, env=env)
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _checked_token(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or any(not 33 <= ord(char) <= 126 for char in value):
        raise GitHubAppError("The configured GitHub credential is empty or invalid")
    return value


def token() -> tuple[str, str]:
    """App token, then host-specific environment token, then the host's gh login."""
    origins = endpoints()
    config = github_app.load_config()
    if config:
        if _endpoints(config.get("apiUrl") or github_app_config.DEFAULT_API_URL) != origins:
            raise GitHubAppError("The GitHub App API host does not match the configured repository host")
        try:
            value = github_app.installation_token({**config, "apiUrl": origins["api_url"]})
        except GitHubAppError:
            raise GitHubAppError("GitHub App authentication failed; check the configured installation, key, and access") from None
        return _checked_token(value), "GitHub App"
    saved = github_app_config.saved_config()
    if (any(os.environ.get(name) for name in (github_app_config.APP_ID_ENV, github_app_config.INSTALLATION_ID_ENV,
                                            github_app_config.PRIVATE_KEY_FILE_ENV))
            or any(saved.get(name) for name in ("appId", "installationId", "privateKeyFile"))
            or github_app_config._key_parameter()):
        raise GitHubAppError("The configured GitHub App is incomplete; provide its ID, installation ID, and private key")
    names = _TOKEN_ENV[:2] if origins["hostname"] == "github.com" else _TOKEN_ENV[2:]
    for name in names:
        if os.environ.get(name):
            return _checked_token(os.environ[name]), name
    value = _gh_cli_token(origins["hostname"])
    return (_checked_token(value), "gh auth token") if value else ("", "")
