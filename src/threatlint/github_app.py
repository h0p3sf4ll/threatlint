"""GitHub App authentication: short-lived installation tokens for every GitHub call Threatlint makes.

  threatlint github login [--app-id ID --installation-id ID --private-key-file PATH --api-url URL]
  threatlint github status          which GitHub credential is in use (never prints a value)
  threatlint github logout          remove ~/.threatlint/github-app.json (the .pem is left alone)

Configuration comes only from local settings, never from the source tree:
  1. THREATLINT_GITHUB_APP_ID, THREATLINT_GITHUB_APP_INSTALLATION_ID, THREATLINT_GITHUB_APP_PRIVATE_KEY_FILE,
     THREATLINT_GITHUB_API_URL (each overrides the saved value),
  2. ~/.threatlint/github-app.json (THREATLINT_HOME relocates it), mode 0600:
       {"appId": "...", "installationId": "...", "privateKeyFile": "/path/to/app.pem", "apiUrl": "https://api.github.com"}
  3. With no key file, the PEM may live in AWS Parameter Store: THREATLINT_GITHUB_APP_PRIVATE_KEY_PARAMETER or
     "githubAppPrivateKeyParameter" in ~/.threatlint/org.json.

The App JWT (RS256, iat backdated 60 s, exp 9 min) is signed by the system `openssl` with the key passed by path
(or over an inherited pipe for a Parameter Store key), so no Python crypto dependency is needed. The installation
token is cached in memory until five minutes before it expires and is never written to disk or logs. Messages from
this module never contain the App ID, installation ID, key path, key, JWT, or token.

Credential order for GitHub everywhere: GitHub App (when configured) -> GH_TOKEN / GITHUB_TOKEN -> `gh auth token`.
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from threatlint.github_app_payloads import (
    GitHubAppError,
    _APP_ID,
    _INSTALLATION_ID,
    _b64url,
    _validate_ids,
    jwt_signing_input,
    validate_api_url,
)
from threatlint.github_app_config import (
    API_URL_ENV, APP_ID_ENV, CONFIG_NAME, DEFAULT_API_URL, INSTALLATION_ID_ENV,
    PRIVATE_KEY_FILE_ENV, PRIVATE_KEY_PARAMETER_ENV, _key_parameter,
    config_path, home, load_config, saved_config, write_config,
)
from threatlint.github_app_cli import PERMISSIONS_HELP, _ask, add_github_parser, cmd_github, login

TOKEN_ENV_NAMES = ("GH_TOKEN", "GITHUB_TOKEN")
REFRESH_MARGIN_S = 300
JWT_BACKDATE_S = 60
JWT_LIFETIME_S = 540  # GitHub rejects an exp more than 10 minutes ahead
_HTTP_TIMEOUT_S = 30

_cache: dict[tuple[str, str, str], tuple[str, float]] = {}
_lock = threading.Lock()


def configured() -> bool:
    return load_config() is not None


def _openssl() -> str:
    for candidate in ("/usr/bin/openssl", shutil.which("openssl") or ""):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise GitHubAppError("The `openssl` command is required to sign the GitHub App JWT")


def _read_parameter(name: str) -> str:
    from threatlint.scanners.base import ScannerError, read_parameter  # noqa: PLC0415
    try:
        return read_parameter(name)
    except ScannerError as exc:
        raise GitHubAppError(f"Could not read the GitHub App private key from Parameter Store: {exc}") from exc


def _sign(signing_input: bytes, config: dict[str, str]) -> bytes:
    """RSA-SHA256 signature by the system openssl. The key is passed by path (or an inherited pipe), never on argv."""
    openssl = _openssl()
    key_file = os.path.expanduser(config.get("privateKeyFile", ""))
    read_fd = None
    try:
        if key_file:
            if not os.path.isfile(key_file) or not os.access(key_file, os.R_OK):
                raise GitHubAppError("The GitHub App private key file is set but cannot be read")
            command, pass_fds = [openssl, "dgst", "-sha256", "-sign", key_file], ()
        else:
            if os.name == "nt":
                raise GitHubAppError("A Parameter Store private key needs a POSIX system; set a private key file instead")
            pem = _read_parameter(config["privateKeyParameter"]).encode()
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, pem)  # a PEM is far below the pipe buffer, so this never blocks
            finally:
                os.close(write_fd)
            command, pass_fds = [openssl, "dgst", "-sha256", "-sign", f"/dev/fd/{read_fd}"], (read_fd,)
        try:
            result = subprocess.run(command, input=signing_input, capture_output=True, timeout=30, check=False, pass_fds=pass_fds)
        except (OSError, subprocess.SubprocessError) as exc:
            raise GitHubAppError(f"openssl could not sign the GitHub App JWT: {type(exc).__name__}") from None
    finally:
        if read_fd is not None:
            os.close(read_fd)
    if result.returncode != 0 or not result.stdout:
        raise GitHubAppError("openssl could not sign the GitHub App JWT; check that the private key is the App's PEM key")
    return result.stdout


def app_jwt(config: dict[str, str], now: float | None = None) -> str:
    """The App's RS256 JWT: iat = now - 60 s, exp = now + 9 min, iss = App ID."""
    _validate_ids(config["appId"], config["installationId"])
    issued = int(now if now is not None else time.time())
    signing_input = jwt_signing_input(config["appId"], issued, JWT_BACKDATE_S, JWT_LIFETIME_S)
    return f"{signing_input.decode('ascii')}.{_b64url(_sign(signing_input, config))}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102, ANN001
        raise GitHubAppError(f"The GitHub API answered with a redirect (HTTP {code}); redirects are refused")


def _opener():
    from threatlint.tls import ssl_context  # noqa: PLC0415
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_context()), _NoRedirect())


def _request(method: str, url: str, authorization: str, opener=None) -> dict:
    request = urllib.request.Request(url, method=method, data=b"" if method == "POST" else None, headers={
        "Authorization": authorization, "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "threatlint"})
    try:
        with (opener or _opener()).open(request, timeout=_HTTP_TIMEOUT_S) as response:
            body = response.read(2_000_000)
    except urllib.error.HTTPError as exc:
        hint = {401: "the App ID or private key was rejected", 403: "the App lacks permission", 404: "the installation was not found"}.get(exc.code, "")
        raise GitHubAppError(f"GitHub API request failed: HTTP {exc.code}{' (' + hint + ')' if hint else ''}") from None
    except urllib.error.URLError as exc:
        raise GitHubAppError(f"GitHub API is unreachable: {exc.reason}") from None
    try:
        value = json.loads(body)
    except ValueError:
        raise GitHubAppError("The GitHub API returned a response that is not JSON") from None
    if not isinstance(value, dict):
        raise GitHubAppError("Unexpected GitHub API response")
    return value


def _expiry(value: object) -> float:
    try:
        return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.time() + 3600


def installation_token(config: dict[str, str] | None = None, *, opener=None, now=time.time) -> str:
    """A cached installation access token, minted again five minutes before it expires."""
    config = config or load_config()
    if not config:
        raise GitHubAppError("No GitHub App is configured. Run `threatlint github login`.")
    api = validate_api_url(config.get("apiUrl") or DEFAULT_API_URL)
    _validate_ids(config["appId"], config["installationId"])
    key = (api, config["appId"], config["installationId"])
    with _lock:
        cached = _cache.get(key)
        if cached and cached[1] - REFRESH_MARGIN_S > now():
            return cached[0]
        data = _request("POST", f"{api}/app/installations/{config['installationId']}/access_tokens",
                        f"Bearer {app_jwt(config, now())}", opener)
        token = data.get("token")
        if not isinstance(token, str) or not token:
            raise GitHubAppError("GitHub did not return an installation token")
        _cache[key] = (token, _expiry(data.get("expires_at")))
        return token


def clear_cache() -> None:
    with _lock:
        _cache.clear()


def _gh_cli_token() -> str:
    executable = shutil.which("gh")
    if not executable:
        return ""
    try:
        from threatlint.tls import tool_env  # noqa: PLC0415
        result = subprocess.run([executable, "auth", "token"], capture_output=True, text=True, timeout=30, check=False, env=tool_env())
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def github_token(*, gh_cli=_gh_cli_token, warn=True) -> tuple[str, str]:
    """(token, source) in the order GitHub App -> GH_TOKEN / GITHUB_TOKEN -> `gh auth token`; ('', '') when none.

    A configured App that fails to mint a token falls back to the next source with a warning (no values)."""
    if configured():
        try:
            return installation_token(), "GitHub App"
        except GitHubAppError as exc:
            if warn:
                print(f"  ! GitHub App token unavailable ({exc}); falling back to GH_TOKEN / gh", file=sys.stderr)
    for name in TOKEN_ENV_NAMES:
        if os.environ.get(name):
            return os.environ[name], name
    token = gh_cli()
    return (token, "gh auth token") if token else ("", "")


def source() -> str:
    """Which credential would be used, without contacting GitHub or printing a value."""
    if configured():
        return "GitHub App"
    for name in TOKEN_ENV_NAMES:
        if os.environ.get(name):
            return name
    return "gh auth token" if shutil.which("gh") else ""


def installation_repositories(config: dict[str, str] | None = None, *, opener=None) -> tuple[int, str]:
    """(total repositories visible to the installation, owner of the first one) via GET /installation/repositories."""
    config = config or load_config()
    if not config:
        raise GitHubAppError("No GitHub App is configured")
    api = validate_api_url(config.get("apiUrl") or DEFAULT_API_URL)
    data = _request("GET", f"{api}/installation/repositories?per_page=1", f"Bearer {installation_token(config, opener=opener)}", opener)
    repos = data.get("repositories") if isinstance(data.get("repositories"), list) else []
    owner = ((repos[0] or {}).get("owner") or {}).get("login", "") if repos and isinstance(repos[0], dict) else ""
    return int(data.get("total_count") or 0), str(owner)


def save_config(app_id: str, installation_id: str, private_key_file: str, api_url: str = DEFAULT_API_URL) -> Path:
    """Write ~/.threatlint/github-app.json (0600). Only the key's path is stored, never the key."""
    path = write_config(config_path(), app_id, installation_id, private_key_file, api_url)
    clear_cache()
    return path


def logout() -> bool:
    clear_cache()
    try:
        config_path().unlink()
        return True
    except FileNotFoundError:
        return False
