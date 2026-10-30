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

import base64
import datetime
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

APP_ID_ENV = "THREATLINT_GITHUB_APP_ID"
INSTALLATION_ID_ENV = "THREATLINT_GITHUB_APP_INSTALLATION_ID"
PRIVATE_KEY_FILE_ENV = "THREATLINT_GITHUB_APP_PRIVATE_KEY_FILE"
API_URL_ENV = "THREATLINT_GITHUB_API_URL"
PRIVATE_KEY_PARAMETER_ENV = "THREATLINT_GITHUB_APP_PRIVATE_KEY_PARAMETER"
DEFAULT_API_URL = "https://api.github.com"
CONFIG_NAME = "github-app.json"
TOKEN_ENV_NAMES = ("GH_TOKEN", "GITHUB_TOKEN")
REFRESH_MARGIN_S = 300
JWT_BACKDATE_S = 60
JWT_LIFETIME_S = 540  # GitHub rejects an exp more than 10 minutes ahead
_HTTP_TIMEOUT_S = 30
_APP_ID = re.compile(r"[A-Za-z0-9.]{1,64}")  # numeric App ID or the App's client ID (Iv1.xxxx)
_INSTALLATION_ID = re.compile(r"[0-9]{1,20}")
PERMISSIONS_HELP = ("Repository permissions: Metadata (read), Contents (read); add Pull requests (read & write) and "
                    "Issues (read & write) only if Threatlint should comment on PRs or open issues.")

_cache: dict[tuple[str, str, str], tuple[str, float]] = {}
_lock = threading.Lock()


class GitHubAppError(RuntimeError):
    """A user-actionable failure; messages never contain IDs, the key path, the key, or a token."""


def home() -> Path:
    return Path(os.environ.get("THREATLINT_HOME") or Path.home() / ".threatlint")


def config_path() -> Path:
    return home() / CONFIG_NAME


def saved_config() -> dict[str, str]:
    try:
        value = json.loads(config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(value, dict):
        return {}
    return {key: str(value.get(key) or "").strip() for key in ("appId", "installationId", "privateKeyFile", "apiUrl")}


def _key_parameter() -> str:
    if os.environ.get(PRIVATE_KEY_PARAMETER_ENV):
        return os.environ[PRIVATE_KEY_PARAMETER_ENV].strip()
    try:
        from threatlint import org_config  # noqa: PLC0415
        saved = json.loads(org_config.path().read_text(encoding="utf-8"))
        return str(saved.get("githubAppPrivateKeyParameter") or "").strip() if isinstance(saved, dict) else ""
    except (OSError, ValueError):
        return ""


def load_config() -> dict[str, str] | None:
    """The App settings (environment over saved file), with "source"; None when no App is configured."""
    saved = saved_config()
    env = {"appId": os.environ.get(APP_ID_ENV, "").strip(), "installationId": os.environ.get(INSTALLATION_ID_ENV, "").strip(),
           "privateKeyFile": os.environ.get(PRIVATE_KEY_FILE_ENV, "").strip(), "apiUrl": os.environ.get(API_URL_ENV, "").strip()}
    config = {key: env[key] or saved.get(key, "") for key in env}
    config["apiUrl"] = config["apiUrl"] or DEFAULT_API_URL
    config["privateKeyParameter"] = "" if config["privateKeyFile"] else _key_parameter()
    if not (config["appId"] and config["installationId"] and (config["privateKeyFile"] or config["privateKeyParameter"])):
        return None
    from_env = any(env[key] for key in ("appId", "installationId", "privateKeyFile"))
    config["source"] = "environment" if from_env and not any(saved.values()) else ("environment + " + str(config_path()) if from_env else str(config_path()))
    return config


def configured() -> bool:
    return load_config() is not None


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
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps({"iat": issued - JWT_BACKDATE_S, "exp": issued + JWT_LIFETIME_S, "iss": config["appId"]},
                                 separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    return f"{header}.{payload}.{_b64url(_sign(signing_input, config))}"


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
    _validate_ids(app_id, installation_id)
    api_url = validate_api_url(api_url or DEFAULT_API_URL)
    key_file = os.path.abspath(os.path.expanduser(private_key_file))
    if not os.path.isfile(key_file):
        raise GitHubAppError("The private key file does not exist")
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump({"appId": app_id, "installationId": installation_id, "privateKeyFile": key_file, "apiUrl": api_url}, handle, indent=2)
        handle.write("\n")
    os.replace(temporary, path)
    if os.name != "nt":
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    clear_cache()
    return path


def logout() -> bool:
    clear_cache()
    try:
        config_path().unlink()
        return True
    except FileNotFoundError:
        return False


# ── CLI ───────────────────────────────────────────────────────────────────────

def add_github_parser(sub) -> None:
    p = sub.add_parser("github", help="Set up GitHub App authentication for clones, PR comments, issues, and API calls")
    actions = p.add_subparsers(dest="github_command", required=True)
    login = actions.add_parser("login", help="Validate and save the GitHub App settings (~/.threatlint/github-app.json)")
    login.add_argument("--app-id", default="", help="GitHub App ID (or client ID)")
    login.add_argument("--installation-id", default="", help="Installation ID of the App on your organization")
    login.add_argument("--private-key-file", default="", help="Path to the App's private key (.pem); only the path is saved")
    login.add_argument("--api-url", default="", help=f"GitHub API URL (default {DEFAULT_API_URL})")
    actions.add_parser("status", help="Show which GitHub credential is in use (never prints a value)")
    actions.add_parser("logout", help="Remove the saved GitHub App settings (the .pem file is left in place)")


def _ask(label: str, value: str, default: str = "") -> str:
    if value:
        return value.strip()
    if not sys.stdin.isatty():
        if default:
            return default
        raise GitHubAppError(f"Pass --{label.lower().replace(' ', '-')} when not running interactively")
    answer = input(f"{label}{' [' + default + ']' if default else ''}: ").strip()
    return answer or default


def login(app_id: str = "", installation_id: str = "", private_key_file: str = "", api_url: str = "", *, opener=None) -> tuple[Path, int, str]:
    saved = saved_config()
    if not (app_id and installation_id and private_key_file) and sys.stdin.isatty():
        print(PERMISSIONS_HELP)
    app_id = _ask("App ID", app_id)
    installation_id = _ask("Installation ID", installation_id)
    private_key_file = _ask("Private key file", private_key_file)
    api_url = validate_api_url(_ask("API URL", api_url, saved.get("apiUrl") or DEFAULT_API_URL))
    _validate_ids(app_id, installation_id)
    config = {"appId": app_id, "installationId": installation_id, "privateKeyFile": os.path.abspath(os.path.expanduser(private_key_file)),
              "apiUrl": api_url, "privateKeyParameter": ""}
    count, owner = installation_repositories(config, opener=opener)  # validates before saving
    return save_config(app_id, installation_id, private_key_file, api_url), count, owner


def cmd_github(args) -> int:
    try:
        if args.github_command == "login":
            path, count, owner = login(args.app_id, args.installation_id, args.private_key_file, args.api_url)
            print(f"✓ GitHub App validated: {count} repositor{'y' if count == 1 else 'ies'} visible{' (owner ' + owner + ')' if owner else ''}")
            print(f"✓ Saved to {path} (App ID, installation ID, and key path set; the key itself is not copied)")
        elif args.github_command == "status":
            config = load_config()
            if config:
                key = "private key file set" if config.get("privateKeyFile") else "private key in Parameter Store"
                print(f"GitHub credential: GitHub App (App ID set, installation ID set, {key}; from {config['source']}; API {config['apiUrl']})")
            else:
                current = source()
                print(f"GitHub credential: {current} (no GitHub App configured)" if current else
                      "No GitHub credential: run `threatlint github login`, set GH_TOKEN, or run `gh auth login`.")
        else:
            print(f"✓ Removed {config_path()}" if logout() else "No saved GitHub App settings")
        return 0
    except (GitHubAppError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
