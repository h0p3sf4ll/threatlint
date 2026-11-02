"""Local GitHub App settings and private configuration-file persistence."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from threatlint.github_app_payloads import GitHubAppError, _validate_ids, validate_api_url

APP_ID_ENV = "THREATLINT_GITHUB_APP_ID"
INSTALLATION_ID_ENV = "THREATLINT_GITHUB_APP_INSTALLATION_ID"
PRIVATE_KEY_FILE_ENV = "THREATLINT_GITHUB_APP_PRIVATE_KEY_FILE"
API_URL_ENV = "THREATLINT_GITHUB_API_URL"
PRIVATE_KEY_PARAMETER_ENV = "THREATLINT_GITHUB_APP_PRIVATE_KEY_PARAMETER"
DEFAULT_API_URL = "https://api.github.com"
CONFIG_NAME = "github-app.json"


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


def write_config(path: Path, app_id: str, installation_id: str, private_key_file: str, api_url: str) -> Path:
    """Write owner-only settings atomically; persist a key path, never a PEM."""
    _validate_ids(app_id, installation_id)
    api_url = validate_api_url(api_url or DEFAULT_API_URL)
    key_file = os.path.abspath(os.path.expanduser(private_key_file))
    if not os.path.isfile(key_file):
        raise GitHubAppError("The private key file does not exist")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump({"appId": app_id, "installationId": installation_id, "privateKeyFile": key_file, "apiUrl": api_url}, handle, indent=2)
        handle.write("\n")
    os.replace(temporary, path)
    if os.name != "nt":
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return path
