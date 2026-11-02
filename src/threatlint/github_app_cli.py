"""GitHub App setup prompts, argument parsing and secret-free CLI messages."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from threatlint.github_app_config import DEFAULT_API_URL
from threatlint.github_app_payloads import GitHubAppError, _validate_ids, validate_api_url

PERMISSIONS_HELP = ("Repository permissions: Metadata (read), Contents (read); add Pull requests (read & write) and "
                    "Issues (read & write) only if Threatlint should comment on PRs or open issues.")


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
    from threatlint.github_app import installation_repositories, save_config, saved_config  # noqa: PLC0415

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
    count, owner = installation_repositories(config, opener=opener)
    return save_config(app_id, installation_id, private_key_file, api_url), count, owner


def cmd_github(args) -> int:
    from threatlint.github_app import config_path, load_config, login, logout, source  # noqa: PLC0415

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
