"""AWS shared-config parsing and SSO profile persistence (no authentication)."""

from __future__ import annotations

import configparser
from pathlib import Path


def write_profile(path: Path, profile: str, start_url: str, sso_region: str, account_id: str,
                  role_name: str, session: str, region: str) -> bool:
    """Update only the requested SSO session/profile, preserving other sections."""
    config = configparser.RawConfigParser()
    config.read(path, encoding="utf-8")
    wanted = {
        f"sso-session {session}": {"sso_start_url": start_url, "sso_region": sso_region, "sso_registration_scopes": "sso:account:access"},
        f"profile {profile}": {"sso_session": session, "sso_account_id": account_id, "sso_role_name": role_name, "region": region, "output": "json"},
    }
    changed = False
    for section, values in wanted.items():
        if not config.has_section(section):
            config.add_section(section)
        for key, value in values.items():
            if config.get(section, key, fallback=None) != value:
                config.set(section, key, value)
                changed = True
    if changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            config.write(handle)
    return changed


def read_section(path: Path, section: str) -> dict[str, str] | None:
    config = configparser.RawConfigParser()
    config.read(path, encoding="utf-8")
    return dict(config.items(section)) if config.has_section(section) else None
