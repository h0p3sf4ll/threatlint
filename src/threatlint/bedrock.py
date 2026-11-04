"""Bedrock API-key configuration, isolated from Anthropic and AWS access keys."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

KEY_ENV_NAMES = ("AWS_BEARER_TOKEN_BEDROCK", "BEDROCK_API_KEY")
REGION_ENV_NAMES = ("AWS_REGION", "AWS_DEFAULT_REGION")
DEFAULT_REGION = "us-east-1"
DAYBREAK_BLUE_MODEL = "openai.gpt-daybreak-blue-5.6-sol"
DAYBREAK_BLUE_REGION = "us-east-2"


def _claude_environment(settings_path: Path | None = None) -> dict[str, str]:
    """Read only recognized Bedrock settings from the user's global Claude settings.

    Project settings, hooks, endpoint overrides, and Claude login files are never read.
    An absent or malformed optional settings file simply supplies no defaults.
    """
    path = settings_path if settings_path is not None else Path.home() / ".claude" / "settings.json"
    try:
        if path.stat().st_size > 1024 * 1024:
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    values = payload.get("env", {}) if isinstance(payload, dict) else {}
    if not isinstance(values, dict):
        return {}
    return {name: values[name] for name in (*KEY_ENV_NAMES, *REGION_ENV_NAMES)
            if isinstance(values.get(name), str) and values[name].strip()}


def endpoint(region: str) -> str:
    """A fixed AWS Messages endpoint; a region can never become a URL or path."""
    if not isinstance(region, str) or len(region) > 40 or not re.fullmatch(r"[a-z]{2,5}(?:-[a-z0-9]+)+-\d{1,2}", region):
        raise ValueError("Invalid Bedrock region. Use an AWS region such as us-east-1.")
    suffix = "amazonaws.com.cn" if region.startswith("cn-") else "amazonaws.com"
    return f"https://bedrock-runtime.{region}.{suffix}/anthropic/v1/messages"


def daybreak_blue_endpoint(region: str) -> str:
    """Mantle OpenAI base URL for the currently published Daybreak Blue region."""
    endpoint(region)  # Reuse the strict region validation before constructing a host.
    if region != DAYBREAK_BLUE_REGION:
        raise ValueError(f"Daybreak Blue on Bedrock is currently available in {DAYBREAK_BLUE_REGION} only.")
    return f"https://bedrock-mantle.{region}.api.aws/openai/v1"


@dataclass(frozen=True)
class Configuration:
    region: str
    api_key: str = field(repr=False)

    @property
    def messages_url(self) -> str:
        return endpoint(self.region)


def configuration(api_key: str = "", region: str = "", *, env: Mapping[str, str] | None = None,
                  settings_path: Path | None = None) -> Configuration:
    """Explicit option > process environment > global Claude settings > region default."""
    environment = env if env is not None else os.environ
    settings = _claude_environment(settings_path)

    def first(source: Mapping[str, str], names: tuple[str, ...]) -> str:
        return next((source[name].strip() for name in names
                     if isinstance(source.get(name), str) and source[name].strip()), "")

    selected_key = api_key.strip() or first(environment, KEY_ENV_NAMES) or first(settings, KEY_ENV_NAMES)
    selected_region = region.strip() or first(environment, REGION_ENV_NAMES) or first(settings, REGION_ENV_NAMES) or DEFAULT_REGION
    endpoint(selected_region)  # Validate before a credential can be used in any request.
    if not selected_key:
        raise ValueError("Bedrock API key required. Pass --api-key, set AWS_BEARER_TOKEN_BEDROCK or BEDROCK_API_KEY, "
                         "or set one of those names in ~/.claude/settings.json env.")
    if any(character in selected_key for character in "\r\n\0"):
        raise ValueError("Invalid Bedrock API key.")
    return Configuration(selected_region, selected_key)
