"""Synthetic environment seeding and sanitization, independent of providers."""

from __future__ import annotations

import os
import re
import secrets

_SENSITIVE = re.compile(r"pass(word|wd)?|secret|token|api[_-]?key|private|credential|auth|salt|signing|access[_-]?key|dsn|_key$", re.I)


def synthetic(name: str, cache: dict) -> str:
    """A random, clearly synthetic value; the same name maps to the same value within a run."""
    return cache.setdefault(name, f"tl-synthetic-{secrets.token_hex(8)}")


def _read(path: str, limit: int = 512 * 1024) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def example_env(checkout: str, cache: dict) -> dict[str, str]:
    """Read only example env files, replacing sensitive-looking and empty values."""
    values: dict[str, str] = {}
    for name in (".env.example", ".env.sample", ".env.template", ".env.dist", "example.env"):
        for line in _read(os.path.join(checkout, name)).splitlines():
            match = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
            if match and match.group(1) not in values:
                value = match.group(2).strip().strip("\"'")
                values[match.group(1)] = synthetic(match.group(1), cache) if _SENSITIVE.search(match.group(1)) or not value else value
    return values


def scrub_env(env: dict, cache: dict) -> dict[str, str]:
    """Resolve repository interpolations without reading the host environment."""
    result = {}
    for key, value in (env or {}).items():
        value = "" if value is None else str(value)
        value = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}", lambda m: m.group(2) if m.group(2) is not None else synthetic(m.group(1), cache), value)
        if _SENSITIVE.search(key) and not re.search(r"(?i)file$|path$|url$|host$|port$|user(name)?$|enabled$", key):
            # Preserve shared credentials across services without preserving their original values.
            value = synthetic("value:" + value, cache)
        result[str(key)] = value
    return result
