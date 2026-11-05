"""Read Semgrep's native login without copying it into Threatlint's settings."""

from __future__ import annotations

import os
import re
from pathlib import Path


def settings_path() -> Path:
    explicit = os.environ.get("SEMGREP_SETTINGS_FILE")
    if explicit:
        return Path(explicit).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    candidate = Path(xdg) / ".semgrep" / "settings.yml" if xdg else None
    return candidate if candidate and candidate.exists() else Path.home() / ".semgrep" / "settings.yml"


def native_token() -> tuple[str, str]:
    """Read the top-level scalar emitted by `semgrep login`; reject complex YAML.

    Semgrep tokens use a restricted alphabet. This intentionally does not evaluate
    YAML aliases/tags, require an optional YAML dependency, or expose file contents.
    """
    path = settings_path()
    try:
        if path.stat().st_size > 64 * 1024:
            return "", ""
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError):
        return "", ""
    matches = re.findall(r"(?m)^api_token\s*:\s*([^\r\n]*)", text)
    if len(matches) != 1:
        return "", ""
    match = re.fullmatch(r"\s*(?:'([A-Za-z0-9._~+/=-]{20,200})'|\"([A-Za-z0-9._~+/=-]{20,200})\"|([A-Za-z0-9._~+/=-]{20,200}))(?:\s+#.*)?\s*", matches[0])
    if not match:
        return "", ""
    return next(value for value in match.groups() if value), str(path)
