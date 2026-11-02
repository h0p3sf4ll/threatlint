"""Guard rule and finding value objects."""

from __future__ import annotations

import re
from dataclasses import dataclass


SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    languages: tuple[str, ...]
    pattern: str
    message: str
    fix: str
    cwe: str
    flags: int = re.IGNORECASE

    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.pattern, self.flags)


@dataclass
class Finding:
    rule_id: str
    severity: str
    path: str
    line: int
    column: int
    message: str
    fix: str
    cwe: str
    snippet: str


def _rank(severity: str) -> int:
    return SEVERITIES.index(severity)
