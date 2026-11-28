"""Minimal SemVer 2.0 parsing and ordering, enough for npm release and canary versions."""
from __future__ import annotations

import re
from functools import total_ordering

_VERSION = re.compile(
    r"^v?(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


@total_ordering
class Version:
    __slots__ = ("major", "minor", "patch", "pre", "text")

    def __init__(self, major: int, minor: int, patch: int, pre: tuple, text: str):
        self.major, self.minor, self.patch, self.pre, self.text = major, minor, patch, pre, text

    @property
    def core(self) -> tuple[int, int, int]:
        return self.major, self.minor, self.patch

    def _key(self):
        # A release sorts after every prerelease of the same core version.
        pre = tuple((0, part, "") if isinstance(part, int) else (1, 0, part) for part in self.pre)
        return self.core, (1,) if not self.pre else (0, pre)

    def __eq__(self, other):
        return isinstance(other, Version) and self._key() == other._key()

    def __lt__(self, other):
        return self._key() < other._key()

    def __hash__(self):
        return hash(self._key())

    def __repr__(self):
        return f"Version({self.text!r})"

    def __str__(self):
        return self.text


def parse(text: str) -> Version | None:
    """A Version, or None for anything that is not an exact SemVer (ranges, tags, URLs)."""
    match = _VERSION.match((text or "").strip())
    if not match:
        return None
    pre = tuple(int(part) if part.isdigit() else part for part in (match["pre"] or "").split(".") if part)
    return Version(int(match["major"]), int(match["minor"]), int(match["patch"]), pre, text.strip().lstrip("v"))


_RANGE_FLOOR = re.compile(r"(?:^|[\s|])(?:\^|~|>=|=)?\s*v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)")


def range_floor(spec: str) -> Version | None:
    """The lowest exact version a simple npm range names (``^19.1.0`` -> 19.1.0).

    Only used for PLAUSIBLE findings when no lockfile pins a version. Returns None
    for tags, URLs, workspace/file protocols, and ``*``.
    """
    spec = (spec or "").strip()
    if not spec or any(spec.startswith(p) for p in ("workspace:", "file:", "link:", "git", "http", "github:", "npm:")):
        if spec.startswith("npm:") and "@" in spec[4:]:
            return range_floor(spec.rsplit("@", 1)[1])
        return None
    found = [parse(match) for match in _RANGE_FLOOR.findall(spec)]
    found = [v for v in found if v]
    return min(found) if found else None
