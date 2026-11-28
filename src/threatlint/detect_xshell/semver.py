"""Minimal version parsing and ordering for npm (SemVer, canaries), Maven/Gradle releases and runtime versions."""
from __future__ import annotations

import re
from functools import total_ordering

_VERSION = re.compile(
    r"^v?(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


@total_ordering
class Version:
    __slots__ = ("major", "minor", "patch", "fourth", "pre", "text")

    def __init__(self, major: int, minor: int, patch: int, pre: tuple, text: str, fourth: int = 0):
        self.major, self.minor, self.patch, self.fourth, self.pre, self.text = major, minor, patch, fourth, pre, text

    @property
    def core(self) -> tuple[int, int, int, int]:
        """Numeric parts; the fourth is 0 except for 4-part releases (JDK 17.0.21.1, brotlicffi 1.2.1.0)."""
        return self.major, self.minor, self.patch, self.fourth

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


# Maven / Gradle / runtime versions: 1-4 numeric parts, an optional release marker (5.2.19.RELEASE, 2.4.Final)
# and an optional qualifier (2.0-beta9, 3.0.0-rc1). Qualifiers order before the release, like SemVer.
_MAVEN = re.compile(
    r"^v?(?P<major>\d+)(?:\.(?P<minor>\d+))?(?:\.(?P<patch>\d+))?(?:\.(?P<fourth>\d+))?"
    r"(?:[.-](?:RELEASE|Final|GA|FINAL))?(?:-(?P<pre>[0-9A-Za-z.-]+))?$"
)


def parse(text: str) -> Version | None:
    """A Version, or None for anything that is not an exact version (ranges, tags, URLs, ${properties})."""
    raw = (text or "").strip()
    match = _VERSION.match(raw) or _MAVEN.match(raw)
    if not match:
        return None
    pre = tuple(int(part) if part.isdigit() else part for part in (match["pre"] or "").split(".") if part)
    fourth = int(match.groupdict().get("fourth") or 0)
    return Version(int(match["major"]), int(match["minor"] or 0), int(match["patch"] or 0), pre, raw.lstrip("v"), fourth)


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
