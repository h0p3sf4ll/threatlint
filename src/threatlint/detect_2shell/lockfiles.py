"""Read resolved package versions from npm, Yarn, pnpm and Bun lockfiles, and declared ranges from package.json.

Parsers are deliberately tolerant line scanners: they never execute anything, never
install, and only return packages in the ``watched`` set, each with a 1-based line.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from posixpath import basename, dirname

LOCKFILE_NAMES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock")
MANIFEST_NAME = "package.json"
DEPENDENCY_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
MAX_FILE_BYTES = 40_000_000


@dataclass(frozen=True)
class Resolved:
    package: str
    version: str
    file: str
    line: int


@dataclass(frozen=True)
class Declared:
    package: str
    spec: str
    file: str
    line: int
    field: str


def is_lockfile(path: str) -> bool:
    return basename(path) in LOCKFILE_NAMES


def is_manifest(path: str) -> bool:
    return basename(path) == MANIFEST_NAME


def excluded(path: str) -> bool:
    parts = path.split("/")
    return any(part in ("node_modules", ".git", "bower_components", ".next", ".yarn") for part in parts[:-1])


def _line_of(text: str, needle: str, start: int = 0) -> tuple[int, int]:
    index = text.find(needle, start)
    if index < 0:
        return 1, start
    return text.count("\n", 0, index) + 1, index + len(needle)


def _name_from_spec(spec: str) -> str:
    spec = spec.strip().strip('"').strip("'")
    at = spec.find("@", 1)
    return spec[:at] if at > 0 else spec


def parse_npm_lock(text: str, file: str, watched: frozenset[str]) -> list[Resolved]:
    data = json.loads(text)
    found: list[Resolved] = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2 / 3
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict) or "node_modules/" not in key:
                continue
            # An aliased install ("my-next": "npm:next@15.1.0") records the real name in "name".
            name = str(meta.get("name") or key.rsplit("node_modules/", 1)[1])
            version = str(meta.get("version") or "")
            if name in watched and version and not meta.get("link"):
                found.append(Resolved(name, version, file, _line_of(text, json.dumps(key))[0]))
        return found

    def walk(deps, cursor):  # lockfileVersion 1
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict):
                continue
            line, cursor = _line_of(text, json.dumps(name) + ":", cursor)
            if name in watched and meta.get("version"):
                found.append(Resolved(name, str(meta["version"]), file, line))
            cursor = walk(meta.get("dependencies"), cursor)
        return cursor

    walk(data.get("dependencies"), 0)
    return found


_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')


def parse_yarn_lock(text: str, file: str, watched: frozenset[str]) -> list[Resolved]:
    found: list[Resolved] = []
    names: list[str] = []
    header_line = 0
    for number, line in enumerate(text.splitlines(), 1):
        if line and not line[0].isspace() and line.rstrip().endswith(":") and not line.startswith("#"):
            names = [_name_from_spec(spec) for spec in line.rstrip()[:-1].split(",")]
            names = [name for name in dict.fromkeys(names) if name in watched]
            header_line = number
            continue
        if names:
            match = _YARN_VERSION.match(line)
            if match:
                found.extend(Resolved(name, match.group(1), file, header_line) for name in names)
                names = []
    return found


# pnpm v5 "/next/15.1.0:", v6-8 "/next@15.1.0(react@19.0.0):", v9 "next@15.1.0:" (quoted when scoped).
_PNPM_KEY = re.compile(r"""^ {2}['"]?/?((?:@[^/@\s'"]+/)?[^/@\s'"(]+)[@/](\d+\.\d+\.\d+[^:('"\s_]*)""")


def parse_pnpm_lock(text: str, file: str, watched: frozenset[str]) -> list[Resolved]:
    found: dict[tuple[str, str], Resolved] = {}
    section = ""
    for number, line in enumerate(text.splitlines(), 1):
        if line and not line[0].isspace():
            section = line.split(":", 1)[0].strip()
            continue
        if section not in ("packages", "snapshots"):
            continue
        match = _PNPM_KEY.match(line)
        if match and match.group(1) in watched:
            key = (match.group(1), match.group(2))
            found.setdefault(key, Resolved(key[0], key[1], file, number))
    return list(found.values())


_BUN_ENTRY = re.compile(r'^\s*"((?:@[^"/]+/)?[^"@/]+)":\s*\[\s*"((?:@[^"/]+/)?[^"@/]+)@([^"]+)"')


def parse_bun_lock(text: str, file: str, watched: frozenset[str]) -> list[Resolved]:
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        match = _BUN_ENTRY.match(line)
        if match and match.group(2) in watched:
            found.append(Resolved(match.group(2), match.group(3), file, number))
    return found


_PARSERS = {
    "package-lock.json": parse_npm_lock,
    "npm-shrinkwrap.json": parse_npm_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "bun.lock": parse_bun_lock,
}


def parse_lockfile(path: str, text: str, watched: frozenset[str]) -> list[Resolved]:
    return _PARSERS[basename(path)](text, path, watched)


def parse_manifest(path: str, text: str, watched: frozenset[str]) -> tuple[list[Declared], dict]:
    """Declared watched dependencies plus the parsed manifest (for workspace detection)."""
    data = json.loads(text)
    if not isinstance(data, dict):
        return [], {}
    found = []
    for field in DEPENDENCY_FIELDS:
        section = data.get(field)
        if not isinstance(section, dict):
            continue
        _, cursor = _line_of(text, json.dumps(field))
        for name, spec in section.items():
            if name in watched and isinstance(spec, str):
                line, _ = _line_of(text, json.dumps(name), cursor)
                found.append(Declared(name, spec, path, line, field))
    return found, data


def project_dir(path: str) -> str:
    return dirname(path)
