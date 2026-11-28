"""Read package versions from npm/Yarn/pnpm/Bun lockfiles and package.json (2Shell), and from Maven, Gradle and vendored jars (4Shell).

Parsers are deliberately tolerant line scanners: they never execute anything, never
install, and only return packages in the ``watched`` set, each with a 1-based line.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from posixpath import basename, dirname

LOCKFILE_NAMES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "gradle.lockfile")
MANIFEST_NAME = "package.json"
JAVA_MANIFEST_NAMES = ("pom.xml", "build.gradle", "build.gradle.kts", "libs.versions.toml")
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
    pinned: bool = False  # an exact version the build resolves as written (Maven direct dependency)


def is_lockfile(path: str) -> bool:
    return basename(path) in LOCKFILE_NAMES


def is_manifest(path: str) -> bool:
    return basename(path) == MANIFEST_NAME or basename(path) in JAVA_MANIFEST_NAMES


def excluded(path: str) -> bool:
    parts = path.split("/")
    return any(part in ("node_modules", ".git", "bower_components", ".next", ".yarn", ".gradle", ".m2") for part in parts[:-1])


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


# ─── Java (*-4Shell) ────────────────────────────────────────────────────────
# Regex readers, never an XML parser: a hostile pom.xml cannot trigger entity expansion,
# and nothing is resolved from remote repositories.

SPRING_BOOT_KEY = "org.springframework.boot:spring-boot"
_COORD = re.compile(r"^[\w.-]+:[\w.-]+$")


def _java_key(group: str, artifact: str) -> str:
    """Spring Boot starters, parents and BOMs all stand in for the Boot release they come from."""
    if group == "org.springframework.boot" and artifact.startswith("spring-boot"):
        return SPRING_BOOT_KEY
    return f"{group}:{artifact}"


def _tag(block: str, name: str) -> str:
    match = re.search(rf"<{name}>\s*([^<]*?)\s*</{name}>", block)
    return match.group(1) if match else ""


def _resolve(value: str, props: dict[str, str]) -> str:
    for _ in range(4):
        found = re.fullmatch(r"\$\{([\w.-]+)\}", value.strip())
        if not found or found.group(1) not in props:
            break
        value = props[found.group(1)]
    return value.strip()


def parse_gradle_lock(text: str, file: str, watched: frozenset[str]) -> list[Resolved]:
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^([\w.-]+):([\w.-]+):([^=\s]+)=", line)
        if match:
            key = _java_key(match.group(1), match.group(2))
            if key in watched:
                found.append(Resolved(key, match.group(3), file, number))
    return found


def parse_pom(text: str, file: str, watched: frozenset[str]) -> tuple[list[Declared], dict]:
    clean = re.sub(r"<!--.*?-->", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    props: dict[str, str] = {}
    for section in re.findall(r"<properties>(.*?)</properties>", clean, re.S):
        props.update((k, v.strip()) for k, v in re.findall(r"<([\w.-]+)>([^<]*)</\1>", section))
    found = []

    def add(block: str, start: int, field: str):
        group, artifact = _tag(block, "groupId"), _tag(block, "artifactId")
        version = _resolve(_tag(block, "version"), props)
        key = _java_key(group, artifact)
        if key in watched and version and "${" not in version:
            exact = not any(ch in version for ch in "[](),")
            found.append(Declared(key, version, file, clean.count("\n", 0, start) + 1, field, pinned=exact))

    for match in re.finditer(r"<parent>(.*?)</parent>", clean, re.S):
        add(match.group(1), match.start(), "parent")
    for match in re.finditer(r"<dependency>(.*?)</dependency>", clean, re.S):
        add(match.group(1), match.start(), "dependency")
    packaging = _tag(clean, "packaging")
    return found, {"war": packaging.lower() == "war"}


_GRADLE_STRING = re.compile(r"""["']([\w.-]+):([\w.-]+):([^"'@:\s]+)(?:@\w+)?["']""")
_GRADLE_MAP = re.compile(r"""group\s*[:=]\s*["']([\w.-]+)["']\s*,\s*name\s*[:=]\s*["']([\w.-]+)["']\s*,\s*version\s*[:=]\s*["']([^"']+)["']""")
_GRADLE_BOOT_PLUGIN = re.compile(r"""id\s*\(?\s*["']org\.springframework\.boot["']\s*\)?\s*version\s*\(?\s*["']([^"']+)["']""")
_GRADLE_VAR = re.compile(r"""(?:^|[\s{;])(?:def\s+|val\s+|var\s+|set\(\s*["'])?([A-Za-z_][\w.]*)["']?\s*[=,]\s*["']([\w.+-]+)["']""", re.M)
_GRADLE_WAR = re.compile(r"""id\s*\(?\s*["']war["']|apply\s+plugin\s*:\s*["']war["']|^\s*war\s*\{""", re.M)


def parse_gradle(text: str, file: str, watched: frozenset[str]) -> tuple[list[Declared], dict]:
    variables = {}
    for name, value in _GRADLE_VAR.findall(text):
        variables[name] = value
        variables.setdefault(name.rsplit(".", 1)[-1], value)  # ext.log4jVersion -> $log4jVersion
    found = []

    def add(group, artifact, version, start, field):
        key = _java_key(group, artifact)
        name = version.strip().lstrip("$").strip("{}")
        version = variables.get(name, version) if version.startswith("$") else version
        if key in watched and version and "$" not in version:
            found.append(Declared(key, version, file, text.count("\n", 0, start) + 1, field))

    for match in _GRADLE_STRING.finditer(text):
        add(*match.groups(), match.start(), "dependency")
    for match in _GRADLE_MAP.finditer(text):
        add(*match.groups(), match.start(), "dependency")
    for match in _GRADLE_BOOT_PLUGIN.finditer(text):
        add("org.springframework.boot", "spring-boot", match.group(1), match.start(), "plugin")
    return found, {"war": bool(_GRADLE_WAR.search(text))}


def parse_version_catalog(text: str, file: str, watched: frozenset[str]) -> tuple[list[Declared], dict]:
    versions, section = {}, ""
    for line in text.splitlines():
        header = re.match(r"^\s*\[([\w.-]+)\]", line)
        if header:
            section = header.group(1)
        elif section == "versions":
            pair = re.match(r"""^\s*([\w.-]+)\s*=\s*["']([^"']+)["']""", line)
            if pair:
                versions[pair.group(1)] = pair.group(2)
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        module = re.search(r"""module\s*=\s*["']([\w.-]+):([\w.-]+)["']""", line)
        short = re.search(r"""=\s*["']([\w.-]+):([\w.-]+):([^"']+)["']""", line)
        if module:
            ref = re.search(r"""version\.ref\s*=\s*["']([\w.-]+)["']""", line)
            literal = re.search(r"""version\s*=\s*["']([^"']+)["']""", line)
            version = versions.get(ref.group(1), "") if ref else (literal.group(1) if literal else "")
            group, artifact = module.groups()
        elif short:
            group, artifact, version = short.groups()
        else:
            continue
        key = _java_key(group, artifact)
        if key in watched and version:
            found.append(Declared(key, version, file, number, "catalog"))
    return found, {"war": False}


_JAR = re.compile(r"(?:^|/)(log4j-core|spring-beans|spring-webmvc|spring-webflux|commons-text)-(\d[\w.]*?(?:-[\w.]+)?)\.jar$")
_JAR_GROUPS = {"log4j-core": "org.apache.logging.log4j", "spring-beans": "org.springframework",
               "spring-webmvc": "org.springframework", "spring-webflux": "org.springframework",
               "commons-text": "org.apache.commons"}


def jar_artifacts(paths, watched: frozenset[str]) -> list[Resolved]:
    """Vendored jars recognised by file name alone (no download needed)."""
    found = []
    for path in paths:
        match = _JAR.search(path)
        if match and not re.search(r"-(sources|javadoc|tests)$", match.group(2)):
            key = f"{_JAR_GROUPS[match.group(1)]}:{match.group(1)}"
            if key in watched:
                found.append(Resolved(key, match.group(2), path, 1))
    return found


_PARSERS = {
    "package-lock.json": parse_npm_lock,
    "npm-shrinkwrap.json": parse_npm_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "bun.lock": parse_bun_lock,
    "gradle.lockfile": parse_gradle_lock,
}
_JAVA_MANIFEST_PARSERS = {
    "pom.xml": parse_pom,
    "build.gradle": parse_gradle,
    "build.gradle.kts": parse_gradle,
    "libs.versions.toml": parse_version_catalog,
}


def parse_lockfile(path: str, text: str, watched: frozenset[str]) -> list[Resolved]:
    return _PARSERS[basename(path)](text, path, watched)


def is_java_manifest(path: str) -> bool:
    return basename(path) in JAVA_MANIFEST_NAMES


def parse_manifest(path: str, text: str, watched: frozenset[str]) -> tuple[list[Declared], dict]:
    """Declared watched dependencies plus manifest facts (npm data, or {"war": bool} for Java builds)."""
    if is_java_manifest(path):
        return _JAVA_MANIFEST_PARSERS[basename(path)](text, path, watched)
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
