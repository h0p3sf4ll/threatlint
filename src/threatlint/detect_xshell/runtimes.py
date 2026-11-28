"""Runtime and platform versions (PHP, Node.js, JDK, WordPress core) and Python Brotli pins.

Package managers do not record the runtime an app ships on, so evidence comes from build and
tooling files. Only exact versions count: a floating tag such as ``node:22`` or ``php:8.3-apache``
resolves to whatever patch is current, so it proves nothing about exposure and is ignored.

Strength:
- Resolved (CONFIRMED evidence): Docker FROM / compose image tags, wp-includes/version.php,
  composer.lock WordPress-core packages, Python lockfiles and ``==`` requirement pins.
- Declared (PLAUSIBLE): developer and CI pins (.nvmrc, .node-version, .tool-versions,
  .java-version, .sdkmanrc, package.json volta, composer platform, setup-* actions), because
  production may run something else.
"""
from __future__ import annotations

import json
import re
from posixpath import basename

from .advisories import JAVA_RUNTIME, NODE_RUNTIME, PHP_RUNTIME, PYPI_BROTLI, PYPI_BROTLICFFI, WORDPRESS_CORE
from .lockfiles import Declared, Resolved

_DOCKER_IMAGES = {
    "php": PHP_RUNTIME, "node": NODE_RUNTIME, "wordpress": WORDPRESS_CORE,
    "eclipse-temurin": JAVA_RUNTIME, "amazoncorretto": JAVA_RUNTIME, "openjdk": JAVA_RUNTIME,
    "ibm-semeru-runtimes": JAVA_RUNTIME, "sapmachine": JAVA_RUNTIME,
}
_IMAGE_REF = re.compile(r"(?:^|\s)(?:[\w.-]+(?::\d+)?/)*(?P<name>[a-z0-9][\w.-]*):(?P<tag>[\w.+-]+)")
_EXACT = re.compile(r"^v?(\d+\.\d+\.\d+(?:\.\d+)?)(?=$|[-_+])")
_WP_CORE_PACKAGES = {"johnpbloch/wordpress-core", "johnpbloch/wordpress", "roots/wordpress", "roots/wordpress-no-content"}
_TOOL_KEYS = {"nodejs": NODE_RUNTIME, "node": NODE_RUNTIME, "php": PHP_RUNTIME, "java": JAVA_RUNTIME}
_SETUP_KEYS = {"node-version": NODE_RUNTIME, "php-version": PHP_RUNTIME, "java-version": JAVA_RUNTIME}
_PY_PACKAGES = {"brotli": PYPI_BROTLI, "brotlicffi": PYPI_BROTLICFFI}

RUNTIME_KEYS = frozenset(_DOCKER_IMAGES.values()) | {PYPI_BROTLI, PYPI_BROTLICFFI}


def is_runtime_file(path: str) -> bool:
    name = basename(path)
    lower = name.lower()
    return (lower.startswith("dockerfile") or lower.endswith(".dockerfile") or lower.startswith(("docker-compose", "compose."))
            or name in (".nvmrc", ".node-version", ".tool-versions", ".java-version", ".sdkmanrc", "composer.json",
                        "composer.lock", "poetry.lock", "uv.lock", "Pipfile.lock")
            or (lower.startswith("requirements") and lower.endswith(".txt"))
            or path.endswith("wp-includes/version.php")
            or (re.search(r"(^|/)\.github/workflows/[^/]+\.ya?ml$", path) is not None))


def exact_version(text: str) -> str:
    """The exact version at the start of a tag or pin ("22.23.3-alpine" -> "22.23.3"), else ""."""
    match = _EXACT.match((text or "").strip().strip("'\""))
    return match.group(1) if match else ""


def _line(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def parse_runtime_file(path: str, text: str) -> tuple[list[Resolved], list[Declared], list[str]]:
    """(resolved, declared, coverage notes) for one runtime evidence file."""
    name = basename(path)
    lower = name.lower()
    resolved: list[Resolved] = []
    declared: list[Declared] = []
    notes: list[str] = []

    if lower.startswith("dockerfile") or lower.endswith(".dockerfile") or lower.startswith(("docker-compose", "compose.")):
        pattern = r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)" if "compose" not in lower else r"^\s*image:\s*[\"']?([^\s\"']+)"
        for match in re.finditer(pattern, text, re.M | re.I):
            ref = _IMAGE_REF.search(" " + match.group(1))
            if not ref or ref.group("name") not in _DOCKER_IMAGES:
                continue
            key, tag = _DOCKER_IMAGES[ref.group("name")], ref.group("tag")
            if ref.group("name") == "amazoncorretto" and re.match(r"^\d+\.\d+\.\d+\.\d+\.\d+", tag):
                notes.append(f"{path}: Corretto tag {tag} uses a vendor build number; check the JDK version manually.")
                continue
            version = exact_version(tag)
            if version:
                resolved.append(Resolved(key, version, path, _line(text, match.start())))
            # wordpress:6.9.3-php8.3.10-apache also pins PHP
            php = re.search(r"-php(\d+\.\d+\.\d+)", tag)
            if key == WORDPRESS_CORE and php:
                resolved.append(Resolved(PHP_RUNTIME, php.group(1), path, _line(text, match.start())))
        return resolved, declared, notes

    if name in (".nvmrc", ".node-version", ".java-version"):
        version = exact_version(text.strip().splitlines()[0] if text.strip() else "")
        if version:
            declared.append(Declared(NODE_RUNTIME if name != ".java-version" else JAVA_RUNTIME, version, path, 1, "tooling"))
        return resolved, declared, notes

    if name == ".tool-versions":
        for number, line in enumerate(text.splitlines(), 1):
            parts = line.split("#", 1)[0].split()
            if len(parts) >= 2 and parts[0] in _TOOL_KEYS:
                version = exact_version(re.sub(r"^[a-z]+-", "", parts[1]))  # java temurin-21.0.13+11
                if version:
                    declared.append(Declared(_TOOL_KEYS[parts[0]], version, path, number, "tooling"))
        return resolved, declared, notes

    if name == ".sdkmanrc":
        for number, line in enumerate(text.splitlines(), 1):
            match = re.match(r"^\s*java\s*=\s*(\S+)", line)
            if match and exact_version(match.group(1)):
                declared.append(Declared(JAVA_RUNTIME, exact_version(match.group(1)), path, number, "tooling"))
        return resolved, declared, notes

    if path.endswith("wp-includes/version.php"):
        match = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", text)
        if match:
            resolved.append(Resolved(WORDPRESS_CORE, match.group(1), path, _line(text, match.start())))
        return resolved, declared, notes

    if name == "composer.json":
        data = json.loads(text)
        platform = ((data.get("config") or {}).get("platform") or {}).get("php") if isinstance(data, dict) else None
        if isinstance(platform, str) and exact_version(platform):
            index = text.find('"platform"')
            declared.append(Declared(PHP_RUNTIME, exact_version(platform), path, _line(text, max(index, 0)), "platform"))
        return resolved, declared, notes

    if name == "composer.lock":
        data = json.loads(text)
        for package in (data.get("packages") or []) + (data.get("packages-dev") or []):
            if isinstance(package, dict) and package.get("name") in _WP_CORE_PACKAGES:
                version = str(package.get("version") or "").lstrip("v")
                if version:
                    index = text.find(json.dumps(package["name"]))
                    resolved.append(Resolved(WORDPRESS_CORE, version, path, _line(text, max(index, 0))))
        return resolved, declared, notes

    if lower.startswith("requirements") and lower.endswith(".txt"):
        for number, line in enumerate(text.splitlines(), 1):
            match = re.match(r"^\s*(brotli|brotlicffi)\s*(?:\[[^\]]*\])?\s*==\s*([\w.]+)", line, re.I)
            if match:
                resolved.append(Resolved(_PY_PACKAGES[match.group(1).lower()], match.group(2), path, number))
        return resolved, declared, notes

    if name in ("poetry.lock", "uv.lock"):
        for match in re.finditer(r'^name\s*=\s*"(brotli|brotlicffi)"\s*\nversion\s*=\s*"([^"]+)"', text, re.M | re.I):
            resolved.append(Resolved(_PY_PACKAGES[match.group(1).lower()], match.group(2), path, _line(text, match.start())))
        return resolved, declared, notes

    if name == "Pipfile.lock":
        data = json.loads(text)
        for section in ("default", "develop"):
            for pkg, meta in ((data.get(section) or {}).items() if isinstance(data, dict) else []):
                if pkg.lower() in _PY_PACKAGES and isinstance(meta, dict) and str(meta.get("version", "")).startswith("=="):
                    index = text.find(json.dumps(pkg))
                    resolved.append(Resolved(_PY_PACKAGES[pkg.lower()], meta["version"][2:], path, _line(text, max(index, 0))))
        return resolved, declared, notes

    if re.search(r"(^|/)\.github/workflows/[^/]+\.ya?ml$", path):
        for match in re.finditer(r"^\s*(node-version|php-version|java-version)\s*:\s*(.+)$", text, re.M):
            values = re.findall(r"[\w.+-]+", match.group(2).split("#", 1)[0])
            for value in values:
                version = exact_version(value)
                if version:
                    declared.append(Declared(_SETUP_KEYS[match.group(1)], version, path, _line(text, match.start()), "ci"))
        return resolved, declared, notes

    return resolved, declared, notes


def package_json_runtime(path: str, data: dict, text: str) -> list[Declared]:
    """package.json "volta": {"node": "22.23.3"} (exact pins only; "engines" ranges prove nothing)."""
    node = ((data.get("volta") or {}).get("node")) if isinstance(data, dict) else None
    version = exact_version(node) if isinstance(node, str) else ""
    if not version:
        return []
    return [Declared(NODE_RUNTIME, version, path, _line(text, max(text.find('"volta"'), 0)), "volta")]
