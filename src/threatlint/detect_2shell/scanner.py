"""Deterministic 2Shell detector for one repository snapshot (a local directory or a remote tree)."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Iterable, Protocol

from . import advisories as catalog
from .lockfiles import (
    MAX_FILE_BYTES, Declared, Resolved, excluded, is_lockfile, is_manifest, parse_lockfile, parse_manifest,
)
from .semver import Version, parse, range_floor

SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
CONFIDENCE_RANK = {"CONFIRMED": 3, "PLAUSIBLE": 2, "THEORETICAL": 1}
MAX_MANIFESTS = 400

_APP_ROUTER = re.compile(
    r"(?:^|/)(?:src/)?app/(?:.+/)?(?:page|layout|route|template|default|loading|error|not-found)\.(?:js|jsx|ts|tsx|mjs|cjs)$"
)


class FileSource(Protocol):
    """A read-only repository snapshot."""

    def paths(self) -> list[str]: ...  # repo-relative, "/" separated
    def size(self, path: str) -> int | None: ...
    def read(self, path: str) -> str: ...


class LocalSource:
    def __init__(self, root: str, max_files: int = 400_000):
        self.root = os.path.abspath(root)
        if not os.path.isdir(self.root):
            raise ValueError(f"Not a directory: {root}")
        self.max_files = max_files
        self.truncated = False
        self._paths: list[str] | None = None

    def paths(self) -> list[str]:
        if self._paths is None:
            found: list[str] = []
            for directory, dirs, files in os.walk(self.root):
                dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", ".next", ".yarn", "bower_components")
                           and not os.path.islink(os.path.join(directory, d))]
                rel = os.path.relpath(directory, self.root).replace(os.sep, "/")
                for name in files:
                    found.append(name if rel == "." else f"{rel}/{name}")
                    if len(found) >= self.max_files:
                        self.truncated = True
                        self._paths = found
                        return found
            self._paths = found
        return self._paths

    def size(self, path: str) -> int | None:
        try:
            return os.path.getsize(self._abs(path))
        except OSError:
            return None

    def read(self, path: str) -> str:
        with open(self._abs(path), encoding="utf-8", errors="replace") as handle:
            return handle.read(MAX_FILE_BYTES + 1)

    def _abs(self, path: str) -> str:
        full = os.path.realpath(os.path.join(self.root, path))
        if not (full == self.root or full.startswith(self.root + os.sep)):
            raise ValueError("Path escapes the repository")
        return full


@dataclass
class ScanResult:
    findings: list[dict] = field(default_factory=list)
    inventory: list[dict] = field(default_factory=list)
    coverage: list[str] = field(default_factory=list)
    files_examined: int = 0

    @property
    def status(self) -> str:
        if self.findings:
            return "vulnerable"
        return "clean" if self.inventory else "not-applicable"


def matching_line(advisory: catalog.Advisory, version: Version) -> catalog.FixLine | None:
    for line in advisory.lines:
        introduced = parse(line.introduced)
        if introduced is None or version < introduced:
            continue
        if line.fixed is None:
            if version.core == introduced.core:
                return line
            continue
        fixed = parse(line.fixed)
        if fixed is not None and version < fixed:
            return line
    return None


def _advisories_for(package: str) -> list[catalog.Advisory]:
    return [adv for adv in catalog.ADVISORIES if package in adv.packages]


def _under(path: str, directory: str) -> bool:
    return not directory or path.startswith(directory + "/")


def _dir(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _app_router_evidence(paths: Iterable[str], directory: str) -> str:
    for path in paths:
        if _under(path, directory) and not excluded(path) and _APP_ROUTER.search(path[len(directory) + 1:] if directory else path):
            return path
    return ""


def _fold(package: str, version: Version, matches: list[tuple[catalog.Advisory, catalog.FixLine]]) -> dict:
    """One finding per package@version@file: the most severe advisory, every CVE, the safest fixed version."""
    matches.sort(key=lambda item: -SEVERITY_RANK[item[0].severity])
    primary = matches[0][0]
    cves = list(dict.fromkeys(cve for adv, _ in matches for cve in adv.cves))
    fixes = [parse(line.fixed) for _, line in matches if line.fixed]
    no_fix_on_line = any(line.fixed is None for _, line in matches)
    fixed_in = str(max(fixes)) if fixes and not no_fix_on_line else ""
    return {
        "advisory": primary.key,
        "title": primary.title,
        "severity": primary.severity,
        "cvss": primary.cvss,
        "cwe": primary.cwe,
        "package": package,
        "version": str(version),
        "fixedIn": fixed_in or "no fix on this release line; move to a supported stable line",
        "cves": cves,
        "impact": primary.impact,
        "remediation": primary.remediation,
        "sources": list(dict.fromkeys(src for adv, _ in matches for src in adv.sources)),
        "related": [adv.key for adv, _ in matches[1:]],
    }


def scan_source(source: FileSource) -> ScanResult:
    result = ScanResult()
    watched = catalog.WATCHED_PACKAGES
    paths = [p for p in source.paths() if not excluded(p)]
    lockfiles = sorted(p for p in paths if is_lockfile(p))
    manifests = sorted(p for p in paths if is_manifest(p))
    if len(manifests) > MAX_MANIFESTS:
        result.coverage.append(f"Only the first {MAX_MANIFESTS} of {len(manifests)} package.json files were read.")
        manifests = manifests[:MAX_MANIFESTS]

    resolved: list[Resolved] = []
    for path in lockfiles:
        size = source.size(path)
        if size is not None and size > MAX_FILE_BYTES:
            result.coverage.append(f"Skipped {path}: larger than {MAX_FILE_BYTES // 1_000_000} MB.")
            continue
        try:
            resolved.extend(parse_lockfile(path, source.read(path), watched))
            result.files_examined += 1
        except Exception as exc:  # noqa: BLE001 - one malformed lockfile must not stop the scan
            result.coverage.append(f"Could not parse {path}: {type(exc).__name__}.")

    declared: list[Declared] = []
    for path in manifests:
        try:
            found, _ = parse_manifest(path, source.read(path), watched)
            declared.extend(found)
            result.files_examined += 1
        except Exception as exc:  # noqa: BLE001
            result.coverage.append(f"Could not parse {path}: {type(exc).__name__}.")

    lock_dirs = {_dir(p) for p in lockfiles}

    def covered(manifest: str) -> bool:
        directory = _dir(manifest)
        while True:
            if directory in lock_dirs:
                return True
            if not directory:
                return False
            directory = _dir(directory)

    seen_inventory = set()
    for item in resolved:
        key = (item.package, item.version, item.file)
        if key not in seen_inventory:
            seen_inventory.add(key)
            result.inventory.append({"package": item.package, "version": item.version, "file": item.file,
                                     "line": item.line, "source": "lockfile"})
    for item in declared:
        if not covered(item.file):
            result.inventory.append({"package": item.package, "version": item.spec, "file": item.file,
                                     "line": item.line, "source": "manifest"})

    rsc_markers = {entry["package"] for entry in result.inventory}
    findings: dict[tuple, dict] = {}

    def add(package, version, file, line, confidence, evidence_note):
        matches = [(adv, ln) for adv in _advisories_for(package) if (ln := matching_line(adv, version))]
        if not matches:
            return
        key = (package, str(version), file)
        if key in findings:
            return
        finding = _fold(package, version, matches)
        exposure, confidence = _exposure(finding, package, file, paths, rsc_markers, confidence)
        finding.update({"file": file, "line": line, "confidence": confidence, "exposure": exposure,
                        "evidence": evidence_note})
        findings[key] = finding

    for item in resolved:
        version = parse(item.version)
        if version:
            add(item.package, version, item.file, item.line, "CONFIRMED",
                f"{item.file} resolves {item.package}@{item.version}.")
    for item in declared:
        if covered(item.file):
            continue
        floor = range_floor(item.spec)
        if floor:
            add(item.package, floor, item.file, item.line, "PLAUSIBLE",
                f"{item.file} declares {item.package} \"{item.spec}\" and no lockfile pins the installed version; "
                f"the lowest allowed version {floor} is affected. Confirm with the deployed lockfile or build.")

    ordered = sorted(findings.values(), key=lambda f: (-SEVERITY_RANK[f["severity"]], -CONFIDENCE_RANK[f["confidence"]],
                                                       f["file"], f["package"]))
    for number, finding in enumerate(ordered, 1):
        finding["id"] = f"TS-{number:03d}"
    result.findings = ordered
    if getattr(source, "truncated", False):
        result.coverage.append("The repository file list was truncated; some manifests may not have been read.")
    return result


def _exposure(finding: dict, package: str, file: str, paths: list[str], markers: set[str], confidence: str):
    directory = _dir(file)
    if package == "next":
        evidence = _app_router_evidence(paths, directory)
        if evidence:
            return f"App Router in use (for example `{evidence}`); the vulnerable code path is reachable.", confidence
        return ("No App Router files were found under this project. Pages Router and Edge Runtime apps are not "
                "affected by the RCE; upgrade anyway and verify.", "THEORETICAL")
    if package in catalog.REACT_RSC_PACKAGES:
        frameworks = sorted(m for m in markers if m in catalog.RSC_FRAMEWORK_MARKERS)
        if frameworks:
            return f"RSC runtime present alongside {', '.join(frameworks)}.", confidence
        return "RSC runtime present; confirm the app serves React Server Components.", confidence
    return "RSC framework present.", confidence


def scan_path(path: str) -> ScanResult:
    return scan_source(LocalSource(path))
