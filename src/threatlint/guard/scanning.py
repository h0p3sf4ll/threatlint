"""Language-aware scanning, justified suppressions, and file discovery."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from pathlib import Path

from .models import Finding, Rule, _rank
from .rules import ANY, _COMPILED_RULES


LANGUAGE_EXTENSIONS = {
    "python": {".py", ".pyw"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte"},
    "go": {".go"},
    "java": {".java", ".kt", ".scala"},
    "csharp": {".cs"},
    "ruby": {".rb"},
    "php": {".php"},
}


TEXT_EXTENSIONS = set().union(*LANGUAGE_EXTENSIONS.values()) | {
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".properties",
    ".sh", ".bash", ".zsh", ".ps1", ".tf", ".tfvars", ".xml", ".html", ".md", ".txt",
}


SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
             ".tox", ".mypy_cache", ".pytest_cache", "release", "vendor", "target", ".next"}


MAX_FILE_BYTES = 1_000_000
MAX_LINE_CHARS = 4000
SNIPPET_CHARS = 200
FILE_SUPPRESSION_LINES = 10
SUPPRESS = re.compile(r"threatlint-ignore:\s*((?:(?:TL-[A-Z0-9-]+|ALL)[\s,]*)+)(\S.*)?$")
SUPPRESS_FILE = re.compile(r"threatlint-ignore-file:\s*((?:(?:TL-[A-Z0-9-]+|ALL)[\s,]*)+)(\S.*)$")


def _rule_ids(listing: str) -> set[str]:
    return {item.strip() for item in listing.replace(",", " ").split()}


def _language(path: Path) -> str | None:
    suffix = path.suffix.lower()
    for language, extensions in LANGUAGE_EXTENSIONS.items():
        if suffix in extensions:
            return language
    return None


def _scannable(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS or path.name.startswith(".env")


def _suppressed(lines: Sequence[str], index: int, rule_id: str) -> bool:
    for candidate in (lines[index], lines[index - 1] if index > 0 else ""):
        match = SUPPRESS.search(candidate)
        if match:
            ids = _rule_ids(match.group(1))
            # A suppression must name the rule and give a reason; blanket ignores are not honoured.
            if (rule_id in ids or "ALL" in ids) and match.group(2):
                return True
    return False


def _file_suppressions(lines: Sequence[str]) -> set[str]:
    ignored: set[str] = set()
    for line in lines[:FILE_SUPPRESSION_LINES]:
        match = SUPPRESS_FILE.search(line)
        if match:
            ignored |= _rule_ids(match.group(1)) - {"ALL"}
    return ignored


def _rule_findings(rule: Rule, regex: re.Pattern[str], lines: Sequence[str], path: str) -> Iterable[Finding]:
    for index, line in enumerate(lines):
        if len(line) > MAX_LINE_CHARS:
            continue
        # Match only the code before a suppression comment, never the comment text itself.
        match = regex.search(line.split("threatlint-ignore")[0])
        if not match or _suppressed(lines, index, rule.id):
            continue
        snippet = line[: match.start()].strip() + " [redacted]" if rule.id.startswith("TL-SECRET") else line.strip()
        yield Finding(rule.id, rule.severity, path, index + 1, match.start() + 1,
                      rule.message, rule.fix, rule.cwe, snippet[:SNIPPET_CHARS])


def scan_text(text: str, path: str = "<memory>", language: str | None = None) -> list[Finding]:
    """Scan source text. ``language`` overrides detection from ``path``."""
    lang = language or _language(Path(path))
    lines = text.splitlines()
    file_ignored = _file_suppressions(lines)
    findings = [finding
                for rule, regex in _COMPILED_RULES
                if (ANY in rule.languages or lang in rule.languages) and rule.id not in file_ignored
                for finding in _rule_findings(rule, regex, lines, path)]
    findings.sort(key=lambda f: (f.path, f.line, -_rank(f.severity)))
    return findings


def _walk(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        skipped = any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1])
        if not skipped and path.is_file() and _scannable(path):
            yield path


def iter_files(paths: Iterable[str]) -> Iterable[Path]:
    for raw in paths:
        root = Path(raw)
        if root.is_dir():
            yield from _walk(root)
        elif root.is_file() and _scannable(root):
            yield root


def scan_paths(paths: Iterable[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_files(paths):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_text(text, str(path)))
    return findings
