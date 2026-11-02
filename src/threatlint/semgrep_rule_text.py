"""Pure parsing and normalization of proposed Semgrep rules and fixtures."""

from __future__ import annotations

import re
from pathlib import Path

EXCLUSION = re.compile(r"^\s*-?\s*(pattern-not(?:-inside|-regex)?|metavariable-regex|pattern-sanitizers|regex):")


def tuned_rule_from_report(report: str) -> str:
    """The reviewer's tuned-rule YAML block, or empty when none was proposed."""
    match = re.search(r"\*\*Tuned rule\*\*:\s*\n+```ya?ml\n(.*?)\n```", report, re.S)
    return match.group(1).strip() + "\n" if match else ""


def fixtures_from_report(report: str) -> str:
    match = re.search(r"\*\*Tuned rule fixtures\*\*:\s*\n+```\w*\n(.*?)\n```", report, re.S)
    return match.group(1) + "\n" if match else ""


def fixture_lines(fixtures: str, rule_id: str) -> tuple[list[int], list[int]]:
    """Expected matching and nonmatching lines using Semgrep's marker convention."""
    expect, avoid = [], []
    for number, line in enumerate(fixtures.splitlines(), start=1):
        marker = re.search(r"(ruleid|ok):\s*([\w.,\s-]+?)\s*(?:-->|\*/)?\s*$", line) or re.search(r"(ruleid|ok):\s*([\w.,\s-]+)", line)
        if marker and rule_id in [part.strip() for part in marker.group(2).split(",")]:
            # A standalone marker annotates the next line; a trailing marker annotates its own line.
            own_line = bool(line[:marker.start()].strip(" \t/#*-<!"))
            (expect if marker.group(1) == "ruleid" else avoid).append(number if own_line else number + 1)
    return expect, avoid


def fixture_name(rule_id: str, target_file: str) -> str:
    """Pair a fixture with its YAML rule without overwriting the rule itself."""
    target = Path(target_file)
    suffix = target.suffix or (".dockerfile" if target.name.lower().startswith("dockerfile") else ".txt")
    return f"{rule_id}{'.test' if suffix.lower() in ('.yaml', '.yml') else ''}{suffix}"


def needs_named_fixture(rule_yaml: str, target_file: str) -> bool:
    """Extensionless targets and literal path includes need a copy with the target's name."""
    named_only = bool(target_file) and not Path(target_file).suffix
    literal_include = re.search(r"(?m)^\s+include:\s*\n\s+-\s*['\"]?[^*\n]+['\"]?\s*$", rule_yaml)
    return bool((named_only or literal_include) and target_file)


def exclusions(rule_yaml: str, pattern: re.Pattern = EXCLUSION) -> list[str]:
    """Exclusion and sanitizer lines, compared without indentation."""
    return [line.strip() for line in rule_yaml.splitlines() if pattern.match(line)]


def normalize_for_merge(text: str) -> str:
    """Ignore registry metadata and IDs while preserving all rule-body edits."""
    text = re.sub(r"(?m)^(\s*-\s*id:\s*)\S+", lambda match: match.group(1) + "RULE_ID", text, count=1)
    out, skipping, indent = [], False, 0
    for line in text.splitlines():
        if re.match(r"^\s+semgrep\.dev:\s*$", line) or re.match(r"^\s+(source|shortlink|rule-origin-note):", line):
            skipping, indent = True, len(line) - len(line.lstrip())
            continue
        if skipping and (not line.strip() or len(line) - len(line.lstrip()) > indent):
            continue
        skipping = False
        out.append(line)
    return "\n".join(out) + "\n"
