"""Stable findings with source attribution; scanner evidence is never exploit proof."""

from __future__ import annotations

import hashlib
import re

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")
MAX_FINDINGS = 2000


def redacted(value: object) -> str:
    text = str(value or "")
    # Use the same secret patterns as Guard, including findings embedded in SAST snippets.
    from threatlint.guard.rules import _COMPILED_RULES
    for rule, pattern in _COMPILED_RULES:
        if rule.id.startswith("TL-SECRET"):
            text = pattern.sub("[redacted]", text)
    return text[:800]


def finding(*, source, category, rule, title, severity, path="", line=1, column=1,
            snippet="", impact="Review reachability and attacker control before accepting this finding.",
            recommendation="Review the affected code and apply the smallest verified correction.",
            cwe=None, references=None, package=None, confidence="PATTERN_MATCH") -> dict:
    severity = str(severity).upper()
    if severity not in SEVERITIES:
        severity = "UNKNOWN"
    stable = "\0".join(map(str, (source, rule, path, line, (package or {}).get("name", ""))))
    fingerprint = hashlib.sha256(stable.encode()).hexdigest()
    snippet = "[secret redacted]" if category == "secrets" else redacted(snippet)
    return {"id": fingerprint[:24], "fingerprint": fingerprint, "category": category, "source": source,
            "ruleId": redacted(rule), "title": redacted(title), "severity": severity, "confidence": confidence,
            "path": str(path), "line": max(1, int(line or 1)), "column": max(1, int(column or 1)),
            "snippet": snippet, "impact": redacted(impact), "recommendation": redacted(recommendation),
            "cwe": cwe or [], "references": [ref for ref in (references or []) if isinstance(ref, str) and re.match(r"^https://", ref)][:8],
            "package": package, "fixAvailable": False,
            "evidence": [{"path": str(path), "line": max(1, int(line or 1)), "quote": snippet, "verification": "reported"}]}


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda value: (SEVERITIES.index(value["severity"]), value["path"], value["line"], value["id"]))
