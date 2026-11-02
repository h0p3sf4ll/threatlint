"""Guard text, JSON, and SARIF rendering and severity thresholds."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from threatlint import __version__
from .models import Finding, SEVERITIES, _rank
from .rules import RULES


_SARIF_LEVEL = {"info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}


_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def to_text(findings: list[Finding]) -> str:
    if not findings:
        return "threatlint guard: no known-insecure patterns matched (this is not a security approval)."
    out = []
    for f in findings:
        out.append(f"{f.path}:{f.line}:{f.column}: {f.severity.upper()} {f.rule_id} {f.message}\n"
                   f"    secure alternative: {f.fix}")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in reversed(SEVERITIES)}
    out.append("threatlint guard: " + ", ".join(f"{n} {s}" for s, n in counts.items() if n))
    return "\n".join(out)


def to_json(findings: list[Finding]) -> str:
    return json.dumps({"tool": "threatlint-guard", "version": __version__,
                       "findings": [asdict(f) for f in findings]}, indent=2)


def to_sarif(findings: list[Finding]) -> str:
    used = sorted({f.rule_id for f in findings})
    rules = [{
        "id": rule.id, "name": rule.id,
        "shortDescription": {"text": rule.message},
        "help": {"text": rule.fix},
        "properties": {"security-severity": _SECURITY_SEVERITY[rule.severity],
                       "tags": ["security", rule.cwe]},
        "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
    } for rule in RULES if rule.id in used]
    results = [{
        "ruleId": f.rule_id, "level": _SARIF_LEVEL[f.severity],
        "message": {"text": f"{f.message} Secure alternative: {f.fix}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": Path(f.path).as_posix()},
                                            "region": {"startLine": f.line, "startColumn": f.column}}}],
    } for f in findings]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "threatlint-guard", "version": __version__,
                                      "informationUri": "https://github.com/h0p3sf4ll/threatlint", "rules": rules}},
                  "results": results}],
    }, indent=2)


def failing(findings: list[Finding], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = _rank(fail_on)
    return any(_rank(f.severity) >= threshold for f in findings)
