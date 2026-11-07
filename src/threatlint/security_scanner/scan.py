"""Compose baseline and optional engines into an honest coverage report."""

from __future__ import annotations

from datetime import datetime, timezone

from .baseline import baseline
from .engines import external_scans
from .normalize import SEVERITIES, sort_findings, MAX_FINDINGS
from .snapshot import ScannerError, snapshot


def scan_repository(repository: str, *, engines=None, external=external_scans) -> dict:
    engines = engines or []
    if not isinstance(engines, list) or any(item not in {"semgrep", "trivy"} for item in engines):
        raise ScannerError("Choose semgrep and/or trivy; the baseline always runs")
    binding, files, coverage = snapshot(repository)
    findings = baseline(files)
    baseline_count = len(findings)
    extra, statuses = external(files, engines)
    findings.extend(extra)
    from .fixes import eligible, RULES
    for item in findings:
        item["fixAvailable"] = eligible(item, files)
    finding_limit = len(findings) >= MAX_FINDINGS
    findings = sort_findings(findings)[:MAX_FINDINGS]
    statuses.insert(0, {"id": "baseline", "categories": ["sast", "sca", "secrets", "iac"], "status": "completed",
                        "findings": baseline_count,
                        "detail": "Guard source/secret patterns, selected infrastructure checks, and npm lockfile hygiene; no CVE database or exploit verification."})
    coverage["status"] = "partial"
    coverage["maxFindings"] = MAX_FINDINGS
    coverage["findingLimitReached"] = finding_limit
    coverage["categories"] = {category: {"status": "partial", "engines": [status["id"] for status in statuses if category in status["categories"] and status["status"] in {"completed", "partial"}]}
                              for category in ("sast", "sca", "secrets", "iac")}
    coverage["limitations"] = ["Pattern matches require security review; no exploitability claim.",
                               "Dependency CVE coverage requires a successful opted-in Trivy run and its database.",
                               "Generated, binary, excluded, oversized, and unsupported files and git history are not scanned."]
    if finding_limit:
        coverage["limitations"].append("Finding budget reached; additional matches may be omitted. Narrow the scan scope for full output.")
    return {"schemaVersion": 1, "status": "partial", "binding": binding, "observedAt": datetime.now(timezone.utc).isoformat(),
            "findings": findings, "engines": statuses, "coverage": coverage,
            "summary": {severity: sum(item["severity"] == severity for item in findings) for severity in SEVERITIES},
            "policy": {"mode": "review", "autoApply": False, "eligibleRules": list(RULES)}}
