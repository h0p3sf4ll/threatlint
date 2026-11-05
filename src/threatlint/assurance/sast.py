"""Static analysis stage: run Semgrep over the checkout and normalize its findings.

Semgrep is the built-in SAST provider; it runs against the pulled checkout, needs no ephemeral environment, and is
the gate's first stop. Additional providers (for example a SonarQube scan) plug in through the integrations
framework and are out of scope for this module. The scan runner is injectable so the pipeline is testable without
Semgrep installed.
"""

from __future__ import annotations

import json

from threatlint.avit_report import ResolveError

# Semgrep's own level → our severity, used only when a rule carries no explicit metadata severity.
_LEVEL = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
_METADATA_SEVERITY = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "ERROR": "HIGH", "MEDIUM": "MEDIUM",
                      "WARNING": "MEDIUM", "LOW": "LOW", "INFO": "INFO", "WARN": "MEDIUM"}


def _semgrep_runner(checkout: str, config: str):
    from threatlint import semgrep_engine  # noqa: PLC0415
    from threatlint.tls import tool_env  # noqa: PLC0415
    return semgrep_engine.run(["scan", "--config", config, "--json", "--quiet", "--metrics", "off", checkout],
                              environment=tool_env, error_type=ResolveError)


def _severity(result: dict) -> str:
    metadata = (result.get("extra") or {}).get("metadata") or {}
    explicit = str(metadata.get("severity") or metadata.get("impact") or "").upper()
    if explicit in _METADATA_SEVERITY:
        return _METADATA_SEVERITY[explicit]
    return _LEVEL.get(str((result.get("extra") or {}).get("severity") or "INFO").upper(), "LOW")


def normalize(payload: dict) -> list[dict]:
    """Turn Semgrep JSON into the pipeline's finding shape."""
    findings = []
    for result in payload.get("results", []) if isinstance(payload, dict) else []:
        extra = result.get("extra") or {}
        start = result.get("start") or {}
        findings.append({
            "source": "semgrep", "rule_id": str(result.get("check_id") or "semgrep-rule"),
            "title": str(extra.get("message") or result.get("check_id") or "Semgrep finding").strip()[:300],
            "severity": _severity(result),
            "location": f"{result.get('path', '?')}:{start.get('line', '?')}",
        })
    return findings


def scan(checkout: str, *, config: str = "auto", runner=_semgrep_runner) -> list[dict]:
    """Run the SAST scan and return normalized findings. ``runner(checkout, config)`` is injectable for tests."""
    completed = runner(checkout, config)
    try:
        payload = json.loads(completed.stdout or "{}")
    except ValueError as exc:
        detail = (getattr(completed, "stderr", "") or completed.stdout or "")[-300:]
        raise ResolveError(f"Semgrep did not return readable JSON: {detail}") from exc
    return normalize(payload)
