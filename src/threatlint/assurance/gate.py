"""The pass/fail gate and its "DNF" aggregation.

Each stage of the pipeline produces normalized findings. A stage *trips the gate* when it has any CRITICAL or HIGH
finding. The pipeline never skips a later stage because an earlier one tripped — every scan still runs to completion,
because the platforms need the data ("crossed the finish line") — but the verdict is decided by the gate ("went out
of bounds → loss on disqualification"):

  QUALIFIED     every stage ran and none tripped the gate.
  DISQUALIFIED  at least one stage tripped; ``disqualified_at`` names the first one, in stage order.
  ERROR         no stage tripped, but a stage could not run to produce a verdict (e.g. a tool was missing).
"""

from __future__ import annotations

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
BLOCKING = ("CRITICAL", "HIGH")


def severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = str(finding.get("severity") or "INFO").upper()
        counts[severity if severity in counts else "INFO"] += 1
    return counts


def evaluate(findings: list[dict]) -> dict:
    """The gate result for one stage's findings: whether a CRITICAL or HIGH tripped it, with the counts."""
    counts = severity_counts(findings)
    blocking = sum(counts[severity] for severity in BLOCKING)
    return {"threshold": "CRITICAL or HIGH", "tripped": blocking > 0, "blocking": blocking, "counts": counts}


def verdict(stages: list[dict]) -> tuple[str, str | None]:
    """Overall verdict and the first stage that tripped the gate (``None`` when nothing tripped)."""
    tripped = [stage for stage in stages if stage.get("gate", {}).get("tripped")]
    if tripped:
        return "DISQUALIFIED", tripped[0]["name"]
    if any(stage.get("status") == "error" for stage in stages):
        return "ERROR", None
    return "QUALIFIED", None
