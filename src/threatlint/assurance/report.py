"""Render the assurance run as Markdown."""

from __future__ import annotations

from threatlint.assurance.gate import SEVERITIES

_VERDICT_LINE = {
    "QUALIFIED": "✅ **QUALIFIED** — every scan ran and no stage reported a CRITICAL or HIGH finding.",
    "DISQUALIFIED": "🏁 **DISQUALIFIED** — all scans ran to completion (the data was still updated), but a stage "
                    "went out of bounds with a CRITICAL or HIGH finding. Like a racer who crosses the line after "
                    "leaving the track: a finish on paper, a loss on disqualification.",
    "ERROR": "⚠️ **ERROR** — a stage could not run to produce a verdict; see the stage notes.",
}


def _counts_line(counts: dict) -> str:
    parts = [f"{counts[severity]} {severity.title()}" for severity in SEVERITIES if counts.get(severity)]
    return ", ".join(parts) if parts else "no findings"


def render(state: dict) -> str:
    target = state.get("target", {})
    lines = [
        "# Assurance Gate", "",
        f"**Repository:** {target.get('web_url', '?')} · branch `{target.get('branch', '?')}`  ",
        f"**Run:** {state.get('run_id', '?')} · {state.get('started', '?')}  ",
        f"**Application type:** {state.get('app_class', {}).get('type', '?')} "
        f"({state.get('app_class', {}).get('platform', '?')})",
        "",
        f"## Verdict: {state.get('verdict', '?')}", "",
        _VERDICT_LINE.get(state.get("verdict", ""), ""),
    ]
    if state.get("disqualified_at"):
        lines += ["", f"**Disqualified at:** the {state['disqualified_at']} stage (first gate tripped)."]
    lines += ["", "## Stages", ""]
    for stage in state.get("stages", []):
        gate = stage.get("gate") or {}
        status = stage.get("status", "?")
        headline = "GATE TRIPPED" if gate.get("tripped") else ("could not run" if status == "error" else "clear")
        lines.append(f"### {stage['name']} — {headline}")
        if stage.get("provider"):
            lines.append(f"- Provider: {stage['provider']}")
        if status == "error":
            lines.append(f"- Did not run: {stage.get('note', 'unknown error')}")
        else:
            lines.append(f"- Findings: {_counts_line(gate.get('counts', {}))}")
            if gate.get("tripped"):
                lines.append(f"- **{gate.get('blocking', 0)} CRITICAL/HIGH finding(s) — this is a disqualifying gate.**")
        if stage.get("note") and status != "error":
            lines.append(f"- Note: {stage['note']}")
        top = [f for f in stage.get("findings", []) if str(f.get("severity")).upper() in ("CRITICAL", "HIGH")][:10]
        for finding in top:
            where = finding.get("location") or f"{finding.get('method', '')} {finding.get('path', '')}".strip()
            lines.append(f"  - `{finding.get('severity')}` {finding.get('title', finding.get('rule_id', '?'))}"
                         + (f" ({where})" if where else ""))
        lines.append("")
    lines += [
        "## Scope and posture", "",
        "- Every stage runs to completion so the scanning platforms stay up to date, even after the verdict is lost.",
        "- The web/API dynamic stage builds the app in a bounded, no-egress ephemeral environment and tears it down.",
        "- Invicti and NowSecure submissions are injectable; when not configured they are recorded as stubbed, not sent.",
        "",
    ]
    return "\n".join(lines)
