"""Draft confirmed runtime findings as ServiceNow AVITs. Posting is stubbed.

A real AVIT integration registers a publisher with `set_avit_publisher(fn)`, where ``fn(draft) -> str`` posts one
draft and returns a reference (e.g. an AVIT number). Until then, `publish_drafts` only formats and returns the
drafts; the assessment writes them to the report and to ``avits.json`` in the run directory and says they were not
posted. This mirrors `dast.set_invicti_hook`, so the live integration drops in without touching the pipeline.
"""

from __future__ import annotations

import datetime
from collections.abc import Callable

_PUBLISHER: Callable[[dict], str] | None = None


def set_avit_publisher(publisher: Callable[[dict], str] | None) -> None:
    """Register the live AVIT publisher, or None to return to the stub."""
    global _PUBLISHER
    _PUBLISHER = publisher


def avit_draft(finding: dict, target: dict, run_id: str) -> dict:
    """A confirmed finding as an AVIT draft: the fields a ServiceNow AVIT needs, with evidence already redacted."""
    return {
        "short_description": f"[Threatlint runtime] {finding['title']} at {finding['method']} {finding['path']}",
        "category": finding["category"],
        "cwe": finding["cwe"],
        "severity": finding["severity"],
        "rule_id": finding["rule_id"],
        "repository": target.get("web_url", ""),
        "branch": target.get("branch", ""),
        "endpoint": f"{finding['method']} {finding['path']}",
        "parameter": finding.get("parameter", ""),
        "evidence": finding["signals"],
        "state": "draft",
        "source": "Threatlint runtime red team",
        "run_id": run_id,
        "drafted": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


def publish_drafts(drafts: list[dict]) -> list[dict]:
    """Post each draft through the registered publisher, or mark it pending when posting is stubbed."""
    results = []
    for draft in drafts:
        if _PUBLISHER is None:
            results.append({**draft, "posted": False, "reference": None, "note": "ServiceNow posting is stubbed; not posted"})
            continue
        try:
            reference = _PUBLISHER(draft)
            results.append({**draft, "posted": True, "reference": reference, "note": f"Posted as {reference}"})
        except Exception as exc:  # noqa: BLE001 - a publisher failure must not lose the draft
            results.append({**draft, "posted": False, "reference": None, "note": f"Publisher error: {type(exc).__name__}: {exc}"})
    return results


def stubbed() -> bool:
    return _PUBLISHER is None
