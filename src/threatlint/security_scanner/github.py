"""Compact PR summaries and native, commit-bound GitHub suggestion payloads."""

from __future__ import annotations

import html
import re

from .normalize import sort_findings, redacted


def _cell(value, limit=240):
    return html.escape(redacted(value)).replace("@", "@\u200b").replace("|", "\\|").replace("`", "ˋ").replace("\n", " ")[:limit]


def build_comment(scan: dict, action_url: str = "") -> str:
    lines = ["<!-- threatlint:security-scanner -->", "## Security scanner", "",
             f"Revision: `{_cell(scan.get('binding', {}).get('commit', 'unknown'))}`. Coverage: **partial**; scanner matches require review.", "",
             "| Severity | Issue | Impact | Vulnerable code | Proposed fix |",
             "| --- | --- | --- | --- | --- |"]
    for item in sort_findings(scan.get("findings", []))[:20]:
        lines.append("| " + " | ".join((_cell(item["severity"]), _cell(item["title"]), _cell(item["impact"]),
                                       _cell(f"{item['path']}:{item['line']} — {item['snippet']}"), _cell(item["recommendation"]))) + " |")
    if not scan.get("findings"):
        lines.append("| — | No findings in evaluated checks | Coverage is limited | — | Review engine and coverage details |")
    lines += ["", "Engines: " + "; ".join(f"{_cell(engine['id'])}: {_cell(engine['status'])}" for engine in scan.get("engines", [])) + "."]
    if len(scan.get("findings", [])) > 20:
        lines.append(f"Showing 20 of {len(scan['findings'])} findings; the scan artifact contains the rest.")
    if re.fullmatch(r"https://[A-Za-z0-9.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/workflows/appsec-auto-fix\.yml", action_url):
        lines += ["", f"[Apply fix and rescan — open the reviewed workflow]({action_url})",
                  "Provide this exact revision in the workflow. Eligible edits open a draft PR; human review is required."]
    return "\n".join(lines)


def suggestion_payload(plan: dict, commit: str) -> dict:
    if not re.fullmatch(r"[a-f0-9]{40,64}", commit) or plan.get("binding", {}).get("commit") != commit:
        raise ValueError("Suggestion must match the reviewed commit")
    if plan.get("ruleId") != "TL-DEBUG-ENABLED" or "\n" in plan.get("after", "") or "```" in plan.get("after", ""):
        raise ValueError("Only a validated single-line deterministic fix is eligible")
    from .fixes import protected, DEBUG_ASSIGNMENT
    before = plan.get("before", "")
    match = DEBUG_ASSIGNMENT.fullmatch(before)
    if not match or plan["after"] != match[1] + "False" + match[2] or redacted(before) != before:
        raise ValueError("Suggestion replacement must be the exact safe transformation")
    path = plan.get("path", "")
    if protected(path) or path.startswith("/") or any(part in {"", ".", ".."} for part in path.split("/")):
        raise ValueError("Protected or invalid suggestion path")
    return {"commit_id": commit, "path": path, "line": plan["line"], "side": "RIGHT",
            "body": "Disable debug mode after reviewing runtime behavior. Commit this native suggestion to trigger the PR scan again.\n\n```suggestion\n" + plan["after"] + "\n```"}
