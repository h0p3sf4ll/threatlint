"""Semgrep follow-ups to triage and repair later: tuning that did not pass, triage that was blocked, and Semgrep
errors after an AVIT was already closed with its report.

None of these fail an AVIT review. Each is appended as one JSON line to ~/.threatlint/semgrep-tuning-backlog.jsonl
(THREATLINT_HOME overrides the folder) and listed with `threatlint avit tuning-backlog`. Both the headless runner and
the Workbench log through `threatlint avit resolve` (the Workbench passes its reason with --tuning-reason). Entries
hold finding metadata and the proposed rule, never credentials.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

FILE_NAME = "semgrep-tuning-backlog.jsonl"
STAGES = ("tuning", "triage", "semgrep")
_MAX_TEXT = 2_000
_MAX_RULE = 20_000


def path() -> Path:
    home = os.environ.get("THREATLINT_HOME") or os.path.join(os.path.expanduser("~"), ".threatlint")
    return Path(home) / FILE_NAME


def tuned_rule(markdown: str) -> str:
    """The proposed **Tuned rule** YAML block, if the report has one."""
    match = re.search(r"\*\*Tuned rule\*\*\s*:?\s*\n+\s*```[^\n]*\n(.*?)```", markdown or "", re.S | re.I)
    return match.group(1).strip()[:_MAX_RULE] if match else ""


def record(avit: str, stage: str, reason: str, *, context: dict | None = None, markdown: str = "", report_attachment: str = "",
           triage_reason: str = "", disposition: str = "FALSE POSITIVE", out=None) -> bool:
    """Append one follow-up. Never raises: a logging problem must not change the AVIT's outcome."""
    context = context or {}
    entry = {
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "avit": avit, "disposition": disposition, "stage": stage if stage in STAGES else "semgrep",
        "reason": str(reason or "")[:_MAX_TEXT], "triage_reason": str(triage_reason or "")[:_MAX_TEXT],
        **{key: str(context.get(key) or "") for key in ("rule", "scm_tool", "organization", "project", "repository",
                                                       "branch", "file_path", "line", "finding_source")},
        "report_attachment": report_attachment, "tuned_rule": tuned_rule(markdown), "status": "open",
    }
    try:
        target = path()
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:
        print(f"  ! The Semgrep follow-up could not be logged ({exc.__class__.__name__}); note it manually: {entry['reason']}", file=out or sys.stderr)
        return False
    print(f"  ! Logged for Semgrep triage and repair later ({entry['stage']}): {target}", file=out or sys.stdout)
    return True


def entries() -> list[dict]:
    try:
        lines = path().read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    found = []
    for line in lines:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            found.append(item)
    return found


def cmd_backlog(args) -> int:
    items = entries()
    if getattr(args, "json", False):
        for item in items:
            print(json.dumps(item, ensure_ascii=False))
        return 0
    if not items:
        print(f"No Semgrep follow-ups logged ({path()}).")
        return 0
    print(f"{len(items)} Semgrep follow-up(s) in {path()}:")
    for item in items:
        place = f"{item.get('repository') or '?'}@{item.get('branch') or '?'} {item.get('file_path') or ''}{':' + item['line'] if item.get('line') else ''}"
        print(f"  {item.get('recorded_at', '')}  {item.get('avit', '')}  [{item.get('stage', '')}]  {item.get('rule') or 'rule unknown'}")
        print(f"      {place.strip()}")
        print(f"      {item.get('reason', '')}")
    return 0
