"""ServiceNow catalog tasks (SCTASK) that ask AppSec to review one or more AVITs.

  threatlint sctask avits <SCTASK>          list the AVIT numbers named in the task's description
  threatlint sctask close <SCTASK> [--yes]  after the AVITs are reviewed: attach each AVIT's Threatlint report
                                            to the task, comment on every AVIT's outcome, and close the task

The task is closed (Closed Complete) only when every AVIT it names has a TRUE POSITIVE or FALSE POSITIVE
verdict. Otherwise the comment is added and the task stays open, listing what still needs a decision.
Each AVIT's outcome and report are read back from the AVIT itself (its Threatlint work note and attached
Word report), so nothing is kept locally between the review and the close.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.parse

from threatlint import servicenow as sn
from threatlint import sctask_cli, sctask_text
from threatlint.finding_review import is_conservative, normalize_verdict
from threatlint.avit_resolve import AMBIGUOUS_COMMENT, CLOSING_COMMENT, TRUE_POSITIVE_COMMENT, ResolveError, _confirm, _false_positive_choices, _session
from threatlint.sctask_text import _SCTASK, closing_comment, parse_sctask_numbers
from threatlint.sctask_cli import add_sctask_parser

TABLE = "sc_task"
# Closed Complete; override for instances with a different choice list.
CLOSED_STATE = os.environ.get("THREATLINT_SNOW_SCTASK_CLOSED_STATE", "3")
REPORT_SUFFIX = "-threatlint-fp-review.docx"
REPORT_STEM = "-threatlint-fp-review"
ACCESS_HELP = ("The OAuth client needs read and write access to the sc_task table (and to sys_attachment for it). "
               "Ask the ServiceNow team to add sc_task to the client's ACLs.")


def avits_in(text: str) -> list[str]:
    """AVIT numbers in free text, in order of appearance, without duplicates."""
    return sctask_text.avits_in(text, sn._AVIT_PATTERN)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def fetch(instance: str, token: str, number: str) -> dict:
    query = urllib.parse.urlencode({"sysparm_query": f"number={number}", "sysparm_display_value": "all", "sysparm_limit": "1",
                                    "sysparm_fields": "sys_id,number,state,short_description,description,active"})
    rows = sn._request_json(f"{instance}/api/now/table/{TABLE}?{query}", headers=_auth(token)).get("result", [])
    if not rows:
        raise ResolveError(f"{number} was not found or is not readable. {ACCESS_HELP}")
    row = sn._flatten(rows[0])
    if not re.fullmatch(r"[0-9a-f]{32}", row.get("sys_id", "")):
        raise ResolveError(f"{number} returned an unexpected sys_id")
    return row


def avit_outcome(instance: str, token: str, avit: str) -> dict:
    """What Threatlint recorded on the AVIT: disposition (from its work note), state, and its report attachment."""
    query = urllib.parse.urlencode({"sysparm_query": f"number={avit}", "sysparm_display_value": "all", "sysparm_limit": "1",
                                    "sysparm_fields": "sys_id,number,state,work_notes"})
    rows = sn._request_json(f"{instance}/api/now/table/{sn.AVIT_TABLE}?{query}", headers=_auth(token)).get("result", [])
    if not rows:
        return {"avit": avit, "disposition": "NOT FOUND", "state": "", "report": None}
    row = sn._flatten(rows[0])
    notes = row.get("work_notes", "")
    disposition = sctask_text.journal_disposition(notes, (
        (CLOSING_COMMENT, "FALSE POSITIVE"),
        (TRUE_POSITIVE_COMMENT, "TRUE POSITIVE"),
        (AMBIGUOUS_COMMENT.split(".")[0], "AMBIGUOUS"),
    ))
    # A repeated headless review retains each report with a timestamped name.
    # Read the newest matching attachment, including the original fixed name.
    query = urllib.parse.urlencode({"sysparm_query": f"table_name={sn.AVIT_TABLE}^table_sys_id={row['sys_id']}^ORDERBYDESCsys_created_on",
                                    "sysparm_fields": "sys_id,file_name,sys_created_on", "sysparm_limit": "200"})
    attachments = sn._request_json(f"{instance}/api/now/attachment?{query}", headers=_auth(token)).get("result")
    if not isinstance(attachments, list):
        raise ResolveError(f"ServiceNow did not return a readable report attachment list for {avit}")
    valid_name = re.compile(rf"{re.escape(avit)}{re.escape(REPORT_STEM)}(?:-(\d{{8}}T\d{{12}}Z))?\.docx")
    reports = [(match.group(1) or "", item) for item in attachments if isinstance(item, dict)
               if (match := valid_name.fullmatch(str(item.get("file_name", ""))))
               and re.fullmatch(r"[0-9a-f]{32}", str(item.get("sys_id", "")))]
    latest = max(reports, key=lambda pair: pair[0])[1] if reports else None
    result = normalize_verdict({"avit": avit, "disposition": disposition, "state": row.get("state", ""),
                                "report": latest["sys_id"] if latest else None,
                                "report_name": latest["file_name"] if latest else None})
    if not result["disposition"]:  # Workflow states are not finding decisions.
        result["disposition"] = disposition
    if "CONSERVATIVE DEFAULT" in notes or "False positive was not proven beyond reasonable doubt" in notes:
        result["unverified"] = True
    return result


def _download(instance: str, token: str, attachment_id: str) -> bytes:
    import urllib.request  # noqa: PLC0415
    request = urllib.request.Request(f"{instance}/api/now/attachment/{attachment_id}/file", headers={**_auth(token), "Accept": "*/*"})
    with sn._OPENER.open(request, timeout=sn._HTTP_TIMEOUT_S) as response:  # noqa: S310 - HTTPS origin validated
        return response.read()


def close(instance: str, token: str, number: str, yes: bool, out=sys.stdout, leave_open: bool = False) -> dict:
    task = fetch(instance, token, number)
    avits = avits_in(task.get("description", "") + "\n" + task.get("short_description", ""))
    if not avits:
        raise ResolveError(f"{number} names no AVIT numbers in its description")
    outcomes = [avit_outcome(instance, token, avit) for avit in avits]
    closed_positives = [item["avit"] for item in outcomes if item["disposition"] == "TRUE POSITIVE"
                        and (str(item.get("state", "")).strip().lower().startswith("closed")
                             or str(item.get("state", "")).strip() == _false_positive_choices()[0])]
    if closed_positives:
        raise ResolveError(f"Cannot update {number}: true-positive AVITs {', '.join(closed_positives)} "
                           "remain closed in ServiceNow; verify or reopen them before updating the task")
    decided = sctask_text.all_decided(outcomes)
    missing_decided = [item["avit"] for item in outcomes
                       if item["disposition"] in ("TRUE POSITIVE", "FALSE POSITIVE") and not item["report"]]
    if missing_decided:
        raise ResolveError(f"Cannot update {number}: no readable Threatlint report is attached to "
                           f"{', '.join(missing_decided)}; attach the AVIT report before closing the task")
    closing = decided and not leave_open
    for item in outcomes:
        print(f"  {item['avit']} : {item['disposition']}{' · report attached' if item['report'] else ' · no Threatlint report'}", file=out)
    _confirm(f"{number}: attach {sum(bool(item['report']) for item in outcomes)} report(s), add the comment"
             f"{' and close the task' if closing else ' (the task stays open)'}?", yes)
    from threatlint.avit_resolve import _DOCX  # noqa: PLC0415
    query = urllib.parse.urlencode({"sysparm_query": f"table_name={TABLE}^table_sys_id={task['sys_id']}", "sysparm_fields": "file_name", "sysparm_limit": "200"})
    attached = sn._request_json(f"{instance}/api/now/attachment?{query}", headers=_auth(token)).get("result")
    if not isinstance(attached, list) or any(not isinstance(row, dict) for row in attached):
        raise ResolveError(f"ServiceNow did not return a readable attachment list for {number}")
    existing = {sn._field_value(row.get("file_name")) for row in attached}
    for item in outcomes:
        name = item.get("report_name") or f"{item['avit']}{REPORT_SUFFIX}"
        if not item["report"] or name in existing:
            continue
        upload = urllib.parse.urlencode({"table_name": TABLE, "table_sys_id": task["sys_id"], "file_name": name})
        sn._request_json(f"{instance}/api/now/attachment/file?{upload}", data=_download(instance, token, item["report"]),
                         headers={**_auth(token), "Content-Type": _DOCX})
        print(f"  ✓ Attached {name}", file=out)
    comment = closing_comment(outcomes, leave_open)
    values = {"comments": comment, "work_notes": comment}
    if closing:
        values.update({"state": CLOSED_STATE, "close_notes": comment})
    stored = sn._request_json(f"{instance}/api/now/table/{TABLE}/{task['sys_id']}?sysparm_fields=number,state", method="PATCH",
                              data=json.dumps(values).encode(), headers={**_auth(token), "Content-Type": "application/json"}).get("result", {}) or {}
    if closing:
        closed = str(stored.get("state")) == CLOSED_STATE
        print(f"  {'✓ Closed ' + number if closed else '! ServiceNow kept ' + number + ' in state ' + str(stored.get('state'))}", file=out)
    else:
        print(f"  ✓ Comment added; {number} left open{' (it can be closed)' if decided else ' until the remaining AVITs are decided'}", file=out)
    return {"sctask": number, "closed": closing, "avits": outcomes}


# ── CLI ───────────────────────────────────────────────────────────────────────

def cmd_sctask(args) -> int:
    return sctask_cli.cmd_sctask(
        args, session=_session, parse_numbers=parse_sctask_numbers, fetch=fetch, avits_in=avits_in, close=close,
    )
