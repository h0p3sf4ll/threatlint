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
from threatlint.avit_resolve import AMBIGUOUS_COMMENT, CLOSING_COMMENT, TRUE_POSITIVE_COMMENT, ResolveError, _confirm, _session

TABLE = "sc_task"
_SCTASK = re.compile(r"SCTASK\d{7,10}")
# Closed Complete; override for instances with a different choice list.
CLOSED_STATE = os.environ.get("THREATLINT_SNOW_SCTASK_CLOSED_STATE", "3")
REPORT_SUFFIX = "-threatlint-fp-review.docx"
ACCESS_HELP = ("The OAuth client needs read and write access to the sc_task table (and to sys_attachment for it). "
               "Ask the ServiceNow team to add sc_task to the client's ACLs.")


def parse_sctask_numbers(text: str) -> list[str]:
    return list(dict.fromkeys(_SCTASK.findall(str(text or "").upper())))


def avits_in(text: str) -> list[str]:
    """AVIT numbers in free text, in order of appearance, without duplicates."""
    return list(dict.fromkeys(sn._AVIT_PATTERN.findall(str(text or "").upper())))


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
    # The journal lists the newest entry first, so the earliest match is the latest verdict.
    found = sorted((notes.find(text), label) for text, label in ((CLOSING_COMMENT, "FALSE POSITIVE"), (TRUE_POSITIVE_COMMENT, "TRUE POSITIVE"),
                                                                 (AMBIGUOUS_COMMENT.split(".")[0], "AMBIGUOUS")) if text in notes)
    query = urllib.parse.urlencode({"sysparm_query": f"table_name={sn.AVIT_TABLE}^table_sys_id={row['sys_id']}^file_name={avit}{REPORT_SUFFIX}",
                                    "sysparm_fields": "sys_id,file_name", "sysparm_limit": "1"})
    attachments = sn._request_json(f"{instance}/api/now/attachment?{query}", headers=_auth(token)).get("result", [])
    return {"avit": avit, "disposition": found[0][1] if found else "NOT REVIEWED", "state": row.get("state", ""),
            "report": attachments[0]["sys_id"] if attachments else None}


def _download(instance: str, token: str, attachment_id: str) -> bytes:
    import urllib.request  # noqa: PLC0415
    request = urllib.request.Request(f"{instance}/api/now/attachment/{attachment_id}/file", headers={**_auth(token), "Accept": "*/*"})
    with sn._OPENER.open(request, timeout=sn._HTTP_TIMEOUT_S) as response:  # noqa: S310 - HTTPS origin validated
        return response.read()


def closing_comment(outcomes: list[dict]) -> str:
    """The comment developers see on the task: one line per AVIT, then where to go next."""
    lines = ["Closed by Threatlint. Each AVIT below was reviewed against its repository and branch, and its report is attached to this task.", ""]
    for item in outcomes:
        lines.append({
            "FALSE POSITIVE": f"- {item['avit']}: false positive, closed by Threatlint.",
            "TRUE POSITIVE": f"- {item['avit']}: true positive, still open. Please remediate it in {item['avit']}.",
            "AMBIGUOUS": f"- {item['avit']}: could not be decided from the code; left open for AppSec follow-up (see its report).",
        }.get(item["disposition"], f"- {item['avit']}: not reviewed ({item['disposition'].lower()}); left open for AppSec follow-up."))
    true_positives = [item["avit"] for item in outcomes if item["disposition"] == "TRUE POSITIVE"]
    lines.append("")
    if true_positives:
        lines.append(f"Developers: {', '.join(true_positives)} {'is a confirmed finding' if len(true_positives) == 1 else 'are confirmed findings'} "
                     "and must be fixed in the AVIT itself. Each attached report gives the evidence, the proposed fix and the acceptance criteria.")
    lines.append("If you have questions about any decision, review the attached report for that AVIT first, then contact Application Security.")
    return "\n".join(lines)


def close(instance: str, token: str, number: str, yes: bool, out=sys.stdout) -> dict:
    task = fetch(instance, token, number)
    avits = avits_in(task.get("description", "") + "\n" + task.get("short_description", ""))
    if not avits:
        raise ResolveError(f"{number} names no AVIT numbers in its description")
    outcomes = [avit_outcome(instance, token, avit) for avit in avits]
    decided = all(item["disposition"] in ("TRUE POSITIVE", "FALSE POSITIVE") for item in outcomes)
    for item in outcomes:
        print(f"  {item['avit']} : {item['disposition']}{' · report attached' if item['report'] else ' · no Threatlint report'}", file=out)
    _confirm(f"{number}: attach {sum(bool(item['report']) for item in outcomes)} report(s), add the comment"
             f"{' and close the task' if decided else ' (left open: not every AVIT is decided)'}?", yes)
    from threatlint.avit_resolve import _DOCX  # noqa: PLC0415
    query = urllib.parse.urlencode({"sysparm_query": f"table_name={TABLE}^table_sys_id={task['sys_id']}", "sysparm_fields": "file_name", "sysparm_limit": "200"})
    existing = {row.get("file_name") for row in sn._request_json(f"{instance}/api/now/attachment?{query}", headers=_auth(token)).get("result", [])}
    for item in outcomes:
        name = f"{item['avit']}{REPORT_SUFFIX}"
        if not item["report"] or name in existing:
            continue
        upload = urllib.parse.urlencode({"table_name": TABLE, "table_sys_id": task["sys_id"], "file_name": name})
        sn._request_json(f"{instance}/api/now/attachment/file?{upload}", data=_download(instance, token, item["report"]),
                         headers={**_auth(token), "Content-Type": _DOCX})
        print(f"  ✓ Attached {name}", file=out)
    comment = closing_comment(outcomes)
    values = {"comments": comment, "work_notes": comment}
    if decided:
        values.update({"state": CLOSED_STATE, "close_notes": comment})
    stored = sn._request_json(f"{instance}/api/now/table/{TABLE}/{task['sys_id']}?sysparm_fields=number,state", method="PATCH",
                              data=json.dumps(values).encode(), headers={**_auth(token), "Content-Type": "application/json"}).get("result", {}) or {}
    if decided:
        closed = str(stored.get("state")) == CLOSED_STATE
        print(f"  {'✓ Closed ' + number if closed else '! ServiceNow kept ' + number + ' in state ' + str(stored.get('state'))}", file=out)
    else:
        print(f"  ✓ Comment added; {number} left open until the remaining AVITs are decided", file=out)
    return {"sctask": number, "closed": decided, "avits": outcomes}


# ── CLI ───────────────────────────────────────────────────────────────────────

def add_sctask_parser(sub) -> None:
    p = sub.add_parser("sctask", help="Review the AVITs named in a ServiceNow catalog task (SCTASK) and close it")
    actions = p.add_subparsers(dest="sctask_command", required=True)
    for name, text in (("avits", "List the AVIT numbers in the task's description"), ("close", "Attach each AVIT's report, comment, and close the task")):
        action = actions.add_parser(name, help=text)
        action.add_argument("number", metavar="SCTASK")
        sn.add_avit_arguments(action)
        if name == "close":
            action.add_argument("--yes", action="store_true", help="Apply without prompting")


def cmd_sctask(args) -> int:
    try:
        numbers = parse_sctask_numbers(args.number)
        if len(numbers) != 1:
            raise ResolveError(f"Not an SCTASK number: {args.number} (expected e.g. SCTASK14120565)")
        instance, token = _session(args)
        if args.sctask_command == "avits":
            task = fetch(instance, token, numbers[0])
            avits = avits_in(task.get("description", "") + "\n" + task.get("short_description", ""))
            for avit in avits:
                print(avit)
            print(json.dumps({"sctask": numbers[0], "state": task.get("state", ""), "avits": avits}))
            return 0 if avits else 1
        close(instance, token, numbers[0], args.yes)
        return 0
    except (ResolveError, sn.ServiceNowError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
