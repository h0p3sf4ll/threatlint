"""Act on an FP review of AVITs: upload the report to ServiceNow, close false positives, and tune Semgrep.

`threatlint avit resolve <AVIT> --report report.md [--docx report.docx]` reads the AVIT's disposition
from the report the FP reviewer wrote and then:
  TRUE POSITIVE  -> attaches the Word report (prefixed with the AVIT number) and adds the work note
                    "True positive, see attached report."; stays open.
  FALSE POSITIVE -> attaches the Word report, closes the AVIT (state 3, substate 3) with the work note
                    "Closed by Threatlint as a false positive, see attached report.", and ignores the matching
                    open Semgrep finding(s) as false_positive (Code for SAST, Supply Chain for SCA, Secrets for Secrets).
  AMBIGUOUS      -> attaches the Word report and adds the work note "Ambiguous, see attached report.
                    Left open pending the evidence the report names."; stays open, Semgrep untouched.
`threatlint avit note <AVIT> --message TEXT` adds a work note only (e.g. why an AVIT could not be reviewed).
Every write needs confirmation (--yes for non-interactive use). Tokens are used per run and never stored.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from threatlint import servicenow as sn
from threatlint import avit_cli, avit_repositories, avit_semgrep, avit_semgrep_triage
from threatlint.avit_cli import add_resolve_parsers, confirm as _confirm, session as _session
from threatlint.avit_repositories import checkout_branch as _checkout_branch, renamed_ado_repository, repository_removed
from threatlint.avit_report import ResolveError, report_line as _report_line, verdict_for
from threatlint.avit_semgrep import same_path as _same_path, tail as _tail

# Work notes, exactly as AppSec asked for them.
CLOSING_COMMENT = "Closed by Threatlint as a false positive, see attached report."
TRUE_POSITIVE_COMMENT = "True positive, see attached report."
AMBIGUOUS_COMMENT = "Ambiguous, see attached report. Left open pending the evidence the report names."
REPO_REMOVED_COMMENT = "Closed by Threatlint, repo removed."
# AVR Closed state / substate for a false positive (override with THREATLINT_SNOW_FP_STATE / _SUBSTATE).
CLOSED_STATE, CLOSED_SUBSTATE = "3", "3"
# semgrep.dev serves the same API as semgrep.app and resolves on networks that block semgrep.app.
SEMGREP_API = os.environ.get("THREATLINT_SEMGREP_API", "https://semgrep.dev").rstrip("/") + "/api/v1"
_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


# ── ServiceNow writes ────────────────────────────────────────────────────────

def _record(instance: str, token: str, avit: str) -> dict:
    query = urllib.parse.urlencode({"sysparm_query": f"number={avit}", "sysparm_display_value": "all", "sysparm_limit": "1"})
    rows = sn._request_json(f"{instance}/api/now/table/{sn.AVIT_TABLE}?{query}", headers={"Authorization": f"Bearer {token}"}).get("result", [])
    if not rows:
        raise ResolveError(f"{avit} was not found or is not readable by the OAuth client")
    row = rows[0]
    sys_id = sn._field_value(row.get("sys_id"))
    if not re.fullmatch(r"[0-9a-f]{32}", sys_id):
        raise ResolveError(f"{avit} returned an unexpected sys_id")
    fields = sn._flatten(row)
    members = sn.view_members(instance, token, [avit])
    return {"sys_id": sys_id, "fields": fields, "context": sn.avit_context(fields, sn.field_labels(instance, token)), "references": {},
            "in_view": None if members is None else avit in members}


def _false_positive_choices() -> tuple[str, str]:
    """Closed (3) / substate 3 on AVR; the OAuth client cannot read sys_choice, so values are fixed."""
    return os.environ.get("THREATLINT_SNOW_FP_STATE") or CLOSED_STATE, os.environ.get("THREATLINT_SNOW_FP_SUBSTATE") or CLOSED_SUBSTATE


def attach(instance: str, token: str, sys_id: str, name: str, content: bytes, content_type: str) -> None:
    query = urllib.parse.urlencode({"table_name": sn.AVIT_TABLE, "table_sys_id": sys_id, "file_name": name})
    sn._request_json(f"{instance}/api/now/attachment/file?{query}", data=content, headers={"Authorization": f"Bearer {token}", "Content-Type": content_type})


def attachment_names(instance: str, token: str, sys_id: str) -> set[str]:
    query = urllib.parse.urlencode({"sysparm_query": f"table_name={sn.AVIT_TABLE}^table_sys_id={sys_id}", "sysparm_fields": "file_name", "sysparm_limit": "200"})
    rows = sn._request_json(f"{instance}/api/now/attachment?{query}", headers={"Authorization": f"Bearer {token}"}).get("result")
    if not isinstance(rows, list) or any(not isinstance(row, dict) or not sn._field_value(row.get("file_name")) for row in rows):
        raise ResolveError("ServiceNow did not return a readable AVIT attachment list")
    return {sn._field_value(row["file_name"]) for row in rows}


def update(instance: str, token: str, sys_id: str, values: dict[str, str]) -> dict:
    result = sn._request_json(f"{instance}/api/now/table/{sn.AVIT_TABLE}/{sys_id}?sysparm_fields=number,state,substate", method="PATCH",
                              data=json.dumps(values).encode(), headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    return result.get("result", {}) or {}


# ── Semgrep ──────────────────────────────────────────────────────────────────

def semgrep_token(profile: str | None) -> str:
    """SEMGREP_APP_TOKEN, the token saved by `threatlint semgrep login`, or Parameter Store."""
    from threatlint.semgrep_platform import SemgrepError, resolve_token  # noqa: PLC0415
    try:
        return resolve_token(profile)[0]
    except SemgrepError as exc:
        raise ResolveError(str(exc)) from exc


def _semgrep(path: str, token: str, *, body: dict | None = None) -> dict:
    return avit_semgrep.request(path, token, body=body, api=SEMGREP_API)


def semgrep_matches(token: str, kind: str, target: dict[str, str], context: dict[str, str], deployment: str | None = None,
                    report_text: str = "") -> tuple[dict, list[dict]]:
    """Open Semgrep findings for the same project, file, and rule/line as the AVIT."""
    return avit_semgrep.semgrep_matches(
        token, kind, target, context, deployment, report_text, query=_semgrep,
        report_line=_report_line, same_path=_same_path,
    )


def semgrep_ignore(token: str, slug: str, kind: str, ids: list[int], note: str, *,
                   repository: str = "", ref: str = "", rule: str = "", deployment_id=None) -> int:
    return avit_semgrep_triage.ignore(
        token, slug, kind, ids, note, repository=repository, ref=ref, rule=rule,
        deployment_id=deployment_id, query=_semgrep,
    )


def ignore_matches(token, dep, kind, matches, note) -> int:
    scopes = {(match.get("project"), match.get("ref"), match.get("rule"), match.get("product")) for match in matches}
    if len(scopes) != 1 or any(not part for part in next(iter(scopes))):
        raise ResolveError("Semgrep matches do not share one verified repository, branch, rule, and product")
    repository, ref, rule, product = next(iter(scopes))
    if product != kind:
        raise ResolveError("Semgrep triage product differs from the verified matches")
    return semgrep_ignore(token, dep["slug"], product, [match["id"] for match in matches], note,
                          repository=repository, ref=ref, rule=rule, deployment_id=dep["id"])


def _verified_tuning_match(target: dict[str, str], context: dict[str, str], kind: str,
                           line: int, matches: list[dict]) -> bool:
    """Require a current exact Semgrep finding before inferring Unified ruleset membership."""
    project = avit_semgrep.project_names(target)[0]
    return any(match.get("status") == "open" and match.get("product") == kind
               and match.get("project") == project and match.get("ref") == target.get("branch")
               and match.get("rule") == context.get("rule")
               and _same_path(str(match.get("path", "")), context.get("file_path", ""))
               and str(match.get("line", "")).isdigit() and int(match["line"]) == line
               for match in matches)


def _tune_verified_rule(args, markdown: str, avit: str, kind: str, context: dict[str, str],
                        token: str, dep: dict, target: dict[str, str], matches: list[dict]) -> None:
    """Use the supplied checkout or fetch the exact AVIT branch before tuning."""
    from threatlint import semgrep_platform as sp  # noqa: PLC0415
    from threatlint import runtime_env as rt  # noqa: PLC0415

    rule, path = context.get("rule", ""), context.get("file_path", "")
    if not rule or not path or Path(path).is_absolute():
        raise ResolveError("Rule tuning needs the AVIT rule and a repository-relative flagged file")
    line = int(context["line"]) if context.get("line", "").isdigit() else _report_line(markdown, avit)
    if not line or line < 1:
        raise ResolveError("Rule tuning needs the flagged line from the AVIT or report")
    with tempfile.TemporaryDirectory(prefix="threatlint-tune-", dir=rt.repo_store_base()) as temporary:
        checkout = Path(getattr(args, "checkout", "") or temporary).expanduser().resolve()
        flagged = (checkout / path).resolve()
        if not flagged.is_relative_to(checkout):
            raise ResolveError("The AVIT flagged path escapes the repository checkout")
        if not flagged.is_file():
            checkout = Path(temporary) / "repo"
            sn.checkout_repository(target, str(checkout), path)
            flagged = (checkout / path).resolve()
            if not flagged.is_relative_to(checkout.resolve()) or not flagged.is_file():
                raise ResolveError("The flagged file is unavailable on the AVIT branch after checkout")
            print(f"  ✓ Checked out the AVIT branch for Semgrep rule validation: {target.get('branch') or '(default)'}")
        sp.tune_rule(markdown, kind, rule, str(flagged), line, token, {"id": dep["id"], "slug": dep["slug"]},
                     project=avit_semgrep.tuning_project(target, matches),
                     verified_finding=_verified_tuning_match(target, context, kind, line, matches))


# ── CLI ──────────────────────────────────────────────────────────────────────

def cmd_checkout(args) -> int:
    return avit_repositories.cmd_checkout(
        args, session=_session, read_record=_record, checkout_branch=_checkout_branch,
        renamed_repository=renamed_ado_repository,
    )


def cmd_note(args) -> int:
    [avit] = sn.parse_avit_numbers(args.number)
    message = args.message.strip()
    if not message or len(message) > 4000:
        raise ResolveError("The work note must be 1 to 4000 characters")
    instance, token = _session(args)
    record = _record(instance, token, avit)
    _confirm(f"{avit}: add the work note?", args.yes)
    update(instance, token, record["sys_id"], {"work_notes": message})
    print(f"  ✓ Work note added to {avit}; state unchanged")
    return 0


def cmd_close_removed(args) -> int:
    [avit] = sn.parse_avit_numbers(args.number)
    instance, token = _session(args)
    record = _record(instance, token, avit)
    target = sn.repository_target(record["context"])
    if not repository_removed(target):
        raise ResolveError(f"{target['name']} still exists in {target['organization']}; review the AVIT instead of closing it")
    if renamed_ado_repository(target, args):
        raise ResolveError(f"{target['name']} was renamed, not removed; review the AVIT on the renamed repository")
    _confirm(f"{avit}: {target['name']} no longer exists in {target['organization']}. Close the AVIT?", args.yes)
    state, substate = _false_positive_choices()
    stored = update(instance, token, record["sys_id"], {"state": state, "work_notes": REPO_REMOVED_COMMENT, "close_notes": REPO_REMOVED_COMMENT})
    closed = str(stored.get("state")) == str(state)
    print(f"  {'✓ Closed ' + avit + ': repository ' + target['name'] + ' removed' if closed else '! ServiceNow kept state ' + str(stored.get('state'))}")
    return 0 if closed else 1


def cmd_resolve(args) -> int:
    [avit] = sn.parse_avit_numbers(args.number)
    with open(os.path.expanduser(args.report), encoding="utf-8") as handle:
        markdown = handle.read()
    verdict = verdict_for(markdown, avit)
    print(f"  {avit} : {verdict['id']} · {verdict['disposition']} ({verdict['confidence'] or 'confidence not stated'}) · {verdict['title']}")
    ambiguous = verdict["disposition"] == "AMBIGUOUS"
    instance, token = _session(args)
    record = _record(instance, token, avit)
    if getattr(args, "semgrep_rule_hash_id", None):
        record["context"]["rule_hash_id"] = args.semgrep_rule_hash_id
    code_security = sn.in_code_security_view(record)
    kind = sn.finding_kind(record)
    false_positive = verdict["disposition"] == "FALSE POSITIVE"
    # One attachment: the Word report. A headless repeat review uses a unique
    # timestamped name so the new evidence is kept alongside the earlier review.
    name = getattr(args, "attachment_name", None) or f"{avit}-threatlint-fp-review.docx"
    if not re.fullmatch(rf"{re.escape(avit)}-threatlint-fp-review(?:-\d{{8}}T\d{{12}}Z)?\.docx", name):
        raise ResolveError("The AVIT report attachment name is invalid")
    with open(os.path.expanduser(args.docx), "rb") as handle:
        files = [(name, handle.read(), _DOCX)]
    action = ("attach the report and close it as Closed / False Positive" if false_positive
              else "attach the report and add an AMBIGUOUS work note (it stays open)" if ambiguous
              else "attach the report and add a TRUE POSITIVE work note (it stays open)")
    _confirm(f"{avit}: {action}?", args.yes)
    # Attach first so the AVIT is never closed without its evidence.
    existing = attachment_names(instance, token, record["sys_id"])
    for name, content, content_type in files:
        if name in existing:
            print(f"  ✓ {name} is already attached")
            continue
        attach(instance, token, record["sys_id"], name, content, content_type)
        print(f"  ✓ Attached {name}")
    note = CLOSING_COMMENT if false_positive else AMBIGUOUS_COMMENT if ambiguous else TRUE_POSITIVE_COMMENT
    values = {"work_notes": note}
    if false_positive:
        state, substate = _false_positive_choices()
        values.update({"state": state, "substate": substate, "close_notes": note})
    stored = update(instance, token, record["sys_id"], values)
    if false_positive:
        # The state decides whether it closed; AVR business rules may clear the substate, which is reported, not failed.
        closed = str(stored.get("state")) == str(values["state"])
        substate_note = "" if str(stored.get("substate")) == str(values["substate"]) else f" (ServiceNow stored substate {stored.get('substate') or 'blank'}, not {values['substate']})"
        print(f"  {'✓ Closed as false positive' + substate_note if closed else '! ServiceNow kept state ' + str(stored.get('state')) + ' / ' + str(stored.get('substate')) + ' (pending approval?)'}")
        if not closed:
            return 1
    else:
        state = sn._field_value(stored.get("state"))
        previous = record["fields"].get("state", "")
        closed_state = _false_positive_choices()[0]
        closed = lambda value: value == closed_state or value.lower().startswith("closed")
        if not state or closed(state):
            print(f"  ! Work note added and report attached, but AVIT open state could not be confirmed"
                  f" (previous {previous or 'unknown'}, stored {state or 'unknown'}); verify or reopen it")
            return 1
        print("  ✓ Work note added; AVIT left open")
    if false_positive and not code_security:
        print("  Semgrep not applicable: this AVIT is not a CodeSecurity finding")
    if false_positive and code_security and not args.skip_semgrep:
        sg_token = semgrep_token(args.aws_profile)
        target = sn.repository_target(record["context"])
        try:
            dep, matches = semgrep_matches(sg_token, kind, target, {**record["context"], "avit": avit}, args.semgrep_deployment, markdown)
        except ResolveError as exc:
            # The AVIT stays closed; exit non-zero so callers (queue, CI) see that Semgrep was not updated.
            # Only a 404 points at the deployment; other failures (ambiguous match, missing line) say what to fix.
            hint = " The token's deployment may not scan this repository; pass --semgrep-deployment." if "HTTP 404" in str(exc) else ""
            print(f"  ! Semgrep unchanged: {exc}.{hint}")
            return 1
        kind = dep.get("product", kind)
        unmatched = not matches
        if not matches:
            print(f"  ! No open Semgrep {({'secrets': 'Secrets', 'sca': 'Supply Chain'}).get(kind, 'Code')} finding matches {record['context'].get('file_path')}; finding triage unchanged")
        else:
            for match in matches:
                print(f"    Semgrep #{match['id']} · {match['rule']} · {match['path']}:{match['line'] or '?'} · {match['ref'] or ''}")
            count = ignore_matches(sg_token, dep, kind, matches, f"Closed by Threatlint as a false positive ({avit}, {verdict['id']}): {verdict['title']}")
            print(f"  ✓ Semgrep ignored {count} finding(s) as false_positive; branch scope and stored IDs verified")
        # SAST and Secrets: replace the rule with the reviewer's tuned rule so the same false positive does not return.
        if kind in ("sast", "secrets") and not args.skip_rule_tuning:
            from threatlint import semgrep_platform as sp  # noqa: PLC0415
            try:
                _tune_verified_rule(args, markdown, avit, kind, record["context"], sg_token, dep, target, matches)
            except (sp.SemgrepError, sn.ServiceNowError, ResolveError) as exc:
                print(f"  ! Rule not tuned: {exc}")
                return 1
        if unmatched and getattr(args, "require_complete_semgrep", False):
            return 1
    return 0


def remove_checkout(path: str | None) -> bool:
    """Delete the AVIT checkout once triage and validation are done; read-only git objects are made writable first."""
    if not path or not os.path.isdir(path) or not os.path.isdir(os.path.join(path, ".git")):
        return False
    import shutil  # noqa: PLC0415
    import stat  # noqa: PLC0415

    def writable(function, target, _info):
        os.chmod(target, stat.S_IWRITE)
        function(target)
    shutil.rmtree(path, onerror=writable)  # onerror: Windows marks git pack files read-only
    return True


def cmd_semgrep(args) -> int:
    """Re-run only the Semgrep triage for an AVIT that Threatlint already closed as a false positive."""
    [avit] = sn.parse_avit_numbers(args.number)
    instance, token = _session(args)
    record = _record(instance, token, avit)
    notes = record["fields"].get("work_notes", "") + "\n" + record["fields"].get("close_notes", "")
    if record["fields"].get("state", "").lower() != "closed" or "Closed by Threatlint as a false positive" not in notes:
        raise ResolveError(f"{avit} is not closed as a false positive by Threatlint; run `avit resolve` with a report instead")
    kind = sn.finding_kind(record)
    context = dict(record["context"])
    if getattr(args, "semgrep_rule_hash_id", None):
        context["rule_hash_id"] = args.semgrep_rule_hash_id
    if args.line:
        context["line"] = str(args.line)
    markdown = ""
    if getattr(args, "report", None):
        with open(os.path.expanduser(args.report), encoding="utf-8") as handle:
            markdown = handle.read()
    sg_token = semgrep_token(args.aws_profile)
    target = sn.repository_target(context)
    dep, matches = semgrep_matches(sg_token, kind, target, {**context, "avit": avit}, args.semgrep_deployment, markdown)
    kind = dep.get("product", kind)
    if not matches:
        print(f"  ! No open Semgrep finding matches {context.get('file_path')}{':' + context['line'] if context.get('line') else ''}; Semgrep triage unchanged")
    else:
        for match in matches:
            print(f"    Semgrep #{match['id']} · {match['rule']} · {match['path']}:{match['line'] or '?'} · {match['ref'] or ''}")
        count = ignore_matches(sg_token, dep, kind, matches, f"Closed by Threatlint as a false positive ({avit}); see the report attached to the AVIT")
        print(f"  ✓ Semgrep ignored {count} finding(s) as false_positive; branch scope and stored IDs verified")
    if markdown and kind in ("sast", "secrets"):
        from threatlint import semgrep_platform as sp  # noqa: PLC0415
        try:
            _tune_verified_rule(args, markdown, avit, kind, context, sg_token, dep, target, matches)
        except (sp.SemgrepError, sn.ServiceNowError, ResolveError) as exc:
            print(f"  ! Rule not tuned: {exc}")
            return 1
    return 0


def run(handler, args) -> int:
    return avit_cli.run(handler, args, remove_checkout=remove_checkout)
