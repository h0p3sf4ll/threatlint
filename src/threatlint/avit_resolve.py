"""Act on an FP review of AVITs: upload the report to ServiceNow, close false positives, and tune Semgrep.

`threatlint avit resolve <AVIT> --report report.md [--docx report.docx]` reads the AVIT's disposition
from the report the FP reviewer wrote and then:
  TRUE POSITIVE  -> attaches the Word report (prefixed with the AVIT number) and adds the work note
                    "True positive, see attached report."; stays open.
  FALSE POSITIVE -> attaches the Word report, closes the AVIT (state 3, substate 3) with the work note
                    "Closed by Threatlint as a false positive, see attached report.", and ignores the matching
                    open Semgrep finding(s) as false_positive (Code for SAST, Supply Chain for SCA, Secrets for Secrets).
  Legacy AMBIGUOUS decisions become conservative TRUE POSITIVE decisions with uncertainty retained;
                    they stay open, with Semgrep untouched and no claim of independent verification.
`threatlint avit note <AVIT> --message TEXT` adds a work note only (e.g. why an AVIT could not be reviewed).
Every write needs confirmation (--yes for non-interactive use). Tokens are used per run and never stored.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from pathlib import Path

from threatlint import one_pager, servicenow as sn, tuning_backlog
from threatlint import avit_cli, avit_repositories, avit_semgrep, avit_semgrep_triage
from threatlint.avit_cli import add_resolve_parsers, confirm as _confirm, session as _session
from threatlint.avit_repositories import checkout_branch as _checkout_branch, renamed_ado_repository, repository_removed
from threatlint.avit_report import ClosedAvitSemgrepError, ResolveError, RuleNotTuned, needs_confirmation, report_line as _report_line, verdict_for
from threatlint.finding_review import CONSERVATIVE_REASON, is_conservative
from threatlint.avit_semgrep import same_path as _same_path, tail as _tail

# Work notes, exactly as AppSec asked for them.
CLOSING_COMMENT = "Closed by Threatlint as a false positive, see attached report."
TRUE_POSITIVE_COMMENT = "True positive, see attached report."
UNVERIFIED_COMMENT = "Threatlint has not confirmed the scanner claim. See the report for the remaining evidence."
AMBIGUOUS_COMMENT = "Ambiguous, see attached report. Left open pending the evidence the report names."  # Legacy journal recognition only.
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


def attach(instance: str, token: str, sys_id: str, name: str, content: bytes, content_type: str,
           table: str = sn.AVIT_TABLE) -> str:
    query = urllib.parse.urlencode({"table_name": table, "table_sys_id": sys_id, "file_name": name})
    response = sn._request_json(f"{instance}/api/now/attachment/file?{query}", data=content,
                                headers={"Authorization": f"Bearer {token}", "Content-Type": content_type})
    result = response.get("result") if isinstance(response, dict) else None
    attachment_id = sn._field_value(result.get("sys_id")) if isinstance(result, dict) else ""
    if not re.fullmatch(r"[0-9a-f]{32}", attachment_id):
        raise ResolveError("ServiceNow did not confirm the new report attachment")
    return attachment_id


def report_family(number: str) -> re.Pattern[str]:
    """Every Threatlint report file for one AVIT or ticket number: the Word or Markdown report and its one-page summary.

    Covers AVIT reports ({AVIT}-threatlint-fp-review[-<timestamp>].docx) and Workbench reviews
    ({number}-threatlint-review-<fingerprint>.docx|.md). ServiceNow cannot overwrite an attachment,
    so a new report replaces this whole family by deletion before upload.
    """
    stem = rf"{re.escape(number)}-threatlint-(?:fp-review(?:-\d{{8}}T\d{{12}}Z)?|review-[0-9a-f]{{20}})"
    return re.compile(rf"{stem}\.(?:docx|md)|{re.escape(one_pager.PREFIX)}{stem}\.pdf")


def _report_attachments(instance: str, token: str, sys_id: str, number: str, table: str = sn.AVIT_TABLE) -> set[str]:
    """The IDs of earlier Threatlint reports for this number on this record; unrelated attachments are never listed."""
    family = report_family(number)
    reports: set[str] = set()
    limit = 200
    for offset in range(0, 2000, limit):
        query = urllib.parse.urlencode({
            "sysparm_query": f"table_name={table}^table_sys_id={sys_id}^file_nameLIKE{number}-threatlint-^ORDERBYsys_id",
            "sysparm_fields": "sys_id,file_name,table_name,table_sys_id", "sysparm_limit": str(limit), "sysparm_offset": str(offset),
        })
        response = sn._request_json(f"{instance}/api/now/attachment?{query}", headers={"Authorization": f"Bearer {token}"})
        rows = response.get("result") if isinstance(response, dict) else None
        if not isinstance(rows, list) or any(not isinstance(row, dict) or not sn._field_value(row.get("file_name")) for row in rows):
            raise ResolveError("ServiceNow did not return a readable attachment list")
        for row in rows:
            if not family.fullmatch(sn._field_value(row.get("file_name"))):
                continue
            attachment_id = sn._field_value(row.get("sys_id"))
            if (not re.fullmatch(r"[0-9a-f]{32}", attachment_id) or attachment_id in reports
                    or sn._field_value(row.get("table_name")) != table
                    or sn._field_value(row.get("table_sys_id")) != sys_id):
                raise ResolveError("ServiceNow did not identify a previous report on this record; no new report was uploaded")
            reports.add(attachment_id)
        if len(rows) < limit:
            return reports
    raise ResolveError("The attachment list exceeded the review limit; no new report was uploaded")


def replace_reports(instance: str, token: str, sys_id: str, number: str, files: list[tuple[str, bytes, str]], *,
                    table: str = sn.AVIT_TABLE, label: str = "", partial: str = "", out=None) -> dict[str, str]:
    """Delete every earlier Threatlint report for `number` on the record, confirm they are gone, then upload `files`.

    Nothing is uploaded unless the deletion is confirmed. Returns {file name: new attachment sys_id}.
    """
    label = label or number
    previous = _report_attachments(instance, token, sys_id, number, table)
    if previous:
        failure: Exception | None = None
        for attachment_id in sorted(previous):
            try:
                sn._request_json(f"{instance}/api/now/attachment/{attachment_id}", method="DELETE",
                                 headers={"Authorization": f"Bearer {token}"})
            except sn.ServiceNowError as exc:
                failure = exc  # A timed-out request may still have deleted it: the listing below decides.
        try:
            remaining = _report_attachments(instance, token, sys_id, number, table)
        except (ResolveError, sn.ServiceNowError) as exc:
            raise ResolveError(f"Could not confirm removal of the previous Threatlint report for {number} from {label}; "
                               f"no new report was uploaded. {exc}") from exc
        if remaining:
            raise ResolveError(f"Could not remove the previous Threatlint report for {number} from {label}; no new report was uploaded. "
                               f"{failure or 'ServiceNow still lists a previous report'}")
        print(f"  ✓ Removed {len(previous)} earlier Threatlint report file{'s' if len(previous) != 1 else ''} for {number}", file=out)
    attached: dict[str, str] = {}
    for index, (file_name, data, content_type) in enumerate(files):
        try:
            attached[file_name] = attach(instance, token, sys_id, file_name, data, content_type, table)
        except (ResolveError, sn.ServiceNowError) as exc:
            if index:
                raise ResolveError(f"The Word report for {number} was attached to {label}, but its one-page summary could not be confirmed; "
                                   f"{partial or 'run the step again to replace both.'} {exc}") from exc
            if previous:
                raise ResolveError(f"The previous Threatlint report for {number} was removed from {label}, but the replacement attachment could not be confirmed. {exc}") from exc
            raise
        print(f"  ✓ Attached {file_name}", file=out)
    return attached


def _replace_report(instance: str, token: str, sys_id: str, avit: str, name: str, content: bytes,
                    summary: bytes | None = None) -> None:
    """Replace earlier Threatlint reports and one-page summaries, then attach the Word report and its summary."""
    files = [(name, content, _DOCX)] + ([(one_pager.attachment_name(name), summary, one_pager.CONTENT_TYPE)] if summary is not None else [])
    replace_reports(instance, token, sys_id, avit, files,
                    partial="the AVIT state was not changed. Run resolve again to replace both.")


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


def _apply_semgrep_review(args, avit, markdown, context, token, dep, target, kind, matches, *, note, tune,
                          avit_closed=False) -> int:
    """Track finding triage and rule tuning separately. Only a proven no-write scope block can defer triage."""
    from threatlint import semgrep_platform as sp  # noqa: PLC0415

    scope_block = None
    if matches:
        for match in matches:
            print(f"    Semgrep #{match['id']} · {match['rule']} · {match['path']}:{match['line'] or '?'} · {match['ref'] or ''}")
        try:
            count = ignore_matches(token, dep, kind, matches, note)
        except avit_semgrep_triage.TriageScopeBlocked as exc:
            scope_block = exc
        else:
            print(f"  ✓ Semgrep ignored {count} finding(s) as false_positive; branch scope and stored IDs verified")
    else:
        product = {"secrets": "Secrets", "sca": "Supply Chain"}.get(kind, "Code")
        message = f"No open Semgrep {product} finding matches {context.get('file_path')}; finding triage unchanged"
        if avit_closed and getattr(args, "require_complete_semgrep", False):
            scope_block = avit_semgrep_triage.TriageScopeBlocked(f"Semgrep triage blocked: {message}")
        else:
            print(f"  ! {message}")

    if tune:
        try:
            if avit_closed and (blocker := _tuning_proposal_error(context, markdown)):
                _check_existing_tuning(args, markdown, avit, kind, context, token, dep, target, matches, blocker)
            _tune_verified_rule(args, markdown, avit, kind, context, token, dep, target, matches)
        except (sp.SemgrepError, sn.ServiceNowError, ResolveError, OSError) as exc:
            if getattr(exc, "tuning_write_uncertain", False):
                if scope_block:
                    print(f"  ! {scope_block}")
                raise ResolveError(f"Semgrep could not verify the rule update. {exc}") from exc
            if avit_closed:
                raise RuleNotTuned(str(exc), str(scope_block or "")) from exc
            if scope_block:
                print(f"  ! {scope_block}")
            print(f"  ! Rule not tuned: {exc}")
            return 1
    if scope_block:
        raise scope_block
    return int(not matches and getattr(args, "require_complete_semgrep", False))


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


@contextmanager
def _tuning_checkout(args, markdown: str, avit: str, context: dict[str, str], target: dict[str, str]):
    """Use the supplied checkout or fetch the exact AVIT branch before tuning."""
    from threatlint import runtime_env as rt  # noqa: PLC0415

    rule, path = context.get("rule", ""), context.get("file_path", "")
    if not rule or not path or Path(path).is_absolute():
        raise ResolveError("Rule tuning needs the AVIT rule and a repository-relative flagged file")
    line = int(context["line"]) if context.get("line", "").isdigit() else _report_line(markdown, avit, path)
    if not line or line < 1:
        raise ResolveError("Rule tuning needs the flagged line from the AVIT or report")
    with rt.temporary_repo(prefix="threatlint-tune-") as temporary:
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
        yield checkout, flagged, line


def _tune_verified_rule(args, markdown: str, avit: str, kind: str, context: dict[str, str],
                        token: str, dep: dict, target: dict[str, str], matches: list[dict]) -> None:
    from threatlint import semgrep_platform as sp  # noqa: PLC0415

    with _tuning_checkout(args, markdown, avit, context, target) as (_, flagged, line):
        sp.tune_rule(markdown, kind, context["rule"], str(flagged), line, token, {"id": dep["id"], "slug": dep["slug"]},
                     project=avit_semgrep.tuning_project(target, matches),
                     verified_finding=_verified_tuning_match(target, context, kind, line, matches),
                     **({"allow_live_shortcut": False} if context.get("snippet_match") == "semgrep" else {}))


def _tuning_proposal_error(context: dict[str, str], markdown: str) -> ResolveError | None:
    from threatlint.avit_tuning import require_proposal  # noqa: PLC0415

    try:
        require_proposal(context, markdown)
    except ResolveError as exc:
        return exc
    return None


def _check_existing_tuning(args, markdown, avit, kind, context, token, dep, target, matches, blocker) -> None:
    """Allow an incomplete proposal only when the exact source is covered by live tuning."""
    from threatlint import semgrep_platform as sp  # noqa: PLC0415
    from threatlint.avit_tuning import flagged_location  # noqa: PLC0415

    rule = context.get("rule", "")
    if rule and context.get("snippet_match") != "semgrep":
        active = sp.existing_tuning(token, {"id": dep["id"], "slug": dep["slug"]}, kind, rule,
                                    project=avit_semgrep.tuning_project(target, matches))
        if active:
            with _tuning_checkout(args, markdown, avit, context, target) as (checkout, _, _):
                flagged, line = flagged_location(checkout, context, markdown, avit)
                yaml = sp.original_rule_yaml(active[0]["tuned"], token)
                if sp.live_rule_matches(yaml, str(flagged), line) == []:
                    return
    raise blocker


def _semgrep_resolution(args, avit, context, kind, markdown):
    token = semgrep_token(args.aws_profile)
    target = sn.repository_target(context)
    dep, matches = semgrep_matches(token, kind, target, {**context, "avit": avit}, args.semgrep_deployment, markdown)
    return token, target, dep, matches


def _locate_scanner_snippet(record, args):
    """Repeat checkout-based location recovery against the fresh AVIT before write-back."""
    from threatlint.avit_tuning import confirm_snippet_match

    context = record["context"]
    if str(context.get("line", "")).isdigit() or not record.get("fields", {}).get("u_code_snippet"):
        return
    target = sn.repository_target(context)
    if not context.get("file_path") or not target.get("branch"):
        return

    def corroborate(repo):
        location = avit_repositories.scanner_snippet_location(record, repo, target)
        if location.get("line_blocker"):
            raise avit_semgrep_triage.TriageScopeBlocked(f"Semgrep triage blocked: {location['line_blocker']}")
        if location.get("line_source") == "scanner_snippet":
            location["snippet_match"] = confirm_snippet_match(context, repo / context["file_path"], int(location["line"]),
                                                             semgrep_token(args.aws_profile), getattr(args, "semgrep_deployment", None))
            context.update(location)

    checkout = getattr(args, "checkout", None)
    if checkout:
        corroborate(Path(checkout))
    else:
        from threatlint import runtime_env as rt

        with rt.temporary_repo(prefix="threatlint-avit-line-") as work:
            repo = Path(work) / "repo"
            sn.checkout_repository(target, str(repo), context["file_path"])
            corroborate(repo)


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
    instance, token = _session(args)
    record = _record(instance, token, avit)
    if getattr(args, "semgrep_rule_hash_id", None):
        record["context"]["rule_hash_id"] = args.semgrep_rule_hash_id
    code_security = sn.in_code_security_view(record)
    kind = sn.finding_kind(record)
    false_positive = verdict["disposition"] == "FALSE POSITIVE"
    name = getattr(args, "attachment_name", None) or f"{avit}-threatlint-fp-review.docx"
    report_name = re.compile(rf"{re.escape(avit)}-threatlint-fp-review(?:-\d{{8}}T\d{{12}}Z)?\.docx")
    if not report_name.fullmatch(name):
        raise ResolveError("The AVIT report attachment name is invalid")
    with open(os.path.expanduser(args.docx), "rb") as handle:
        content = handle.read()
    if not content.startswith(b"PK"):
        raise ResolveError("The new AVIT report is not a Word document")
    try:
        summary = one_pager.build(markdown, avit, verdict["id"])
    except Exception as exc:  # noqa: BLE001 - nothing is written without both attachments
        raise ResolveError(f"The one-page summary could not be generated; the AVIT was not changed. {exc}") from exc
    action = ("close it as Closed / False Positive" if false_positive
              else "add a TRUE POSITIVE work note (state unchanged)")
    _confirm(f"{avit}: replace any previous Threatlint report, attach this report and its one-page summary, and {action}?", args.yes)
    _replace_report(instance, token, record["sys_id"], avit, name, content, summary)
    note = CLOSING_COMMENT if false_positive else TRUE_POSITIVE_COMMENT
    if is_conservative(verdict):
        note += " " + CONSERVATIVE_REASON
    elif needs_confirmation(verdict, markdown):
        note += " " + UNVERIFIED_COMMENT
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
        if closed(state):
            print("  INFO: AVIT is already closed in ServiceNow; work note added and report attached.")
            return 0
        if not state:
            print(f"  ! Work note added and report attached, but AVIT open state could not be confirmed"
                  f" (previous {previous or 'unknown'}, stored {state or 'unknown'}); verify or reopen it")
            return 1
        print("  ✓ Work note added; AVIT left open")
    if false_positive and not code_security:
        print("  Semgrep not applicable: this AVIT is not a CodeSecurity finding")
    followup = lambda stage, reason, triage="": tuning_backlog.record(
        avit, stage, reason, context=record["context"], markdown=markdown, report_attachment=name, triage_reason=triage)
    if false_positive and getattr(args, "tuning_reason", ""):
        followup("tuning", args.tuning_reason)  # Tuning failed before write-back; the AVIT closed without it.
    if false_positive and code_security and not args.skip_semgrep:
        try:
            return _closed_semgrep(args, avit, markdown, record, kind, verdict)
        except RuleNotTuned as exc:
            followup("tuning", str(exc), exc.triage_reason)
            raise
        except avit_semgrep_triage.TriageScopeBlocked as exc:
            followup("triage", str(exc))
            raise
        except ClosedAvitSemgrepError as exc:
            followup("semgrep", str(exc))
            raise
    return 0


def _closed_semgrep(args, avit: str, markdown: str, record: dict, kind: str, verdict: dict) -> int:
    """Semgrep triage and rule tuning for a false positive whose AVIT is already closed with its report."""
    try:
        if kind in ("sast", "secrets"):
            _locate_scanner_snippet(record, args)
        sg_token, target, dep, matches = _semgrep_resolution(args, avit, record["context"], kind, markdown)
    except avit_semgrep_triage.TriageScopeBlocked as exc:
        if kind in ("sast", "secrets") and not args.skip_rule_tuning:
            raise RuleNotTuned("The scanner finding could not be identified for this AVIT.", str(exc)) from exc
        raise
    except (ResolveError, sn.ServiceNowError, OSError) as exc:
        hint = " The token's deployment may not scan this repository; pass --semgrep-deployment." if "HTTP 404" in str(exc) else ""
        raise ClosedAvitSemgrepError(f"Semgrep lookup failed: {exc}.{hint}") from exc
    kind = dep.get("product", kind)
    try:
        return _apply_semgrep_review(
            args, avit, markdown, record["context"], sg_token, dep, target, kind, matches,
            note=f"Closed by Threatlint as a false positive ({avit}, {verdict['id']}): {verdict['title']}",
            tune=kind in ("sast", "secrets") and not args.skip_rule_tuning, avit_closed=True,
        )
    except (RuleNotTuned, avit_semgrep_triage.TriageScopeBlocked):
        raise
    except (ResolveError, sn.ServiceNowError, OSError) as exc:
        raise ClosedAvitSemgrepError(str(exc)) from exc


def remove_checkout(path: str | None) -> bool:
    """Clean only a checkout created by Threatlint; preserve triage if its disk disappeared."""
    from threatlint.servicenow_checkout import remove_owned_checkout  # noqa: PLC0415
    return remove_owned_checkout(path)


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
    if kind in ("sast", "secrets"):
        _locate_scanner_snippet({**record, "context": context}, args)
    report_requested = bool(getattr(args, "report", None))
    markdown = ""
    if report_requested:
        with open(os.path.expanduser(args.report), encoding="utf-8") as handle:
            markdown = handle.read()
    sg_token, target, dep, matches = _semgrep_resolution(args, avit, context, kind, markdown)
    kind = dep.get("product", kind)
    tune_requested = report_requested and kind in ("sast", "secrets")
    if tune_requested:
        from threatlint import semgrep_platform as sp  # noqa: PLC0415

        blocker = _tuning_proposal_error(context, markdown)
        if blocker is not None:
            try:
                _check_existing_tuning(args, markdown, avit, kind, context, sg_token, dep, target, matches, blocker)
            except (sp.SemgrepError, sn.ServiceNowError, ResolveError, OSError) as exc:
                print(f"  ! Rule not tuned: {exc}. Semgrep was not changed.")
                return 1
    return _apply_semgrep_review(
        args, avit, markdown, context, sg_token, dep, target, kind, matches,
        note=f"Closed by Threatlint as a false positive ({avit}); see the report attached to the AVIT",
        tune=tune_requested,
    )


def run(handler, args) -> int:
    return avit_cli.run(handler, args, remove_checkout=remove_checkout)
