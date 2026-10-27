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
import urllib.error
import urllib.parse
import urllib.request

from threatlint import servicenow as sn

# Work notes, exactly as AppSec asked for them.
CLOSING_COMMENT = "Closed by Threatlint as a false positive, see attached report."
TRUE_POSITIVE_COMMENT = "True positive, see attached report."
AMBIGUOUS_COMMENT = "Ambiguous, see attached report. Left open pending the evidence the report names."
# AVR Closed state / substate for a false positive (override with THREATLINT_SNOW_FP_STATE / _SUBSTATE).
CLOSED_STATE, CLOSED_SUBSTATE = "3", "3"
# semgrep.dev serves the same API as semgrep.app and resolves on networks that block semgrep.app.
SEMGREP_API = os.environ.get("THREATLINT_SEMGREP_API", "https://semgrep.dev").rstrip("/") + "/api/v1"
_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
_DISPOSITION = re.compile(r"TRUE POSITIVE|FALSE POSITIVE|AMBIGUOUS", re.IGNORECASE)


class ResolveError(RuntimeError):
    """A user-actionable failure; messages never contain credential values."""


# ── Report parsing ───────────────────────────────────────────────────────────

def verdict_for(report: str, avit: str) -> dict[str, str]:
    """The finding in an FP report whose Original finding names this AVIT: id, title, disposition, confidence."""
    sections = re.split(r"(?m)^#{2,6}\s+(?=\[[A-Z][A-Z0-9]*-\d+\])", report)
    matches = []
    for section in sections[1:]:
        header, _, body = section.partition("\n")
        original = re.search(r"(?im)^\**Original finding\**\s*:\s*(.+)$", body)
        if avit not in (original.group(1) if original else header).upper():
            continue
        def field(name: str) -> str:
            match = re.search(rf"(?im)^\**(?:{name})\**\s*:\s*(.+)$", body)
            return match.group(1).replace("*", "").strip() if match else ""
        disposition = _DISPOSITION.search(field("Disposition|Verdict"))
        identifier = re.match(r"\[([A-Z][A-Z0-9]*-\d+)\]", header)
        matches.append({"id": identifier.group(1) if identifier else "", "title": re.sub(r"^\[[^\]]+\]\s*[—–:-]?\s*", "", header).strip(),
                        "disposition": disposition.group(0).upper() if disposition else "", "confidence": field("Confidence").split()[0] if field("Confidence") else ""})
    if not matches:
        raise ResolveError(f"The report has no finding whose Original finding is {avit}")
    if len({match["disposition"] for match in matches}) > 1:
        raise ResolveError(f"The report gives {avit} conflicting dispositions; resolve it manually")
    if not matches[0]["disposition"]:
        raise ResolveError(f"{matches[0]['id'] or avit} has no TRUE POSITIVE / FALSE POSITIVE / AMBIGUOUS disposition")
    return matches[0]


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
    try:
        rows = sn._request_json(f"{instance}/api/now/attachment?{query}", headers={"Authorization": f"Bearer {token}"}).get("result", [])
    except sn.ServiceNowError:
        return set()
    return {str(row.get("file_name", "")) for row in rows if isinstance(row, dict)}


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
    request = urllib.request.Request(f"{SEMGREP_API}{path}", data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {token}", "Accept": "application/json", **({"Content-Type": "application/json"} if body is not None else {})})
    try:
        with sn._OPENER.open(request, timeout=120) as response:  # noqa: S310 - fixed HTTPS host, redirects refused
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        hint = {401: " Check the Semgrep token.", 403: " The token needs Web API scope.", 404: " Check the deployment and project."}.get(exc.code, "")
        raise ResolveError(f"Semgrep returned HTTP {exc.code}.{hint}") from exc
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise ResolveError(f"Semgrep request failed: {exc}") from exc


def _tail(value: str) -> str:
    return str(value or "").replace("\\", "/").lstrip("./")


def _same_path(found: str, wanted: str) -> bool:
    a, b = _tail(found), _tail(wanted)
    return bool(a and b) and (a == b or a.endswith("/" + b) or b.endswith("/" + a))


def semgrep_matches(token: str, kind: str, target: dict[str, str], context: dict[str, str], deployment: str | None = None,
                    report_text: str = "") -> tuple[dict, list[dict]]:
    """Open Semgrep findings for the same project, file, and rule/line as the AVIT."""
    from threatlint.semgrep_platform import deployment as find_deployment, SemgrepError  # noqa: PLC0415
    try:
        dep = find_deployment(token, deployment or "")
    except SemgrepError as exc:
        raise ResolveError(str(exc)) from exc
    path, line, rule = context.get("file_path", ""), context.get("line", ""), context.get("rule", "")
    if not path:
        raise ResolveError("The AVIT has no File Path, so its Semgrep finding cannot be matched narrowly")
    # Semgrep names ADO projects "{Project}/{Repository}" and GitHub ones "{owner}/{repo}".
    named = list(dict.fromkeys(name for name in (f"{target.get('project')}/{target['name']}" if target.get("project") else "",
                                                 f"{target.get('organization')}/{target['name']}") if name and not name.startswith("/")))
    if not line.isdigit():
        line = _report_line(report_text, context.get("avit", "")) if report_text else None
        line = str(line) if line else ""
    if not line.isdigit():
        # Without a line the match would cover every finding of the rule in the file, including real ones.
        raise ResolveError("Neither the AVIT nor the report records the flagged line, so the Semgrep finding cannot be matched narrowly; pass --line")
    near = lambda found: found is not None and abs(int(found) - int(line)) <= 3
    matches = []
    if kind in ("sast", "sca"):
        for project in named:
            for page in range(20):
                query = urllib.parse.urlencode({"issue_type": kind, "repos": project, "status": "open", "dedup": "true", "page": page, "page_size": 100})
                findings = _semgrep(f"/deployments/{urllib.parse.quote(dep['slug'])}/findings?{query}", token).get("findings", [])
                for finding in findings:
                    name = str(finding.get("rule_name") or (finding.get("rule") or {}).get("name", ""))
                    location = finding.get("location") or {}
                    if rule and not (name == rule or name.endswith("." + rule) or rule.endswith("." + name)):
                        continue
                    if _same_path(location.get("file_path", ""), path) and near(location.get("line")):
                        matches.append({"id": int(finding["id"]), "rule": name, "path": location.get("file_path"), "line": location.get("line"), "ref": finding.get("ref")})
                if len(findings) < 100:
                    break
            if matches:
                break
    else:
        cursor = ""
        for _ in range(20):
            query = urllib.parse.urlencode({"limit": 100, **({"cursor": cursor} if cursor else {}), **{"repo": named[0]}})
            data = _semgrep(f"/deployments/{dep['id']}/secrets?{query}", token)
            for finding in data.get("findings", []):
                found_path, _, found_line = str(finding.get("findingPath", "")).rpartition(":")
                if not found_path:
                    found_path, found_line = finding.get("findingPath", ""), ""
                status = str(finding.get("status", ""))
                if any(word in status for word in ("FIXED", "IGNORED", "REMOVED")):
                    continue
                if _same_path(found_path, path) and near(found_line or None):
                    matches.append({"id": int(finding["id"]), "rule": finding.get("type"), "path": found_path, "line": found_line or None, "ref": finding.get("ref")})
            cursor = data.get("cursor") or ""
            if not cursor or not data.get("findings"):
                break
    return dep, matches


def semgrep_ignore(token: str, slug: str, kind: str, ids: list[int], note: str) -> int:
    body = {"issue_type": kind, "issue_ids": sorted(set(ids)), "new_triage_state": "ignored", "new_triage_reason": "false_positive", "new_note": note[:3000]}
    return int(_semgrep(f"/deployments/{urllib.parse.quote(slug)}/triage", token, body=body).get("num_triaged", 0))


# ── CLI ──────────────────────────────────────────────────────────────────────

def add_resolve_parsers(actions) -> None:
    checkout = actions.add_parser("checkout", help="Clone the repository and branch named in the AVIT (SCM Tool, Organization, Project, Repository, Branch)")
    checkout.add_argument("number", metavar="AVIT")
    checkout.add_argument("--dir", required=True, help="Empty directory to clone into")
    sn.add_avit_arguments(checkout)
    semgrep = actions.add_parser("semgrep", help="Re-run the Semgrep triage for an AVIT already closed as a false positive by Threatlint")
    semgrep.add_argument("number", metavar="AVIT")
    semgrep.add_argument("--line", type=int, help="Flagged line, when the AVIT does not record one (narrows the match to ±3 lines)")
    semgrep.add_argument("--semgrep-deployment", help="Semgrep deployment ID or slug (default: THREATLINT_SEMGREP_DEPLOYMENT, org.json, or the token's only deployment)")
    semgrep.add_argument("--report", help="FP report with a **Tuned rule** block: also tune the rule (SAST/Secrets)")
    semgrep.add_argument("--checkout", help="The AVIT checkout, to validate the tuned rule against the flagged file (deleted afterwards)")
    sn.add_avit_arguments(semgrep)
    note = actions.add_parser("note", help="Add a work note to an AVIT without changing its state (e.g. why it could not be reviewed)")
    note.add_argument("number", metavar="AVIT")
    note.add_argument("--message", required=True, help="Work note text")
    note.add_argument("--yes", action="store_true", help="Apply without prompting")
    sn.add_avit_arguments(note)
    resolve = actions.add_parser("resolve", help="Upload the FP report to the AVIT; close it and tune Semgrep when it is a false positive")
    resolve.add_argument("number", metavar="AVIT")
    resolve.add_argument("--report", required=True, help="FP review report (Markdown) naming the AVIT in Original finding")
    resolve.add_argument("--docx", required=True, help="Word report to attach (the only file attached to the AVIT)")
    resolve.add_argument("--semgrep-deployment", help="Semgrep deployment slug when the token can access several")
    resolve.add_argument("--skip-semgrep", action="store_true", help="Do not change Semgrep triage or rules")
    resolve.add_argument("--skip-rule-tuning", action="store_true", help="Ignore the Semgrep finding but do not replace the rule")
    resolve.add_argument("--checkout", help="The AVIT checkout (from `avit checkout`); used to validate the tuned rule, then deleted")
    resolve.add_argument("--keep-checkout", action="store_true", help="Do not delete the checkout after resolving")
    resolve.add_argument("--yes", action="store_true", help="Apply without prompting (the caller has confirmed the verdict)")
    sn.add_avit_arguments(resolve)


def _session(args):
    if not args.snow_instance:
        raise ResolveError(f"Set the ServiceNow instance with --snow-instance or {sn.INSTANCE_ENV}")
    instance = sn.validate_instance_url(args.snow_instance)
    client_id, client_secret = sn.resolve_credentials(args.aws_profile)
    return instance, sn.access_token(instance, client_id, client_secret)


def _confirm(question: str, yes: bool) -> None:
    if yes:
        return
    if not sys.stdin.isatty():
        raise ResolveError("Confirmation required: rerun with --yes after reviewing the verdict")
    if input(f"{question} [y/N] ").strip().lower() not in ("y", "yes"):
        raise ResolveError("Cancelled; nothing was changed")


def cmd_checkout(args) -> int:
    [avit] = sn.parse_avit_numbers(args.number)
    instance, token = _session(args)
    record = _record(instance, token, avit)
    kind = sn.finding_kind(record)
    try:
        target = sn.repository_target(record["context"])
    except sn.ServiceNowError as exc:
        if sn.in_code_security_view(record):
            raise
        # Other tools (DAST, pen test, …) often name no repository; the review uses the AVIT's own evidence.
        raise ResolveError(f"{avit} names no repository ({exc}); triage it from the AVIT evidence without a checkout") from exc
    if target["scm"] == "azure-devops" and not sn.git_credential("azure-devops", target["organization"])[0] and sys.stdin.isatty():
        from threatlint.ado_login import prompt_and_save  # noqa: PLC0415
        print("  No Azure DevOps credential found; set up a PAT now (Code: Read).")
        print(f"  ✓ Saved to {prompt_and_save(target['organization'])}")
    print(f"  {avit} : {target['web_url']} · branch {target['branch'] or '(default)'} · {record['context'].get('file_path', 'no file path')}")
    try:
        sn.checkout_repository(target, args.dir, record["context"].get("file_path", ""))
    except sn.ServiceNowError as exc:
        renamed = renamed_ado_repository(target, args) if target["scm"] == "azure-devops" and "not found" in str(exc) else None
        if not renamed:
            raise
        print(f"  ! {target['name']} was renamed in Azure DevOps to {renamed}; cloning it (Semgrep still uses the original project name)")
        quote = lambda value: urllib.parse.quote(value, safe="")
        url = f"https://dev.azure.com/{quote(target['organization'])}/{quote(target['project'])}/_git/{quote(renamed)}"
        target = {**target, "clone_url": url, "web_url": url, "renamed_to": renamed}
        sn.checkout_repository(target, args.dir, record["context"].get("file_path", ""))
    print(f"✓ Checked out to {args.dir}")
    print(json.dumps({"avit": avit, "kind": kind, "checkout": os.path.abspath(args.dir), **target, **{k: v for k, v in record["context"].items() if k in ("file_path", "line", "rule", "finding_source")}}))
    return 0


def renamed_ado_repository(target: dict[str, str], args) -> str | None:
    """Current name of an ADO repository the AVIT knows by an old name.

    ServiceNow keeps the name from scan time. Semgrep's project record keeps the repository's GUID in its
    URL, and Azure DevOps resolves a GUID under the current name.
    """
    import base64  # noqa: PLC0415
    from threatlint import semgrep_platform as sp  # noqa: PLC0415
    from threatlint.ado_login import load  # noqa: PLC0415
    from threatlint.tls import ssl_context  # noqa: PLC0415
    try:
        token = sp.resolve_token(getattr(args, "aws_profile", None))[0]
        dep = sp.deployment(token)
        project = sp.call(f"/api/v1/deployments/{urllib.parse.quote(dep['slug'])}/projects/{urllib.parse.quote(target['project'] + '/' + target['name'], safe='/')}", token)
    except sp.SemgrepError:
        return None
    url = str((project.get("project") or project).get("url", ""))
    match = re.search(r"/_apis/git/repositories/([0-9a-f-]{36})", url)
    pat, _source = load(target["organization"])
    if not match or not pat:
        return None
    request = urllib.request.Request(f"https://dev.azure.com/{urllib.parse.quote(target['organization'])}/_apis/git/repositories/{match.group(1)}?api-version=7.1",
                                     headers={"Authorization": "Basic " + base64.b64encode(f":{pat}".encode()).decode(), "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30, context=ssl_context()) as response:  # noqa: S310 - fixed HTTPS host
            name = json.loads(response.read()).get("name")
    except (urllib.error.URLError, ValueError):
        return None
    return name if isinstance(name, str) and name and name != target["name"] else None


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


def cmd_resolve(args) -> int:
    [avit] = sn.parse_avit_numbers(args.number)
    with open(os.path.expanduser(args.report), encoding="utf-8") as handle:
        markdown = handle.read()
    verdict = verdict_for(markdown, avit)
    print(f"  {avit} : {verdict['id']} · {verdict['disposition']} ({verdict['confidence'] or 'confidence not stated'}) · {verdict['title']}")
    ambiguous = verdict["disposition"] == "AMBIGUOUS"
    instance, token = _session(args)
    record = _record(instance, token, avit)
    code_security = sn.in_code_security_view(record)
    kind = sn.finding_kind(record)
    false_positive = verdict["disposition"] == "FALSE POSITIVE"
    # One attachment: the Word report. The Markdown is only read here for the verdict.
    with open(os.path.expanduser(args.docx), "rb") as handle:
        files = [(f"{avit}-threatlint-fp-review.docx", handle.read(), _DOCX)]
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
    else:
        print("  ✓ Work note added; AVIT left open")
    if false_positive and not code_security:
        print("  Semgrep not applicable: this AVIT is not a CodeSecurity finding")
    if false_positive and code_security and not args.skip_semgrep:
        sg_token = semgrep_token(args.aws_profile)
        target = sn.repository_target(record["context"])
        try:
            dep, matches = semgrep_matches(sg_token, kind, target, {**record["context"], "avit": avit}, args.semgrep_deployment, markdown)
        except ResolveError as exc:
            # The AVIT is already closed; a Semgrep gap is reported, not treated as a failure of the close.
            print(f"  ! Semgrep unchanged: {exc}. The token's deployment may not scan this repository; pass --semgrep-deployment.")
            return 0
        if not matches:
            print(f"  ! No open Semgrep {({'secrets': 'Secrets', 'sca': 'Supply Chain'}).get(kind, 'Code')} finding matches {record['context'].get('file_path')}; Semgrep unchanged")
        else:
            for match in matches:
                print(f"    Semgrep #{match['id']} · {match['rule']} · {match['path']}:{match['line'] or '?'} · {match['ref'] or ''}")
            count = semgrep_ignore(sg_token, dep["slug"], kind, [match["id"] for match in matches], f"Closed by Threatlint as a false positive ({avit}, {verdict['id']}): {verdict['title']}")
            print(f"  ✓ Semgrep ignored {count} finding(s) as false_positive (kept for this fingerprint on later scans and branches)")
        # SAST and Secrets: replace the rule with the reviewer's tuned rule so the same false positive does not return.
        if kind in ("sast", "secrets") and not args.skip_rule_tuning:
            from threatlint import semgrep_platform as sp  # noqa: PLC0415
            path = record["context"].get("file_path", "")
            checkout = getattr(args, "checkout", None)
            target_file = os.path.join(checkout, path) if checkout and path else ""
            line = int(record["context"]["line"]) if record["context"].get("line", "").isdigit() else _report_line(markdown, avit)
            rule = record["context"].get("rule", "")
            if not (rule and target_file and os.path.exists(target_file)):
                print("  ! Rule not tuned: pass --checkout <AVIT checkout> so the tuned rule can be validated against the flagged file")
            else:
                try:
                    sp.tune_rule(markdown, kind, rule, target_file, line, sg_token, {"id": dep["id"], "slug": dep["slug"]})
                except sp.SemgrepError as exc:
                    print(f"  ! Rule not tuned: {exc}")
    return 0


def _report_line(report: str, avit: str) -> int | None:
    match = re.search(rf"Original finding\W*:\s*{avit};[^\n]*:(\d+)\s*$", report, re.M)
    return int(match.group(1)) if match else None


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
    if args.line:
        context["line"] = str(args.line)
    sg_token = semgrep_token(args.aws_profile)
    dep, matches = semgrep_matches(sg_token, kind, sn.repository_target(context), context, args.semgrep_deployment)
    if not matches:
        print(f"  ! No open Semgrep finding matches {context.get('file_path')}{':' + context['line'] if context.get('line') else ''}; Semgrep triage unchanged")
    else:
        for match in matches:
            print(f"    Semgrep #{match['id']} · {match['rule']} · {match['path']}:{match['line'] or '?'} · {match['ref'] or ''}")
        count = semgrep_ignore(sg_token, dep["slug"], kind, [match["id"] for match in matches], f"Closed by Threatlint as a false positive ({avit}); see the report attached to the AVIT")
        print(f"  ✓ Semgrep ignored {count} finding(s) as false_positive (kept for this fingerprint on later scans and branches)")
    if getattr(args, "report", None) and kind in ("sast", "secrets"):
        from threatlint import semgrep_platform as sp  # noqa: PLC0415
        with open(os.path.expanduser(args.report), encoding="utf-8") as handle:
            markdown = handle.read()
        path = context.get("file_path", "")
        target_file = os.path.join(args.checkout, path) if getattr(args, "checkout", None) and path else ""
        line = int(context["line"]) if context.get("line", "").isdigit() else _report_line(markdown, avit)
        try:
            sp.tune_rule(markdown, kind, context.get("rule", ""), target_file, line, sg_token, {"id": dep["id"], "slug": dep["slug"]})
        except sp.SemgrepError as exc:
            print(f"  ! Rule not tuned: {exc}")
            return 1
    return 0


def run(handler, args) -> int:
    try:
        return handler(args)
    except (ResolveError, sn.ServiceNowError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        # The checkout holds a copy of someone else's source (possibly live secrets); never leave it on disk.
        if getattr(args, "avit_command", "") in ("resolve", "semgrep") and not getattr(args, "keep_checkout", False) and remove_checkout(getattr(args, "checkout", None)):
            print(f"  ✓ Deleted the local checkout {args.checkout}")
