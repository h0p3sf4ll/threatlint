"""Act on an FP review of AVITs: upload the report to ServiceNow, close false positives, and tune Semgrep.

`threatlint avit resolve <AVIT> --report report.md [--docx report.docx]` reads the AVIT's disposition
from the report the FP reviewer wrote and then:
  TRUE POSITIVE  -> attaches the report (prefixed with the AVIT number) and adds a work note; stays open.
  FALSE POSITIVE -> attaches the report, closes the AVIT as Closed / False Positive with the comment
                    "Closed as false positive by Threatlint fp-review agent", and ignores the matching
                    open Semgrep finding(s) as false_positive (Code for SAST, Supply Chain for SCA, Secrets for Secrets).
  AMBIGUOUS      -> changes nothing.
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

CLOSING_COMMENT = "Closed as false positive by Threatlint fp-review agent"
REVIEWED_COMMENT = "Reviewed by Threatlint fp-review agent"
SEMGREP_TOKEN_PARAMETER = "/cfc-appsec-semgrep-scan/semgrep-token"
SEMGREP_API = "https://semgrep.app/api/v1"
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


def _false_positive_choices(instance: str, token: str) -> tuple[str, str]:
    """Closed / False Positive choice values from sys_choice (THREATLINT_SNOW_FP_STATE/_SUBSTATE override)."""
    state, substate = os.environ.get("THREATLINT_SNOW_FP_STATE"), os.environ.get("THREATLINT_SNOW_FP_SUBSTATE")
    if state and substate:
        return state, substate
    tables = [sn.AVIT_TABLE, "sn_vul_app_vul_entry", "sn_vul_entry", "task"]
    query = urllib.parse.urlencode({"sysparm_query": f"nameIN{','.join(tables)}^elementINstate,substate^inactive=false",
                                    "sysparm_fields": "name,element,value,label", "sysparm_limit": "500"})
    rows = sn._request_json(f"{instance}/api/now/table/sys_choice?{query}", headers={"Authorization": f"Bearer {token}"}).get("result", [])
    def pick(element, label):
        found = sorted((row for row in rows if row.get("element") == element and re.fullmatch(label, str(row.get("label", "")).strip(), re.IGNORECASE)),
                       key=lambda row: tables.index(row.get("name")) if row.get("name") in tables else 99)
        return found[0]["value"] if found else None
    state, substate = state or pick("state", r"closed"), substate or pick("substate", r"false[ -]?positive")
    if not state or not substate:
        raise ResolveError("ServiceNow has no readable Closed / False Positive choices; set THREATLINT_SNOW_FP_STATE and THREATLINT_SNOW_FP_SUBSTATE")
    return state, substate


def attach(instance: str, token: str, sys_id: str, name: str, content: bytes, content_type: str) -> None:
    query = urllib.parse.urlencode({"table_name": sn.AVIT_TABLE, "table_sys_id": sys_id, "file_name": name})
    sn._request_json(f"{instance}/api/now/attachment/file?{query}", data=content, headers={"Authorization": f"Bearer {token}", "Content-Type": content_type})


def update(instance: str, token: str, sys_id: str, values: dict[str, str]) -> dict:
    result = sn._request_json(f"{instance}/api/now/table/{sn.AVIT_TABLE}/{sys_id}?sysparm_fields=number,state,substate", method="PATCH",
                              data=json.dumps(values).encode(), headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    return result.get("result", {}) or {}


# ── Semgrep ──────────────────────────────────────────────────────────────────

def semgrep_token(profile: str | None) -> str:
    if os.environ.get("SEMGREP_APP_TOKEN"):
        return os.environ["SEMGREP_APP_TOKEN"]
    aws = shutil.which("aws")
    if not aws:
        raise ResolveError("The AWS CLI is required to read the Semgrep token (or set SEMGREP_APP_TOKEN)")
    command = [aws, "ssm", "get-parameter", "--name", SEMGREP_TOKEN_PARAMETER, "--with-decryption", "--region", sn.AWS_REGION,
               "--query", "Parameter.Value", "--output", "text", *(["--profile", profile] if profile else [])]
    from threatlint.tls import tool_env  # noqa: PLC0415
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False, env=tool_env())
    if result.returncode != 0 or not result.stdout.strip():
        reason = (result.stderr.strip().splitlines() or ["no value"])[-1][:300]
        raise ResolveError(f"Could not read {SEMGREP_TOKEN_PARAMETER}: {reason}. Run `threatlint aws login`.")
    return result.stdout.strip()


def _semgrep(path: str, token: str, *, body: dict | None = None) -> dict:
    request = urllib.request.Request(f"{SEMGREP_API}{path}", data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {token}", "Accept": "application/json", **({"Content-Type": "application/json"} if body is not None else {})})
    try:
        with sn._OPENER.open(request, timeout=30) as response:  # noqa: S310 - fixed HTTPS host, redirects refused
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


def semgrep_matches(token: str, kind: str, target: dict[str, str], context: dict[str, str], deployment: str | None = None) -> tuple[dict, list[dict]]:
    """Open Semgrep findings for the same project, file, and rule/line as the AVIT."""
    deployments = _semgrep("/deployments", token).get("deployments", [])
    chosen = [item for item in deployments if not deployment or item.get("slug") == deployment]
    if len(chosen) != 1:
        raise ResolveError("Choose the Semgrep deployment with --semgrep-deployment" if chosen else f"The token cannot access deployment {deployment}")
    dep = chosen[0]
    path, line, rule = context.get("file_path", ""), context.get("line", ""), context.get("rule", "")
    if not path:
        raise ResolveError("The AVIT has no File Path, so its Semgrep finding cannot be matched narrowly")
    projects, page = [], 0
    while page < 20:
        batch = _semgrep(f"/deployments/{urllib.parse.quote(dep['slug'])}/projects?page={page}&page_size=100", token).get("projects", [])
        projects += batch
        if len(batch) < 100:
            break
        page += 1
    repo = target["name"].lower()
    named = [p["name"] for p in projects if str(p.get("name", "")).lower() == repo or str(p.get("name", "")).lower().endswith("/" + repo)]
    if not named:
        raise ResolveError(f"No Semgrep project matches repository {target['name']}")
    near = lambda found: not line.isdigit() or found is None or abs(int(found) - int(line)) <= 3
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
    resolve = actions.add_parser("resolve", help="Upload the FP report to the AVIT; close it and tune Semgrep when it is a false positive")
    resolve.add_argument("number", metavar="AVIT")
    resolve.add_argument("--report", required=True, help="FP review report (Markdown) naming the AVIT in Original finding")
    resolve.add_argument("--docx", help="Word copy of the report to attach as well")
    resolve.add_argument("--semgrep-deployment", help="Semgrep deployment slug when the token can access several")
    resolve.add_argument("--skip-semgrep", action="store_true", help="Do not change Semgrep triage")
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
    if not sn.in_code_security_view(record):
        raise ResolveError(f"{avit} is not in the AVR CodeSecurity view; Threatlint reviews only CodeSecurity AVITs")
    kind = sn.finding_kind(record)
    target = sn.repository_target(record["context"])
    if target["scm"] == "azure-devops" and not sn.git_credential("azure-devops")[0] and sys.stdin.isatty():
        from threatlint.ado_login import prompt_and_save  # noqa: PLC0415
        print("  No Azure DevOps credential found; set up a PAT now (Code: Read).")
        print(f"  ✓ Saved to {prompt_and_save(target['organization'])}")
    print(f"  {avit} : {target['web_url']} · branch {target['branch'] or '(default)'} · {record['context'].get('file_path', 'no file path')}")
    sn.checkout_repository(target, args.dir)
    print(f"✓ Checked out to {args.dir}")
    print(json.dumps({"avit": avit, "kind": kind, "checkout": os.path.abspath(args.dir), **target, **{k: v for k, v in record["context"].items() if k in ("file_path", "line", "rule", "finding_source")}}))
    return 0


def cmd_resolve(args) -> int:
    [avit] = sn.parse_avit_numbers(args.number)
    with open(os.path.expanduser(args.report), encoding="utf-8") as handle:
        markdown = handle.read()
    verdict = verdict_for(markdown, avit)
    print(f"  {avit} : {verdict['id']} · {verdict['disposition']} ({verdict['confidence'] or 'confidence not stated'}) · {verdict['title']}")
    if verdict["disposition"] == "AMBIGUOUS":
        print("  AMBIGUOUS: nothing changed; resolve the blocking evidence in the report first.")
        return 0
    instance, token = _session(args)
    record = _record(instance, token, avit)
    if not sn.in_code_security_view(record):
        raise ResolveError(f"{avit} is not in the AVR CodeSecurity view; Threatlint does not change it")
    kind = sn.finding_kind(record)
    false_positive = verdict["disposition"] == "FALSE POSITIVE"
    files = [(f"{avit}-threatlint-fp-review.md", markdown.encode("utf-8"), "text/markdown")]
    if args.docx:
        with open(os.path.expanduser(args.docx), "rb") as handle:
            files.append((f"{avit}-threatlint-fp-review.docx", handle.read(), _DOCX))
    action = "attach the report and close it as Closed / False Positive" if false_positive else "attach the report and add a TRUE POSITIVE work note (it stays open)"
    _confirm(f"{avit}: {action}?", args.yes)
    # Attach first so the AVIT is never closed without its evidence.
    for name, content, content_type in files:
        attach(instance, token, record["sys_id"], name, content, content_type)
        print(f"  ✓ Attached {name}")
    note = "\n".join([CLOSING_COMMENT if false_positive else f"{REVIEWED_COMMENT}: TRUE POSITIVE (left open for remediation).", "",
                      f"Finding: {verdict['id']} — {verdict['title']}", f"Disposition: {verdict['disposition']} (confidence {verdict['confidence'] or 'not stated'})",
                      f"Report attached: {', '.join(name for name, _c, _t in files)}"])
    values = {"work_notes": note}
    if false_positive:
        state, substate = _false_positive_choices(instance, token)
        values.update({"state": state, "substate": substate, "close_notes": note})
    stored = update(instance, token, record["sys_id"], values)
    if false_positive:
        closed = str(stored.get("state")) == str(values["state"]) and str(stored.get("substate")) == str(values["substate"])
        print(f"  {'✓ Closed as false positive' if closed else '! ServiceNow kept state ' + str(stored.get('state')) + ' / ' + str(stored.get('substate')) + ' (pending approval?)'}")
    else:
        print("  ✓ Work note added; AVIT left open")
    if false_positive and not args.skip_semgrep:
        sg_token = semgrep_token(args.aws_profile)
        target = sn.repository_target(record["context"])
        dep, matches = semgrep_matches(sg_token, kind, target, record["context"], args.semgrep_deployment)
        if not matches:
            print(f"  ! No open Semgrep {({'secrets': 'Secrets', 'sca': 'Supply Chain'}).get(kind, 'Code')} finding matches {record['context'].get('file_path')}; Semgrep unchanged")
        else:
            for match in matches:
                print(f"    Semgrep #{match['id']} · {match['rule']} · {match['path']}:{match['line'] or '?'} · {match['ref'] or ''}")
            _confirm(f"Ignore {len(matches)} Semgrep finding(s) as false positive?", args.yes)
            count = semgrep_ignore(sg_token, dep["slug"], kind, [match["id"] for match in matches], f"{CLOSING_COMMENT} ({avit}, {verdict['id']}): {verdict['title']}")
            print(f"  ✓ Semgrep ignored {count} finding(s) as false_positive (kept for this fingerprint on later scans and branches)")
    return 0


def run(handler, args) -> int:
    try:
        return handler(args)
    except (ResolveError, sn.ServiceNowError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
