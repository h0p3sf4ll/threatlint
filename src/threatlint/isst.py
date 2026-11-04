"""Find AVITs associated with an ISST and post their reviewed outcome headlessly.

ISSTs are task subclasses whose concrete table varies between ServiceNow
instances. Resolve the class through ``task.sys_class_name`` rather than
assuming a custom table name. All source and journal fields are untrusted.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse

from threatlint import servicenow as sn
from threatlint.avit_report import ResolveError


_ISST = re.compile(r"ISST\d{7,15}")
_TABLE = re.compile(r"[a-z][a-z0-9_]{1,79}")
_SYS_ID = re.compile(r"[0-9a-f]{32}")
_REPORT = re.compile(r"(AVIT\d{7,15})-threatlint-fp-review(?:-\d{8}T\d{12}Z)?\.docx")
_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
_PAGE = 200
_MAX_PAGES = 20
_FIELD_NAMES = {
    "organization": ("organizationname", "organisationname", "orgname", "organization", "scmorganization"),
    "project": ("projectado", "projectname", "scmproject", "project"),
    "repository": ("repositoryname", "reponame", "repository", "repo"),
    "repo_url": ("repositoryurl", "repourl", "giturl", "scmurl", "repositorylink"),
    "branch": ("projectbranch", "branchname", "scmbranch", "branch"),
    "scm_tool": ("scmtool", "scmprovider", "sourcecontrol", "scm"),
}


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _value(raw) -> str:
    if isinstance(raw, dict):
        raw = raw.get("value") or raw.get("display_value")
    return str(raw or "").strip()


def _rows(instance: str, token: str, table: str, query: str, limit: int, offset: int = 0) -> list[dict]:
    parameters = urllib.parse.urlencode({"sysparm_query": query, "sysparm_display_value": "all",
                                         "sysparm_limit": str(limit), "sysparm_offset": str(offset)})
    result = sn._request_json(f"{instance}/api/now/table/{table}?{parameters}", headers=_auth(token)).get("result")
    if not isinstance(result, list) or any(not isinstance(row, dict) for row in result):
        raise ResolveError(f"ServiceNow did not return readable {table} records")
    return result


def _configured_table() -> str:
    table = os.environ.get("THREATLINT_SNOW_ISST_TABLE", "").strip()
    if table and not _TABLE.fullmatch(table):
        raise ResolveError("THREATLINT_SNOW_ISST_TABLE is not a valid table name")
    return table


def _metadata_table(instance: str, token: str) -> str:
    """Find one ISST task class when task rows are hidden from this OAuth client."""
    try:
        rows = _rows(instance, token, "sys_db_object", "labelLIKEInformation Security", 100)
    except sn.ServiceNowError:
        return ""
    candidates = {name for row in rows
                  if "security" in sn._field_value(row.get("label")).lower()
                  and "task" in sn._field_value(row.get("label")).lower()
                  if (name := _value(row.get("name"))) and _TABLE.fullmatch(name)}
    if len(candidates) > 1:
        raise ResolveError("Several Information Security task tables are available; set THREATLINT_SNOW_ISST_TABLE")
    return next(iter(candidates), "")


def _record(instance: str, token: str, number: str) -> dict:
    configured = _configured_table()
    try:
        task_rows = _rows(instance, token, "task", f"number={number}", 2)
    except sn.ServiceNowError as exc:
        if not configured:
            raise ResolveError("The OAuth client cannot read the task table; set THREATLINT_SNOW_ISST_TABLE to the ISST table") from exc
        task_rows = []
    if len(task_rows) > 1:
        raise ResolveError(f"ServiceNow returned more than one task for {number}")
    task = task_rows[0] if task_rows else None
    concrete = _value(task.get("sys_class_name")) if task else ""
    table = concrete if concrete and concrete != "task" else configured or (_metadata_table(instance, token) if not task else "") or "task"
    if not _TABLE.fullmatch(table):
        raise ResolveError(f"ServiceNow returned an invalid ISST table name for {number}")
    rows = _rows(instance, token, table, f"number={number}", 2) if table != "task" or not task else [task]
    if len(rows) != 1:
        raise ResolveError(f"{number} was not found in {table}, or the OAuth client cannot read its records; "
                           "grant ISST table read access or set THREATLINT_SNOW_ISST_TABLE")
    row = rows[0]
    sys_id = _value(row.get("sys_id"))
    if not _SYS_ID.fullmatch(sys_id) or sn._field_value(row.get("number")) != number:
        raise ResolveError(f"{number} returned an unexpected record identity")
    if task and _value(task.get("sys_id")) != sys_id:
        raise ResolveError(f"The ISST subclass and task identity disagree for {number}")
    return {"number": number, "sys_id": sys_id, "table": table, "fields": sn._flatten(row),
            "assessment_ref": row.get("scan_asmt_details")}


def _assessment_fields(instance: str, token: str, reference) -> dict[str, str]:
    """Read repository fields from a linked scan assessment when the ISST omits them."""
    if not isinstance(reference, dict):
        return {}
    sys_id = _value(reference.get("value"))
    if not _SYS_ID.fullmatch(sys_id):
        return {}
    table = "x_inpe_information_scan_assessments"
    link = sn._reference_url(instance, reference)
    if link and f"/api/now/table/{table}/{sys_id}?" not in link:
        raise ResolveError("The ISST assessment reference points to an unexpected table or record")
    url = link or f"{instance}/api/now/table/{table}/{sys_id}?sysparm_display_value=all"
    result = sn._request_json(url, headers=_auth(token)).get("result")
    if not isinstance(result, dict) or _value(result.get("sys_id")) != sys_id:
        raise ResolveError("The linked scan assessment is not readable or has an unexpected identity")
    fields = sn._flatten(result)
    allowed = {"reponame", "repositoryname", "repourl", "repositoryurl", "branchname", "projectbranch",
               "projectado", "scmproject", "organizationname", "orgname", "scmtool", "description"}
    return {name: value for name, value in fields.items() if sn._normalized(name) in allowed}


def _label_values(fields: dict[str, str]) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {key: [] for key in _FIELD_NAMES}
    aliases = {alias: key for key, names in _FIELD_NAMES.items() for alias in names}
    for name, value in fields.items():
        key = aliases.get(sn._normalized(name))
        if key and value:
            values[key].append(value.strip())
    for source in (fields.get("description", ""), fields.get("short_description", ""),
                   fields.get("scan_asmt_details", ""), fields.get("scan_result", "")):
        for label, value in re.findall(r"(?m)^\s*(?:[-*]\s*)?([\w /-]{2,45})\s*[:=]\s*(\S.*?)\s*$", source):
            key = aliases.get(sn._normalized(label))
            if key and value:
                values[key].append(value.strip())
    return values


def _single(values: list[str], label: str, *, branch: bool = False) -> str:
    cleaned = [re.sub(r"^refs/heads/", "", value.strip()) if branch else value.strip() for value in values if value.strip()]
    if len({value if branch else value.casefold() for value in cleaned}) > 1:
        raise ResolveError(f"The ISST has conflicting {label} values")
    return cleaned[0] if cleaned else ""


def _repo_url(value: str) -> dict[str, str] | None:
    candidate = value.strip().strip("<>[]()\"'.,;")
    try:
        url = urllib.parse.urlsplit(candidate)
    except ValueError:
        return None
    if url.scheme != "https" or url.username or url.password or not url.hostname:
        return None
    host = url.hostname.lower()
    parts = [urllib.parse.unquote(part) for part in url.path.strip("/").split("/") if part]
    if host == "dev.azure.com" and len(parts) >= 4 and parts[2].lower() == "_git":
        return {"scm_tool": "ADO", "organization": parts[0], "project": parts[1], "repository": parts[3]}
    if host.endswith(".visualstudio.com") and len(parts) >= 3 and parts[1].lower() == "_git":
        return {"scm_tool": "ADO", "organization": host.split(".")[0], "project": parts[0], "repository": parts[2]}
    if host == "github.com" and len(parts) >= 2:
        return {"scm_tool": "GitHub", "organization": parts[0], "project": "", "repository": re.sub(r"\.git$", "", parts[1])}
    return None


def _scm_kind(value: str) -> str:
    name = value.strip().casefold()
    if name in ("ado", "azure devops", "azuredevops", "azure repos", "vsts", "tfs"):
        return "ADO"
    if name in ("github", "gh", "github enterprise cloud", "ghec"):
        return "GitHub"
    return value


def _target(fields: dict[str, str]) -> dict[str, str]:
    values = _label_values(fields)
    explicit = {key: _single(entries, key, branch=key == "branch") for key, entries in values.items()}
    texts = [*values["repo_url"], fields.get("description", ""), fields.get("short_description", ""),
             fields.get("scan_asmt_details", ""), fields.get("scan_result", "")]
    urls = [match.group() for text in texts for match in re.finditer(r"https://[^\s<>)]+", text)]
    parsed = [_repo_url(url) for url in urls]
    recognized = [item for item in parsed if item]
    if values["repo_url"] and not recognized:
        raise ResolveError("The ISST repository URL is not a supported Azure DevOps or GitHub URL")
    unique = {tuple(item[key].casefold() for key in ("scm_tool", "organization", "project", "repository")) for item in recognized}
    if len(unique) > 1:
        raise ResolveError("The ISST names more than one repository URL")
    from_url = recognized[0] if recognized else {}
    context = {}
    for key in ("scm_tool", "organization", "project", "repository"):
        stated, derived = explicit[key], from_url.get(key, "")
        if key == "scm_tool":
            stated, derived = _scm_kind(stated), _scm_kind(derived)
        if stated and derived and stated.casefold() != derived.casefold():
            raise ResolveError(f"The ISST {key} conflicts with its repository URL")
        context[key] = stated or derived
    context["branch"] = explicit["branch"]
    if not context["branch"]:
        raise ResolveError("The ISST needs an exact branch name to identify related AVITs")
    if not from_url and not context["scm_tool"]:
        raise ResolveError("The ISST needs a repository URL or SCM Tool to identify its repository")
    try:
        return sn.repository_target(context)
    except sn.ServiceNowError as exc:
        raise ResolveError(f"The ISST repository identity is incomplete: {exc}") from exc


def _candidate_rows(instance: str, token: str, repository: str) -> list[dict]:
    if any(character in repository for character in "^=\r\n"):
        raise ResolveError("The ISST repository name cannot be used safely in a ServiceNow query")
    candidates: dict[str, dict] = {}
    successful = False
    for column in ("u_repository", "repository"):
        for page in range(_MAX_PAGES):
            try:
                rows = _rows(instance, token, sn.AVIT_TABLE, f"{column}={repository}", _PAGE, page * _PAGE)
            except sn.ServiceNowError:
                break
            successful = True
            for row in rows:
                number = sn._field_value(row.get("number"))
                if _ISST.fullmatch(number):
                    continue
                if sn._AVIT_PATTERN.fullmatch(number):
                    candidates[number] = row
            if len(rows) < _PAGE:
                break
        else:
            raise ResolveError(f"More than {_PAGE * _MAX_PAGES} AVIT candidates match repository {repository}; narrow the ServiceNow query")
    if not successful:
        raise ResolveError("The OAuth client could not query AVITs by repository")
    return list(candidates.values())


def discover(instance: str, token: str, number: str) -> tuple[dict, list[str]]:
    """Return the ISST and AVIT numbers with the same SCM, repo, and exact branch."""
    number = str(number or "").strip().upper()
    if not _ISST.fullmatch(number):
        raise ResolveError("Expected an ISST number followed by 7 to 15 digits")
    record = _record(instance, token, number)
    try:
        target = _target(record["fields"])
    except ResolveError as primary:
        assessment = _assessment_fields(instance, token, record.get("assessment_ref"))
        if not assessment:
            raise primary
        fields = dict(record["fields"])
        for name, value in assessment.items():
            if fields.get(name) and fields[name] != value:
                raise ResolveError(f"The ISST and linked scan assessment disagree on {name}")
            fields[name] = value
        target = _target(fields)
        record["fields"] = fields
    labels = sn.field_labels(instance, token)
    numbers: list[str] = []
    for row in _candidate_rows(instance, token, target["name"]):
        fields = sn._flatten(row)
        avit = fields.get("number", "")
        context = sn.avit_context(fields, labels)
        if context.get("repository", "").casefold() != target["name"].casefold():
            continue
        branch = re.sub(r"^refs/heads/", "", context.get("branch", ""))
        if not branch:
            raise ResolveError(f"{avit} names this repository without a branch; ISST association is ambiguous")
        if branch != target["branch"]:
            continue
        try:
            avit_target = sn.repository_target(context)
        except sn.ServiceNowError as exc:
            raise ResolveError(f"{avit} has incomplete repository identity on the ISST branch: {exc}") from exc
        identity = lambda item: (item["scm"], item["organization"].casefold(), item["project"].casefold(), item["name"].casefold(), item["branch"])
        if identity(avit_target) == identity(target):
            numbers.append(avit)
    if len(numbers) > sn.MAX_AVITS:
        raise ResolveError(f"{number} matches {len(numbers)} AVITs; review at most {sn.MAX_AVITS} in one headless run")
    record["target"] = target
    record["avits"] = numbers
    return record, numbers


def _existing_attachments(instance: str, token: str, record: dict) -> dict[str, str]:
    query = urllib.parse.urlencode({"sysparm_query": f"table_name={record['table']}^table_sys_id={record['sys_id']}",
                                    "sysparm_fields": "sys_id,file_name", "sysparm_limit": "200"})
    rows = sn._request_json(f"{instance}/api/now/attachment?{query}", headers=_auth(token)).get("result")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ResolveError(f"ServiceNow did not return readable attachments for {record['number']}")
    found: dict[str, str] = {}
    for row in rows:
        name, sys_id = sn._field_value(row.get("file_name")), _value(row.get("sys_id"))
        if not name or not _SYS_ID.fullmatch(sys_id):
            raise ResolveError(f"ServiceNow returned an invalid attachment for {record['number']}")
        if name in found and found[name] != sys_id:
            raise ResolveError(f"ServiceNow returned duplicate attachment names for {record['number']}")
        found[name] = sys_id
    return found


def _comment_chunks(lines: list[str], limit: int = 3500) -> list[str]:
    chunks: list[str] = []
    current: list[str] = []
    length = 0
    for line in lines:
        if len(line) > limit:
            raise ResolveError("An ISST attachment link is too long for a comment")
        if current and length + len(line) + 1 > limit:
            chunks.append("\n".join(current))
            current, length = [], 0
        current.append(line)
        length += len(line) + 1
    if current:
        chunks.append("\n".join(current))
    return chunks


def summarize(instance: str, token: str, record: dict, outcomes: list[dict]) -> dict:
    """Attach TP reports, add an outcome comment, and leave ISST state unchanged."""
    expected = list(record.get("avits", []))
    if not expected:
        raise ResolveError(f"{record['number']} has no associated AVITs to summarize")
    by_number = {item.get("avit"): item for item in outcomes}
    if len(by_number) != len(outcomes) or any(avit not in expected for avit in by_number):
        raise ResolveError("The ISST outcomes do not match its discovered AVITs")
    positives = [item for item in outcomes if item.get("disposition") == "TRUE POSITIVE"]
    for item in positives:
        name = str(item.get("attachment_name") or "")
        content = item.get("report_bytes")
        match = _REPORT.fullmatch(name)
        if not match or match.group(1) != item["avit"] or not isinstance(content, bytes) or not content.startswith(b"PK"):
            raise ResolveError(f"{item['avit']} has no valid Word report to attach to {record['number']}")
    existing = _existing_attachments(instance, token, record)
    links: dict[str, str] = {}
    for item in positives:
        name = item["attachment_name"]
        sys_id = existing.get(name)
        if not sys_id:
            query = urllib.parse.urlencode({"table_name": record["table"], "table_sys_id": record["sys_id"], "file_name": name})
            payload = sn._request_json(f"{instance}/api/now/attachment/file?{query}", data=item["report_bytes"],
                                       headers={**_auth(token), "Content-Type": _DOCX}).get("result", {})
            sys_id = _value(payload.get("sys_id")) if isinstance(payload, dict) else ""
            if not _SYS_ID.fullmatch(sys_id):
                raise ResolveError(f"ServiceNow did not confirm the {name} attachment on {record['number']}")
        links[item["avit"]] = f"{instance}/sys_attachment.do?sys_id={sys_id}"
    complete = len(by_number) == len(expected) and all(item.get("completed") for item in outcomes)
    all_fp = complete and all(item.get("disposition") == "FALSE POSITIVE" for item in outcomes)
    if all_fp:
        lines = ["All findings reviewed by Threatlint were false positives. This ISST and SCAN request can be closed.",
                 "Reviewed AVITs: " + ", ".join(expected)]
    else:
        lines = ["True positives detected by Threatlint." if positives else "Threatlint review is incomplete for this ISST and SCAN request."]
        for item in positives:
            lines.append(f"{item['avit']} true-positive report attached: {links[item['avit']]}")
        pending = [avit for avit in expected if avit not in by_number or not by_number[avit].get("completed")
                   or by_number[avit].get("disposition") not in ("TRUE POSITIVE", "FALSE POSITIVE")]
        if pending:
            lines.append("AVITs needing follow-up: " + ", ".join(pending) + ". Keep this ISST and SCAN request open.")
        else:
            lines.append("Review the true positives in their AVITs; keep this ISST and SCAN request open for remediation.")
    for comment in _comment_chunks(lines):
        response = sn._request_json(f"{instance}/api/now/table/{record['table']}/{record['sys_id']}?sysparm_fields=number,sys_id,comments",
                                    method="PATCH", data=json.dumps({"comments": comment}).encode(),
                                    headers={**_auth(token), "Content-Type": "application/json"}).get("result")
        if not isinstance(response, dict) or not (sn._field_value(response.get("number")) == record["number"]
                                                  or _value(response.get("sys_id")) == record["sys_id"]):
            raise ResolveError(f"ServiceNow did not confirm the comment on {record['number']}")
    return {"isst": record["number"], "attachment_links": links, "closure_ready": all_fp, "comment": "\n".join(lines)}
