"""Narrowly match an AVIT to paginated Semgrep Code, Supply Chain, or Secrets findings."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from threatlint import servicenow as sn
from threatlint.avit_report import ResolveError


def request(path, token, *, body=None, api):
    request = urllib.request.Request(f"{api}{path}", data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {token}", "Accept": "application/json", **({"Content-Type": "application/json"} if body is not None else {})})
    try:
        with sn._OPENER.open(request, timeout=120) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        hint = {401: " Check the Semgrep token.", 403: " The token needs Web API scope.", 404: " Check the deployment and project."}.get(exc.code, "")
        raise ResolveError(f"Semgrep returned HTTP {exc.code}.{hint}") from exc
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise ResolveError(f"Semgrep request failed: {exc}") from exc


def tail(value: str) -> str:
    return str(value or "").replace("\\", "/").removeprefix("./").lstrip("/")


def same_path(found: str, wanted: str) -> bool:
    a, b = tail(found), tail(wanted)
    return bool(a and b) and a == b


def project_names(target: dict[str, str]) -> list[str]:
    """Keep ADO's organization/project/repository identity intact."""
    parts = [target.get("organization", ""), target.get("project", ""), target.get("name", "")]
    if not parts[0] or not parts[-1]:
        raise ResolveError("Semgrep matching requires the organization and repository")
    return ["/".join(part for part in parts if part)]


def tuning_project(target: dict[str, str], matches: list[dict]) -> str:
    """Use the exact queried project when matched, otherwise the AVIT's canonical project name."""
    if matches and matches[0].get("project"):
        return matches[0]["project"]
    names = project_names(target)
    if not names:
        raise ResolveError("The AVIT has no Semgrep project name, so its rule cannot be tuned narrowly")
    return names[0]


def scoped_findings(token, dep, kind, repository, branch, rule, *, query, status=None):
    """Yield normalized findings without truncating pagination or trusting ignored filters. A Secrets search with
    ``rule=None`` yields every finding on the repository and branch, for location-based correlation."""
    seen, cursors, cursor, page = set(), set(), "", 0
    while True:
        if kind == "secrets":
            params = {"limit": 1000, "repo": repository, **({"cursor": cursor} if cursor else {})}
            endpoint = f"/deployments/{dep['id']}/secrets?"
        else:
            params = {"issue_type": kind, "repos": repository, "ref": branch, "dedup": "false",
                      "page": page, "page_size": 1000}
            if kind == "sast":
                params["rules"] = rule
            if status:
                params["status"] = status
            endpoint = f"/deployments/{urllib.parse.quote(dep['slug'])}/findings?"
        data = query(endpoint + urllib.parse.urlencode(params), token)
        rows = data.get("findings") if isinstance(data, dict) else None
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ResolveError("Semgrep returned an invalid findings page; partial results are not usable")
        for row in rows:
            if (row.get("repository") or {}).get("name") != repository:
                raise ResolveError("Semgrep returned another repository or omitted its identity")
            ref = str(row.get("ref", ""))
            if kind != "secrets" and ref != branch:
                raise ResolveError("Semgrep did not honor the requested branch")
            if kind == "secrets":
                path, separator, line = str(row.get("findingPath", "")).rpartition(":")
                if not separator:
                    path, line = str(row.get("findingPath", "")), ""
                name = str(row.get("ruleHashId", ""))
                stored_status = str(row.get("status", "")).removeprefix("FINDING_STATUS_").lower()
            else:
                location = row.get("location") or {}
                path, line = location.get("file_path", ""), location.get("line")
                name = str(row.get("rule_name") or (row.get("rule") or {}).get("name", ""))
                stored_status = str(row.get("status", ""))
            identifier = row.get("id")
            if isinstance(identifier, bool) or not str(identifier).isdigit() or int(identifier) <= 0:
                raise ResolveError("Semgrep returned an invalid finding ID")
            identity = (int(identifier), ref)
            if identity in seen:
                raise ResolveError("Semgrep repeated a finding across pages; results are incomplete")
            seen.add(identity)
            if ref != branch or (rule is not None and name != rule) or (status and stored_status != status):
                continue
            yield {"id": int(identifier), "rule": name, "path": path, "line": line, "ref": ref,
                   "project": repository, "product": kind, "status": stored_status}
        if kind != "secrets":
            if not rows:
                return
            page += 1
            continue
        following = data.get("cursor") or ""
        if not following:
            return
        if not rows or following == cursor or following in cursors:
            raise ResolveError("Semgrep Secrets returned a non-advancing continuation cursor")
        cursors.add(following)
        cursor = following


def semgrep_matches(token, kind, target, context, deployment=None, report_text="", *,
                    query, report_line, same_path):
    from threatlint.semgrep_platform import deployment as find_deployment, SemgrepError
    try:
        dep = find_deployment(token, deployment or "")
    except SemgrepError as exc:
        raise ResolveError(str(exc)) from exc
    path, line, rule = context.get("file_path", ""), context.get("line", ""), context.get("rule", "")
    if not path:
        raise ResolveError("The AVIT has no File Path, so its Semgrep finding cannot be matched narrowly")
    if not line.isdigit():
        line = report_line(report_text, context.get("avit", "")) if report_text else None
        line = str(line) if line else ""
    if not line.isdigit():
        raise ResolveError("Neither the AVIT nor the report records the flagged line, so the Semgrep finding cannot be matched narrowly; pass --line")
    if int(line) <= 0:
        raise ResolveError("The flagged line must be positive")
    branch = context.get("branch") or target.get("branch", "")
    if not branch or not rule:
        raise ResolveError("Semgrep matching requires the exact branch and rule")
    repository = project_names(target)[0]
    near = lambda found: str(found).isdigit() and int(found) > 0 and abs(int(found) - int(line)) <= 3
    product = "sast" if kind == "secrets" else kind
    matches = [found for found in scoped_findings(token, dep, product, repository, branch, rule, query=query, status="open")
               if same_path(found["path"], path) and near(found["line"])]
    if not matches:
        matches = [found for found in scoped_findings(token, dep, product, repository, branch, rule, query=query, status="ignored")
                   if same_path(found["path"], path) and near(found["line"])]
    if kind == "secrets" and not matches:
        product = "secrets"
        rule_hash = context.get("rule_hash_id", "") or None
        # Without a supplied ruleHashId, the location is the identity: the open Secrets finding on this exact
        # repository, branch, and file, within the same ±3 lines as Code matching. The matched finding's own
        # ruleHashId is then authoritative. The service type an AVIT names is never used as a rule.
        candidates = [found for found in scoped_findings(token, dep, product, repository, branch, rule_hash, query=query, status="open")
                      if same_path(found["path"], path) and near(found["line"])]
        rules = sorted({found["rule"] for found in candidates})
        if not rule_hash and len(rules) > 1:
            raise ResolveError(f"{len(candidates)} open Semgrep Secrets findings at {path}:{line} have different rules "
                               f"({', '.join(rules)}); pass --semgrep-rule-hash-id to choose one")
        matches = candidates
    return {**dep, "project": repository, "product": product}, matches
