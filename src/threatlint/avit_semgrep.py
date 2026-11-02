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
    return str(value or "").replace("\\", "/").lstrip("./")


def same_path(found: str, wanted: str) -> bool:
    a, b = tail(found), tail(wanted)
    return bool(a and b) and (a == b or a.endswith("/" + b) or b.endswith("/" + a))


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
    named = list(dict.fromkeys(name for name in (f"{target.get('project')}/{target['name']}" if target.get("project") else "",
                                                 f"{target.get('organization')}/{target['name']}") if name and not name.startswith("/")))
    if not line.isdigit():
        line = report_line(report_text, context.get("avit", "")) if report_text else None
        line = str(line) if line else ""
    if not line.isdigit():
        raise ResolveError("Neither the AVIT nor the report records the flagged line, so the Semgrep finding cannot be matched narrowly; pass --line")
    near = lambda found: found is not None and abs(int(found) - int(line)) <= 3
    matches = []
    if kind in ("sast", "sca"):
        for project in named:
            for page in range(20):
                params = urllib.parse.urlencode({"issue_type": kind, "repos": project, "status": "open", "dedup": "true", "page": page, "page_size": 100})
                findings = query(f"/deployments/{urllib.parse.quote(dep['slug'])}/findings?{params}", token).get("findings", [])
                for finding in findings:
                    name = str(finding.get("rule_name") or (finding.get("rule") or {}).get("name", ""))
                    location = finding.get("location") or {}
                    if rule and not (name == rule or name.endswith("." + rule) or rule.endswith("." + name)):
                        continue
                    if same_path(location.get("file_path", ""), path) and near(location.get("line")):
                        matches.append({"id": int(finding["id"]), "rule": name, "path": location.get("file_path"), "line": location.get("line"), "ref": finding.get("ref")})
                if len(findings) < 100:
                    break
            if matches:
                break
    else:
        cursor = ""
        for _ in range(20):
            params = urllib.parse.urlencode({"limit": 100, **({"cursor": cursor} if cursor else {}), **{"repo": named[0]}})
            data = query(f"/deployments/{dep['id']}/secrets?{params}", token)
            for finding in data.get("findings", []):
                found_path, _, found_line = str(finding.get("findingPath", "")).rpartition(":")
                if not found_path:
                    found_path, found_line = finding.get("findingPath", ""), ""
                status = str(finding.get("status", ""))
                if any(word in status for word in ("FIXED", "IGNORED", "REMOVED")):
                    continue
                if same_path(found_path, path) and near(found_line or None):
                    matches.append({"id": int(finding["id"]), "rule": finding.get("type"), "path": found_path, "line": found_line or None, "ref": finding.get("ref")})
            cursor = data.get("cursor") or ""
            if not cursor or not data.get("findings"):
                break
    return dep, matches
