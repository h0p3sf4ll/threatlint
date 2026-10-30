"""SonarQube / SonarCloud integration: fetch security issues and hotspots for FP review and write the verdict back.

Endpoints used (token as HTTP Basic user with an empty password, which every SonarQube version and SonarCloud accept):
  GET  /api/issues/search            issues=<keys> or componentKeys/branch/types/severities/statuses, p/ps paging
  GET  /api/hotspots/search          projectKey/branch/status, or hotspots=<keys>
  GET  /api/hotspots/show            one hotspot (rule, component path, line)
  GET  /api/project_links/search     the project's SCM link (repository URL)
  GET  /api/alm_settings/get_binding the DevOps platform binding, when readable (fallback for the repository)
  POST /api/issues/add_comment       the Threatlint comment (issues)
  POST /api/issues/do_transition     FALSE POSITIVE: falsepositive; TRUE POSITIVE: confirm (when the server offers it)
  POST /api/hotspots/change_status   FALSE POSITIVE: REVIEWED / SAFE with the comment
  POST /api/hotspots/add_comment     TRUE POSITIVE / AMBIGUOUS on a hotspot: comment only
  GET  /api/authentication/validate  token check for `threatlint sonar login`

SonarQube cannot store attachments, so the comment carries a short summary and says where the full report lives.
"""

from __future__ import annotations

import base64
import os
import re
import urllib.parse

from threatlint.scanners.base import MAX_BY_ID, Adapter, ScannerError, context_from_repository_url, request

_KEY = r"[A-Za-z0-9_-]{6,64}"
_REFERENCE = re.compile(rf"(?:(SONAR-HOTSPOT-|HOTSPOT-)|(?:SONAR-)?)({_KEY})", re.IGNORECASE)
MAX_SEARCH = 500
_TYPES = ("VULNERABILITY", "BUG", "CODE_SMELL", "SECURITY_HOTSPOT")
_SEVERITIES = ("BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO")
_HINTS = {401: " Check the SonarQube token.", 403: " The token lacks permission (Browse to read; Administer Issues / Administer Security Hotspots to change status).",
          404: " The issue, hotspot, or project was not found; check the key and the base URL.", 400: " SonarQube rejected the request."}
FP_SUMMARY = "Closed by Threatlint as a false positive."
TP_SUMMARY = "True positive per Threatlint review; left open."
AMBIGUOUS_SUMMARY = "Ambiguous per Threatlint review; left open pending the evidence the report names."


def _text(value) -> str:
    return "" if value is None else str(value).strip()[:4000]


def comment_for(verdict: dict, where: str) -> str:
    """The SonarQube comment: outcome, a one-line summary, and where the full report lives (no attachments here)."""
    outcome = {"FALSE POSITIVE": FP_SUMMARY, "TRUE POSITIVE": TP_SUMMARY}.get(verdict["disposition"], AMBIGUOUS_SUMMARY)
    summary = " ".join(filter(None, (verdict.get("id"), f"({verdict['confidence']})" if verdict.get("confidence") else "")))
    title = re.sub(r"\s+", " ", verdict.get("title", "")).strip()[:200]
    return f"{outcome} Summary: {summary}{' — ' + title if title else ''}. Full report: {where}."[:4000]


class SonarQube(Adapter):
    name = "sonarqube"
    command = "sonar"
    label = "SonarQube"
    config_file = "sonarqube.json"
    url_env = "THREATLINT_SONAR_URL"
    token_env = "THREATLINT_SONAR_TOKEN"
    token_parameter = "sonarTokenParameter"
    reference_example = "SONAR-AYxExampleKey01 or SONAR-HOTSPOT-AYxExampleKey02"

    def auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": "Basic " + base64.b64encode(f"{token}:".encode()).decode()}

    def _get(self, url: str, token: str, path: str, params: dict):
        return request(f"{url}{path}?{urllib.parse.urlencode(params)}", label=self.label, headers=self.auth_headers(token), hints=_HINTS) or {}

    def _post(self, url: str, token: str, path: str, params: dict):
        return request(f"{url}{path}", label=self.label, method="POST", data=urllib.parse.urlencode(params).encode(),
                       headers={**self.auth_headers(token), "Content-Type": "application/x-www-form-urlencoded"}, hints=_HINTS)

    # References -----------------------------------------------------------
    def parse_references(self, values) -> list[str]:
        """SONAR-<key> (issue), SONAR-HOTSPOT-<key> (hotspot), or a bare key (an issue, else a hotspot)."""
        text = " ".join(values) if isinstance(values, (list, tuple)) else str(values or "")
        tokens = [token for token in re.split(r"[\s,;]+", text) if token]
        invalid = [token for token in tokens if not _REFERENCE.fullmatch(token)]
        if invalid:
            raise ScannerError(f"Not a SonarQube issue or hotspot key: {', '.join(invalid[:5])} (e.g. SONAR-AYxExampleKey01 or SONAR-HOTSPOT-AYxExampleKey02)")
        references = []
        for token in tokens:
            match = _REFERENCE.fullmatch(token)
            references.append(f"SONAR-HOTSPOT-{match.group(2)}" if match.group(1) else f"SONAR-{match.group(2)}")
        references = list(dict.fromkeys(references))
        if not references:
            raise ScannerError("Enter at least one SonarQube issue or hotspot key")
        if len(references) > MAX_BY_ID:
            raise ScannerError(f"Review at most {MAX_BY_ID} SonarQube findings per report")
        return references

    @staticmethod
    def key(reference: str) -> tuple[str, bool]:
        """(key, is_hotspot) for a canonical reference."""
        if reference.upper().startswith("SONAR-HOTSPOT-"):
            return reference[len("SONAR-HOTSPOT-"):], True
        return reference[len("SONAR-"):], False

    # Context ---------------------------------------------------------------
    def repository_context(self, url: str, token: str, project: str, cache: dict) -> dict[str, str]:
        """GitHub / Azure DevOps context for the project from its SCM link, else its DevOps binding; {} when neither is readable."""
        override = os.environ.get("THREATLINT_SONAR_REPO_URL", "")
        if override:
            return context_from_repository_url(override)
        if not project:
            return {}
        if project in cache:
            return cache[project]
        context: dict[str, str] = {}
        try:
            links = self._get(url, token, "/api/project_links/search", {"projectKey": project}).get("links", [])
            scm = next((link.get("url") for link in links if isinstance(link, dict) and str(link.get("type", "")).lower() == "scm"), "")
            context = context_from_repository_url(re.sub(r"^scm:git:", "", str(scm or "")))
        except ScannerError:
            pass
        if not context:
            try:
                binding = self._get(url, token, "/api/alm_settings/get_binding", {"project": project})
                alm, repository = str(binding.get("alm", "")).lower(), str(binding.get("repository", ""))
                if alm == "github" and "/" in repository:
                    owner, name = repository.split("/", 1)
                    context = {"scm_tool": "GitHub", "organization": owner, "repository": name}
                elif alm == "azure" and binding.get("slug"):
                    organization = urllib.parse.urlsplit(str(binding.get("url", ""))).path.strip("/").split("/")[0]
                    if organization:
                        context = {"scm_tool": "ADO", "organization": organization, "project": repository, "repository": str(binding["slug"])}
            except ScannerError:
                pass
        cache[project] = context
        return context

    def _issue_item(self, url: str, token: str, issue: dict, components: dict, cache: dict, branch: str = "") -> dict:
        component = str(issue.get("component", ""))
        path = components.get(component) or (component.split(":", 1)[1] if ":" in component else "")
        project = str(issue.get("project") or component.split(":", 1)[0])
        line = issue.get("line") or (issue.get("textRange") or {}).get("startLine")
        fields = {name: _text(value) for name, value in issue.items() if not isinstance(value, (dict, list)) and _text(value)}
        for name in ("tags", "impacts"):
            if issue.get(name):
                fields[name] = _text(issue[name])
        key = str(issue["key"])
        context = {**self.repository_context(url, token, project, cache), "branch": _text(issue.get("branch")) or branch, "file_path": path,
                   "line": str(line) if str(line or "").isdigit() else "", "rule": _text(issue.get("rule")), "finding_source": f"SonarQube {issue.get('type', 'issue')}".strip(),
                   "project_key": project}
        query = urllib.parse.urlencode({"id": project, "issues": key, "open": key, **({"branch": context["branch"]} if context["branch"] else {})})
        return {"reference": f"SONAR-{key}", "id": key, "title": _text(issue.get("message")) or key, "severity": _text(issue.get("severity")) or "INFO",
                "kind": "issue", "web_url": f"{url}/project/issues?{query}", "fields": fields, "context": {k: v for k, v in context.items() if v},
                "state": {"status": _text(issue.get("status")), "resolution": _text(issue.get("resolution"))}}

    def _hotspot_item(self, url: str, token: str, hotspot: dict, components: dict, cache: dict, branch: str = "") -> dict:
        component = hotspot.get("component")
        if isinstance(component, dict):
            path, component_key = _text(component.get("path")), _text(component.get("key"))
        else:
            component_key = str(component or "")
            path = components.get(component_key) or (component_key.split(":", 1)[1] if ":" in component_key else "")
        project = hotspot.get("project")
        project = _text(project.get("key")) if isinstance(project, dict) else _text(project) or component_key.split(":", 1)[0]
        rule = hotspot.get("rule")
        rule = _text(rule.get("key")) if isinstance(rule, dict) else _text(hotspot.get("ruleKey") or rule)
        line = hotspot.get("line") or (hotspot.get("textRange") or {}).get("startLine")
        fields = {name: _text(value) for name, value in hotspot.items() if not isinstance(value, (dict, list)) and _text(value)}
        if isinstance(hotspot.get("rule"), dict):
            for name in ("name", "securityCategory", "vulnerabilityProbability", "riskDescription", "vulnerabilityDescription"):
                if _text(hotspot["rule"].get(name)):
                    fields[f"rule.{name}"] = _text(hotspot["rule"][name])
        key = str(hotspot["key"])
        context = {**self.repository_context(url, token, project, cache), "branch": _text(hotspot.get("branch")) or branch, "file_path": path,
                   "line": str(line) if str(line or "").isdigit() else "", "rule": rule, "finding_source": "SonarQube security hotspot", "project_key": project}
        query = urllib.parse.urlencode({"id": project, "hotspots": key, **({"branch": context["branch"]} if context["branch"] else {})})
        return {"reference": f"SONAR-HOTSPOT-{key}", "id": key, "title": _text(hotspot.get("message")) or key,
                "severity": _text(hotspot.get("vulnerabilityProbability")) or "MEDIUM", "kind": "hotspot", "web_url": f"{url}/security_hotspots?{query}",
                "fields": fields, "context": {k: v for k, v in context.items() if v},
                "state": {"status": _text(hotspot.get("status")), "resolution": _text(hotspot.get("resolution"))}}

    @staticmethod
    def _components(payload: dict) -> dict[str, str]:
        return {str(item.get("key")): str(item.get("path") or "") for item in payload.get("components", []) if isinstance(item, dict) and item.get("path")}

    def _issues_by_key(self, url: str, token: str, keys: list[str], cache: dict) -> dict[str, dict]:
        if not keys:
            return {}
        payload = self._get(url, token, "/api/issues/search", {"issues": ",".join(keys), "ps": str(min(500, max(1, len(keys)))), "additionalFields": "comments"})
        components = self._components(payload)
        return {str(issue["key"]): self._issue_item(url, token, issue, components, cache) for issue in payload.get("issues", []) if isinstance(issue, dict) and issue.get("key")}

    def _hotspot_by_key(self, url: str, token: str, key: str, cache: dict) -> dict | None:
        try:
            hotspot = self._get(url, token, "/api/hotspots/show", {"hotspot": key})
        except ScannerError as exc:
            if getattr(exc, "status", None) in (403, 404):
                return None
            raise
        return self._hotspot_item(url, token, hotspot, {}, cache) if hotspot.get("key") else None

    def fetch(self, url: str, token: str, references: list[str]) -> tuple[list[dict], list[str]]:
        cache: dict = {}
        issue_keys = [self.key(reference)[0] for reference in references if not self.key(reference)[1]]
        issues = self._issues_by_key(url, token, issue_keys, cache)
        items, missing = [], []
        for reference in references:
            key, hotspot = self.key(reference)
            item = None if hotspot else issues.get(key)
            if item is None:
                # A bare key that is not an issue may be a hotspot.
                item = self._hotspot_by_key(url, token, key, cache)
            if item is None:
                missing.append(reference)
            else:
                items.append(item)
        return items, missing

    def get(self, url: str, token: str, reference: str) -> dict:
        items, _missing = self.fetch(url, token, [reference])
        if not items:
            raise ScannerError(f"{reference} was not found or is not readable with this token")
        return items[0]

    def add_filter_arguments(self, parser) -> None:
        parser.add_argument("--project", help="Project key (componentKeys / projectKey)")
        parser.add_argument("--branch", help="Branch name (default: the main branch)")
        parser.add_argument("--pull-request", help="Pull request id instead of a branch")
        parser.add_argument("--organization", help="SonarCloud organization key")
        parser.add_argument("--type", action="append", choices=_TYPES, help="Issue type (repeatable; default VULNERABILITY and SECURITY_HOTSPOT)")
        parser.add_argument("--severity", action="append", choices=_SEVERITIES, help="Issue severity (repeatable)")
        parser.add_argument("--status", action="append", help="Issue status (default OPEN, CONFIRMED, REOPENED) or hotspot status (default TO_REVIEW)")
        parser.add_argument("--limit", type=int, default=MAX_BY_ID, help=f"Most findings to fetch (default {MAX_BY_ID}, at most {MAX_SEARCH})")

    def filters(self, args) -> dict:
        values = {"project": getattr(args, "project", None), "branch": getattr(args, "branch", None), "pullRequest": getattr(args, "pull_request", None),
                  "organization": getattr(args, "organization", None), "types": getattr(args, "type", None) or None,
                  "severities": getattr(args, "severity", None) or None, "statuses": getattr(args, "status", None) or None, "limit": getattr(args, "limit", None)}
        return {key: value for key, value in values.items() if value not in (None, "", [])}

    def search(self, url: str, token: str, filters: dict) -> list[dict]:
        project = filters.get("project")
        if not project or not re.fullmatch(r"[\w.:-]{1,400}", str(project)):
            raise ScannerError("Pass --project with the SonarQube project key (or pass issue keys)")
        limit = int(filters.get("limit") or MAX_BY_ID)
        if not 1 <= limit <= MAX_SEARCH:
            raise ScannerError(f"--limit must be 1 to {MAX_SEARCH}")
        types = list(filters.get("types") or ["VULNERABILITY", "SECURITY_HOTSPOT"])
        scope = {key: str(filters[key]) for key in ("branch", "pullRequest", "organization") if filters.get(key)}
        cache: dict = {}
        items: list[dict] = []
        issue_types = [kind for kind in types if kind != "SECURITY_HOTSPOT"]
        statuses = filters.get("statuses") or []
        if issue_types:
            params = {"componentKeys": project, "types": ",".join(issue_types), "statuses": ",".join(s for s in statuses if s != "TO_REVIEW" and s != "REVIEWED") or "OPEN,CONFIRMED,REOPENED",
                      **({"severities": ",".join(filters["severities"])} if filters.get("severities") else {}), **scope}
            for page in range(1, 21):
                payload = self._get(url, token, "/api/issues/search", {**params, "p": str(page), "ps": "100"})
                components = self._components(payload)
                rows = [row for row in payload.get("issues", []) if isinstance(row, dict) and row.get("key")]
                items += [self._issue_item(url, token, row, components, cache, scope.get("branch", "")) for row in rows]
                total = int((payload.get("paging") or {}).get("total", payload.get("total", 0)) or 0)
                if len(items) >= limit or len(rows) < 100 or page * 100 >= total:
                    break
        if "SECURITY_HOTSPOT" in types and len(items) < limit:
            status = next((s for s in statuses if s in ("TO_REVIEW", "REVIEWED")), "TO_REVIEW")
            params = {"projectKey": project, "status": status, **scope}
            for page in range(1, 21):
                payload = self._get(url, token, "/api/hotspots/search", {**params, "p": str(page), "ps": "100"})
                components = self._components(payload)
                rows = [row for row in payload.get("hotspots", []) if isinstance(row, dict) and row.get("key")]
                items += [self._hotspot_item(url, token, row, components, cache, scope.get("branch", "")) for row in rows]
                total = int((payload.get("paging") or {}).get("total", 0) or 0)
                if len(items) >= limit or len(rows) < 100 or page * 100 >= total:
                    break
        return items[:limit]

    # Writes -----------------------------------------------------------------
    def describe(self, disposition: str) -> str:
        return {"FALSE POSITIVE": "comment with a summary and mark it False Positive (hotspots: Reviewed / Safe)",
                "TRUE POSITIVE": "comment with a summary and confirm it when the server offers Confirm (hotspots: comment only)",
                "AMBIGUOUS": "comment with a summary (nothing else changes)"}[disposition]

    def note(self, url: str, token: str, item: dict, message: str) -> None:
        if item["kind"] == "hotspot":
            self._post(url, token, "/api/hotspots/add_comment", {"hotspot": item["id"], "comment": message})
        else:
            self._post(url, token, "/api/issues/add_comment", {"issue": item["id"], "text": message})

    def resolve(self, url: str, token: str, item: dict, verdict: dict, *, files=None, args=None) -> dict:
        disposition = verdict["disposition"]
        where = (getattr(args, "report_url", None) or "").strip()
        if not where:
            names = [os.path.basename(path) for path in (getattr(args, "docx", None), getattr(args, "report", None)) if path]
            where = f"Threatlint report {names[0]} (kept by the reviewer; SonarQube does not store attachments)" if names else "the Threatlint report kept by the reviewer"
        comment = comment_for(verdict, where)
        result = {"reference": item["reference"], "disposition": disposition, "note": comment, "attachments": [], "closed": False, "url": item.get("web_url")}
        if item["kind"] == "hotspot":
            if disposition == "FALSE POSITIVE":
                self._post(url, token, "/api/hotspots/change_status", {"hotspot": item["id"], "status": "REVIEWED", "resolution": "SAFE", "comment": comment})
                result.update(closed=True, action="closed")
                print("  ✓ Hotspot marked Reviewed / Safe with the Threatlint comment")
            else:
                self.note(url, token, item, comment)
                result["action"] = "noted"
                print("  ✓ Comment added; hotspot left To review")
            return result
        # Comment first so a status change never lands without the reasoning.
        self.note(url, token, item, comment)
        print("  ✓ Comment added")
        transition = {"FALSE POSITIVE": "falsepositive", "TRUE POSITIVE": "confirm"}.get(disposition)
        if not transition:
            result["action"] = "noted"
            print("  ✓ Issue left unchanged apart from the comment")
            return result
        try:
            stored = self._post(url, token, "/api/issues/do_transition", {"issue": item["id"], "transition": transition}) or {}
        except ScannerError as exc:
            if disposition == "TRUE POSITIVE" and getattr(exc, "status", None) == 400:
                # Confirm is not offered for confirmed/accepted issues, or on servers that removed the Confirmed status.
                result["action"] = "noted"
                print("  ! Confirm is not available for this issue on this server; the comment records the verdict")
                return result
            raise
        issue = stored.get("issue", {}) if isinstance(stored, dict) else {}
        if disposition == "FALSE POSITIVE":
            result["closed"] = issue.get("resolution", "FALSE-POSITIVE") == "FALSE-POSITIVE"
            result["action"] = "closed" if result["closed"] else "close not applied"
            print("  ✓ Marked False Positive" if result["closed"] else f"  ! SonarQube stored resolution {issue.get('resolution') or 'none'}")
        else:
            result["action"] = "confirmed"
            print("  ✓ Confirmed; issue left open")
        return result

    def validate_token(self, url: str, token: str) -> None:
        payload = request(f"{url}/api/authentication/validate", label=self.label, headers=self.auth_headers(token), hints=_HINTS) or {}
        if payload.get("valid") is not True:
            raise ScannerError("SonarQube did not accept the token")


ADAPTER = SonarQube()
