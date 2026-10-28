"""Azure DevOps and ServiceNow calls for Sidekick, on Threatlint's HTTP helpers and credentials.

Every ServiceNow query value is checked for the encoded-query separator `^` before it is used, so a
repository, project or email cannot change the query (the standalone app did not check these).
"""

from __future__ import annotations

import base64
import concurrent.futures
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from threatlint import ado_login
from threatlint import servicenow as sn
from threatlint.tls import ssl_context

ADO_API = "7.1"
RETRY_STATUS = (429, 500, 502, 503, 504)


class SidekickError(RuntimeError):
    """A user-actionable failure; messages never contain credentials."""


def _safe(value: str, what: str) -> str:
    value = str(value or "").strip()
    if "^" in value or "\n" in value:
        raise SidekickError(f"The {what} must not contain ^ or a line break")
    return value


def _http(url: str, *, headers: dict, data: bytes | None = None, method: str | None = None, timeout: int = 120, attempts: int = 5):
    """(status, headers, body) with retries on 429/5xx and network errors; 2-second linear backoff."""
    last = None
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=ssl_context()) as response:  # noqa: S310 - fixed HTTPS hosts
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as exc:
            if exc.code in RETRY_STATUS and attempt < attempts:
                last = exc
                time.sleep(2 * attempt)
                continue
            body = exc.read()[:300]
            raise SidekickError(f"HTTP {exc.code} from {urllib.parse.urlsplit(url).netloc}: {body.decode('utf-8', 'replace')}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            last = exc
            if attempt < attempts:
                time.sleep(2 * attempt)
                continue
    raise SidekickError(f"{urllib.parse.urlsplit(url).netloc} did not respond after {attempts} attempts: {last}")


# ── Azure DevOps ──────────────────────────────────────────────────────────────

class Ado:
    def __init__(self, organization: str):
        pat, _source = ado_login.load(organization)
        if not pat:
            raise SidekickError(f"No Azure DevOps PAT for {organization}. Run `threatlint ado login --organization {organization}`.")
        self.organization = organization
        self._auth = "Basic " + base64.b64encode(f":{pat}".encode()).decode()

    def _get(self, path: str, **query) -> tuple[dict, dict]:
        query["api-version"] = ADO_API
        url = f"https://dev.azure.com/{urllib.parse.quote(self.organization)}/{path}?{urllib.parse.urlencode(query)}"
        _status, headers, body = _http(url, headers={"Authorization": self._auth, "Accept": "application/json"})
        if not body.lstrip().startswith(b"{"):
            raise SidekickError(f"Azure DevOps did not accept the PAT for {self.organization}")
        return json.loads(body), headers

    def branch_stats(self, project: str, repository: str) -> list[dict]:
        """[{name, date, email}] using the committer, else the author, of each branch's head commit."""
        data, _ = self._get(f"{urllib.parse.quote(project)}/_apis/git/repositories/{urllib.parse.quote(repository)}/stats/branches")
        out = []
        for branch in data.get("value", []):
            commit = branch.get("commit") or {}
            who = commit.get("committer") or {}
            author = commit.get("author") or {}
            out.append({"name": branch.get("name", ""), "date": who.get("date") or author.get("date") or "",
                        "email": who.get("email") or author.get("email") or ""})
        return out

    def repositories(self) -> list[dict]:
        """Every repository in the organization: [{name, project}]."""
        try:
            data, _ = self._get("_apis/git/repositories")
            repos = data.get("value", [])
        except SidekickError:
            repos = []
        if len(repos) >= 100:
            return [{"name": r.get("name", ""), "project": (r.get("project") or {}).get("name", "")} for r in repos]
        projects, token = [], None
        while True:
            query = {"$top": 500, **({"continuationToken": token} if token else {})}
            data, headers = self._get("_apis/projects", **query)
            projects += [p.get("name", "") for p in data.get("value", [])]
            token = headers.get("x-ms-continuationtoken") or headers.get("X-MS-ContinuationToken")
            if not token:
                break
        def list_project(project: str) -> list[dict]:
            data, _ = self._get(f"{urllib.parse.quote(project)}/_apis/git/repositories")
            return [{"name": r.get("name", ""), "project": project} for r in data.get("value", [])]
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            return [repo for chunk in pool.map(list_project, projects) for repo in chunk]


# ── ServiceNow ────────────────────────────────────────────────────────────────

class ServiceNow:
    """OAuth client-credentials session with a single-flight token refresh on 401."""

    def __init__(self, instance: str, client_id: str, client_secret: str):
        self.instance = sn.validate_instance_url(instance)
        self._id, self._secret = client_id, client_secret
        self._token, self._lock = "", threading.Lock()
        self.limit = threading.Semaphore(4)   # ServiceNow throttles; at most 4 concurrent calls

    @classmethod
    def from_config(cls, profile: str | None = None) -> "ServiceNow":
        instance = sn.saved_config().get("instance") or ""
        if not instance:
            raise SidekickError("No ServiceNow instance is configured. Run `threatlint setup`.")
        client_id, client_secret = sn.resolve_credentials(profile)
        return cls(instance, client_id, client_secret)

    def _token_now(self, stale: str = "") -> str:
        with self._lock:
            if not self._token or self._token == stale:
                self._token = sn.access_token(self.instance, self._id, self._secret)
            return self._token

    def request(self, path: str, *, query: dict | None = None, body=None, method: str | None = None) -> tuple[dict, dict]:
        url = f"{self.instance}{path}" + (f"?{urllib.parse.urlencode(query)}" if query else "")
        data = json.dumps(body).encode() if body is not None else None
        token = self._token_now()
        for attempt in (1, 2):
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json", **({"Content-Type": "application/json"} if data else {})}
            try:
                with self.limit:
                    _status, response_headers, raw = _http(url, headers=headers, data=data, method=method)
                return (json.loads(raw) if raw.strip() else {}), response_headers
            except SidekickError as exc:
                if "HTTP 401" in str(exc) and attempt == 1:
                    token = self._token_now(stale=token)
                    continue
                raise
        raise SidekickError("ServiceNow rejected the token")

    def count(self, query: str) -> int:
        data, _ = self.request(f"/api/now/stats/{sn.AVIT_TABLE}", query={"sysparm_query": query, "sysparm_count": "true"})
        result = data.get("result") or {}
        value = (result.get("stats") or {}).get("count", result.get("count"))
        if value is None:
            raise SidekickError("ServiceNow returned no count")
        return int(value)

    def counts_by_repository(self, query: str) -> list[dict]:
        data, _ = self.request(f"/api/now/stats/{sn.AVIT_TABLE}", query={"sysparm_query": query, "sysparm_count": "true",
                                                                          "sysparm_group_by": "u_repository,project_name"})
        rows = []
        for item in data.get("result") or []:
            fields = {f.get("field"): f.get("value", "") for f in item.get("groupby_fields", [])}
            if fields.get("u_repository"):
                rows.append({"repo": fields["u_repository"], "project": fields.get("project_name", ""),
                             "count": int((item.get("stats") or {}).get("count", 0))})
        return sorted(rows, key=lambda row: (-row["count"], row["repo"].lower()))

    def user(self, email: str) -> dict | None:
        email = _safe(email, "email")
        data, _ = self.request("/api/now/table/sys_user", query={"sysparm_query": f"email={email}^active=true",
                                                                 "sysparm_fields": "sys_id,name,user_name,title,email,manager", "sysparm_limit": "1"})
        rows = data.get("result") or []
        return rows[0] if rows else None

    def user_by_id(self, sys_id: str) -> dict | None:
        try:
            data, _ = self.request(f"/api/now/table/sys_user/{urllib.parse.quote(sys_id)}",
                                   query={"sysparm_fields": "sys_id,name,user_name,title,email,manager"})
        except SidekickError:
            return None
        return data.get("result") or None

    def search(self, query: str, limit: int = 100, offset: int = 0, fields: str = "") -> tuple[list[dict], int | None]:
        data, headers = self.request(f"/api/now/table/{sn.AVIT_TABLE}", query={
            "sysparm_query": query, "sysparm_limit": str(max(1, min(limit, 2000))), "sysparm_offset": str(offset),
            "sysparm_display_value": "true", "sysparm_exclude_reference_link": "true",
            "sysparm_fields": fields or "sys_id,number,project_name,u_repository,project_branch,vulnerability,u_security_finding_source,risk_rating,state,active"})
        total = headers.get("X-Total-Count") or headers.get("x-total-count")
        flat = [{k: (v.get("display_value") if isinstance(v, dict) else v) for k, v in row.items()} for row in data.get("result") or []]
        return flat, int(total) if str(total or "").isdigit() else None

    def batch_patch(self, sys_ids: list[str], body: dict, request_id: str) -> dict[str, str | None]:
        """PATCH each record through the Batch API; {sys_id: error or None}. Unserviced ids are resubmitted twice."""
        encoded = base64.b64encode(json.dumps(body).encode()).decode()
        outcome: dict[str, str | None] = {}
        pending = list(sys_ids)
        for _attempt in range(3):
            if not pending:
                break
            requests = [{"id": str(index), "exclude_response_headers": True, "method": "PATCH",
                         "url": f"/api/now/table/{sn.AVIT_TABLE}/{sys_id}",
                         "headers": [{"name": "Content-Type", "value": "application/json"}, {"name": "Accept", "value": "application/json"}],
                         "body": encoded} for index, sys_id in enumerate(pending)]
            data, _ = self.request("/api/now/v1/batch", body={"batch_request_id": request_id, "rest_requests": requests}, method="POST")
            served = {item.get("id"): item.get("status_code") for item in data.get("serviced_requests") or []}
            retry = []
            for index, sys_id in enumerate(pending):
                status = served.get(str(index))
                if status is None:
                    retry.append(sys_id)
                else:
                    outcome[sys_id] = None if 200 <= int(status) < 300 else f"ServiceNow returned HTTP {status}"
            pending = retry
        for sys_id in pending:
            outcome[sys_id] = "not serviced by the Batch API after 3 attempts"
        return outcome


# ── Conditions → encoded query (AVIT Closure) ─────────────────────────────────

FIELDS = ("active", "state", "number", "u_repository", "project_name", "project_branch", "vulnerability",
          "u_security_finding_source", "risk_rating")
OPERATORS = {"=": "=", "!=": "!=", "LIKE": "LIKE", "NOT LIKE": "NOT LIKE", "STARTSWITH": "STARTSWITH",
             "ENDSWITH": "ENDSWITH", "ISEMPTY": "ISEMPTY", "ISNOTEMPTY": "ISNOTEMPTY"}


def build_query(conditions: list[dict]) -> str:
    """[{field, operator, value, join: AND|OR}] → ServiceNow encoded query."""
    parts = []
    for index, condition in enumerate(conditions or []):
        field = condition.get("field", "")
        if field == "normalized_severity":
            field = "risk_rating"
        if field not in FIELDS:
            raise SidekickError(f"Unknown field {field}")
        operator = OPERATORS.get(str(condition.get("operator", "")).upper())
        if not operator:
            raise SidekickError(f"Unknown operator {condition.get('operator')}")
        value = "" if operator in ("ISEMPTY", "ISNOTEMPTY") else _safe(condition.get("value", ""), field)
        if operator not in ("ISEMPTY", "ISNOTEMPTY") and not value:
            raise SidekickError(f"{field} needs a value")
        clause = f"{field}{operator}{value}"
        parts.append(clause if index == 0 else ("^OR" if str(condition.get("join", "AND")).upper() == "OR" else "^") + clause)
    return "".join(parts)
