"""DefectDojo integration (API v2): fetch findings for FP review and write the verdict back.

Endpoints used (all under <url>/api/v2/, header `Authorization: Token <token>`):
  GET   findings/{id}/                 one finding
  GET   findings/?<filters>&limit&offset  a filtered list (follows `next` only on the same base URL)
  GET   tests/{id}/, engagements/{id}/, test_types/{id}/   repository/branch/commit and tool context
  GET   findings/{id}/files/           files already attached (skips re-uploading the same report)
  POST  findings/{id}/files/           attach the Word report (multipart: title, file)
  POST  findings/{id}/notes/           the Threatlint note ({"entry": …})
  PATCH findings/{id}/                 FALSE POSITIVE: false_p=true, active=false, verified=false
                                       TRUE POSITIVE:  verified=true (false_p=false, active=true when it was a FP)

The report is attached first so a finding is never closed without its evidence; the note texts are exactly those
of `threatlint avit resolve`.
"""

from __future__ import annotations

import json
import re
import urllib.parse

from threatlint.scanners.base import (AMBIGUOUS_COMMENT, CLOSING_COMMENT, MAX_BY_ID, TRUE_POSITIVE_COMMENT, Adapter,
                                      ScannerError, context_from_repository_url, request)

_REFERENCE = re.compile(r"(?:DOJO-|DOJO:|DEFECTDOJO-)?(\d{1,12})", re.IGNORECASE)
_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
MAX_SEARCH = 500
_MAX_FIELD = 4000
_SKIPPED = frozenset({"files", "notes", "request_response", "finding_meta", "display_status", "accepted_risks", "jira_creation", "jira_change",
                      "push_to_jira", "related_fields", "age", "sla_days_remaining", "sla_expiration_date"})
_HINTS = {401: " Check the DefectDojo API v2 token.", 403: " The token's user lacks permission for this product or operation.",
          404: " The finding (or the API path) was not found; check the id and the base URL."}


def _text(value) -> str:
    if value is None or value == "" or value == []:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    return str(value).strip()[:_MAX_FIELD]


class DefectDojo(Adapter):
    name = "defectdojo"
    command = "dojo"
    label = "DefectDojo"
    config_file = "defectdojo.json"
    url_env = "THREATLINT_DOJO_URL"
    token_env = "THREATLINT_DOJO_TOKEN"
    token_parameter = "dojoTokenParameter"
    reference_example = "DOJO-123"
    supports_attachments = True

    def auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Token {token}"}

    def _get(self, url: str, token: str, path: str):
        return request(f"{url}/api/v2/{path}", label=self.label, headers=self.auth_headers(token), hints=_HINTS)

    # References -----------------------------------------------------------
    def parse_references(self, values) -> list[str]:
        text = " ".join(values) if isinstance(values, (list, tuple)) else str(values or "")
        tokens = [token for token in re.split(r"[\s,;]+", text) if token]
        invalid = [token for token in tokens if not _REFERENCE.fullmatch(token)]
        if invalid:
            raise ScannerError(f"Not a DefectDojo finding id: {', '.join(invalid[:5])} (expected a number such as 123 or DOJO-123)")
        references = list(dict.fromkeys(f"DOJO-{int(_REFERENCE.fullmatch(token).group(1))}" for token in tokens))
        if not references:
            raise ScannerError("Enter at least one DefectDojo finding id")
        if len(references) > MAX_BY_ID:
            raise ScannerError(f"Review at most {MAX_BY_ID} DefectDojo findings per report")
        return references

    @staticmethod
    def finding_id(reference: str) -> int:
        return int(reference.split("-", 1)[1])

    # Fetch ------------------------------------------------------------------
    def _related(self, url: str, token: str, finding: dict, cache: dict) -> tuple[dict, dict, str]:
        """(test, engagement, test type name) for a finding; empty when the token cannot read them."""
        def get(kind: str, ident) -> dict:
            if isinstance(ident, dict):
                return ident
            if not isinstance(ident, int) and not str(ident or "").isdigit():
                return {}
            key = (kind, int(ident))
            if key not in cache:
                try:
                    cache[key] = self._get(url, token, f"{kind}/{int(ident)}/") or {}
                except ScannerError:
                    cache[key] = {}
            return cache[key]
        test = get("tests", finding.get("test"))
        engagement = get("engagements", test.get("engagement"))
        test_type = test.get("test_type_name") or ""
        if not test_type and test.get("test_type") is not None:
            test_type = test["test_type"].get("name", "") if isinstance(test["test_type"], dict) else get("test_types", test["test_type"]).get("name", "")
        return test, engagement, str(test_type or "")

    def item(self, url: str, token: str, finding: dict, cache: dict | None = None) -> dict:
        """A DefectDojo finding as a review item with repository/branch/file/line/rule/tool context."""
        cache = {} if cache is None else cache
        test, engagement, test_type = self._related(url, token, finding, cache)
        fields = {name: _text(value) for name, value in finding.items() if name not in _SKIPPED}
        fields = {name: value for name, value in fields.items() if value}
        if test_type:
            fields["test_type"] = test_type
        for source, prefix in ((test, "test"), (engagement, "engagement")):
            for name in ("title", "name", "branch_tag", "commit_hash", "build_id", "source_code_management_uri", "product"):
                if _text(source.get(name)):
                    fields[f"{prefix}.{name}"] = _text(source.get(name))
        repo_url = _text(engagement.get("source_code_management_uri"))
        vulnerability_ids = [str(entry.get("vulnerability_id", "")) for entry in finding.get("vulnerability_ids") or [] if isinstance(entry, dict)]
        rule = _text(finding.get("vuln_id_from_tool")) or ", ".join(filter(None, vulnerability_ids)) or (f"CWE-{finding['cwe']}" if finding.get("cwe") else "")
        line = finding.get("line") or finding.get("sast_source_line")
        context = {**context_from_repository_url(repo_url),
                   "branch": _text(test.get("branch_tag")) or _text(engagement.get("branch_tag")),
                   "commit": _text(test.get("commit_hash")) or _text(engagement.get("commit_hash")),
                   "file_path": _text(finding.get("file_path")) or _text(finding.get("sast_source_file_path")),
                   "line": str(line) if isinstance(line, int) or str(line or "").isdigit() else "",
                   "rule": rule, "finding_source": test_type or _text(finding.get("found_by")),
                   "component": " ".join(filter(None, (_text(finding.get("component_name")), _text(finding.get("component_version")))))}
        if repo_url and not context.get("repository"):
            context["repository_url"] = repo_url
        reference = f"DOJO-{int(finding['id'])}"
        return {"reference": reference, "id": str(finding["id"]), "title": _text(finding.get("title")) or reference,
                "severity": _text(finding.get("severity")) or "Info", "kind": "finding",
                "web_url": f"{url}/finding/{int(finding['id'])}", "fields": fields,
                "context": {key: value for key, value in context.items() if value},
                "state": {key: bool(finding.get(key)) for key in ("active", "verified", "false_p", "is_mitigated")}}

    def get(self, url: str, token: str, reference: str) -> dict:
        try:
            finding = self._get(url, token, f"findings/{self.finding_id(reference)}/")
        except ScannerError as exc:
            if getattr(exc, "status", None) == 404:
                raise ScannerError(f"{reference} was not found or is not readable with this token") from exc
            raise
        if not isinstance(finding, dict) or "id" not in finding:
            raise ScannerError(f"{reference} returned an unexpected record")
        return self.item(url, token, finding)

    def fetch(self, url: str, token: str, references: list[str]) -> tuple[list[dict], list[str]]:
        items, missing, cache = [], [], {}
        for reference in references:
            try:
                finding = self._get(url, token, f"findings/{self.finding_id(reference)}/")
            except ScannerError as exc:
                if getattr(exc, "status", None) in (403, 404):
                    missing.append(reference)
                    continue
                raise
            items.append(self.item(url, token, finding, cache))
        return items, missing

    def add_filter_arguments(self, parser) -> None:
        parser.add_argument("--product", type=int, help="Product id (test__engagement__product)")
        parser.add_argument("--engagement", type=int, help="Engagement id")
        parser.add_argument("--test", type=int, help="Test id")
        parser.add_argument("--active", choices=("true", "false"), help="Only active (true) or inactive (false) findings")
        parser.add_argument("--verified", choices=("true", "false"), help="Only verified (true) or unverified (false) findings")
        parser.add_argument("--severity", action="append", choices=_SEVERITIES, help="Severity (repeatable)")
        parser.add_argument("--tag", action="append", default=[], help="Tag (repeatable; findings with any of them)")
        parser.add_argument("--limit", type=int, default=MAX_BY_ID, help=f"Most findings to fetch (default {MAX_BY_ID}, at most {MAX_SEARCH})")

    def filters(self, args) -> dict:
        values = {"test__engagement__product": getattr(args, "product", None), "test__engagement": getattr(args, "engagement", None),
                  "test": getattr(args, "test", None), "active": getattr(args, "active", None), "verified": getattr(args, "verified", None),
                  "severity": ",".join(getattr(args, "severity", None) or []) or None, "tags": ",".join(getattr(args, "tag", None) or []) or None,
                  "limit": getattr(args, "limit", None)}
        return {key: value for key, value in values.items() if value not in (None, "")}

    def search(self, url: str, token: str, filters: dict) -> list[dict]:
        limit = int(filters.get("limit") or MAX_BY_ID)
        if not 1 <= limit <= MAX_SEARCH:
            raise ScannerError(f"--limit must be 1 to {MAX_SEARCH}")
        if not any(key in filters for key in ("test__engagement__product", "test__engagement", "test", "tags")):
            raise ScannerError("Narrow the search with --product, --engagement, --test, or --tag (or pass finding ids)")
        for key in ("test__engagement__product", "test__engagement", "test"):
            if key in filters and int(filters[key]) < 1:
                raise ScannerError(f"{key} must be a positive id")
        query = {key: str(value) for key, value in filters.items() if key != "limit"}
        query.update({"limit": str(min(limit, 100)), "offset": "0", "ordering": "id"})
        page_url, findings, cache = f"{url}/api/v2/findings/?{urllib.parse.urlencode(query)}", [], {}
        while page_url and len(findings) < limit:
            page = request(page_url, label=self.label, headers=self.auth_headers(token), hints=_HINTS) or {}
            findings += [row for row in page.get("results", []) if isinstance(row, dict) and "id" in row]
            following = page.get("next")
            # Follow pagination only on the validated base URL; the token must never go elsewhere.
            page_url = following if isinstance(following, str) and following.startswith(f"{url}/api/v2/findings/") else None
        return [self.item(url, token, finding, cache) for finding in findings[:limit]]

    # Writes -----------------------------------------------------------------
    def describe(self, disposition: str) -> str:
        return {"FALSE POSITIVE": "attach the report, add the closing note, and mark it false positive (false_p, inactive)",
                "TRUE POSITIVE": "attach the report, add the true-positive note, and mark it verified (it stays active)",
                "AMBIGUOUS": "attach the report and add the ambiguous note (nothing else changes)"}[disposition]

    def attached_titles(self, url: str, token: str, finding_id: int) -> set[str]:
        try:
            payload = self._get(url, token, f"findings/{finding_id}/files/") or {}
        except ScannerError:
            return set()
        rows = payload.get("files", payload.get("results", [])) if isinstance(payload, dict) else payload
        return {str(row.get("title", "")) for row in rows or [] if isinstance(row, dict)}

    def attach(self, url: str, token: str, finding_id: int, name: str, content: bytes, content_type: str) -> None:
        from threatlint.scanners.base import multipart  # noqa: PLC0415
        body, content_type_header = multipart({"title": name}, [("file", name, content, content_type)])
        request(f"{url}/api/v2/findings/{finding_id}/files/", label=self.label, method="POST", data=body,
                headers={**self.auth_headers(token), "Content-Type": content_type_header}, hints=_HINTS)

    def note(self, url: str, token: str, item: dict, message: str) -> None:
        request(f"{url}/api/v2/findings/{int(item['id'])}/notes/", label=self.label, method="POST",
                data=json.dumps({"entry": message, "private": False}).encode(),
                headers={**self.auth_headers(token), "Content-Type": "application/json"}, hints=_HINTS)

    def patch(self, url: str, token: str, finding_id: int, values: dict) -> dict:
        return request(f"{url}/api/v2/findings/{finding_id}/", label=self.label, method="PATCH", data=json.dumps(values).encode(),
                       headers={**self.auth_headers(token), "Content-Type": "application/json"}, hints=_HINTS) or {}

    def resolve(self, url: str, token: str, item: dict, verdict: dict, *, files: list[tuple[str, bytes, str]], args=None) -> dict:
        disposition = verdict["disposition"]
        finding_id = int(item["id"])
        existing = self.attached_titles(url, token, finding_id)
        attached = []
        # Attach first so the finding is never closed without its evidence.
        for name, content, content_type in files:
            if name in existing:
                print(f"  ✓ {name} is already attached")
                attached.append({"name": name, "alreadyAttached": True})
                continue
            self.attach(url, token, finding_id, name, content, content_type)
            print(f"  ✓ Attached {name}")
            attached.append({"name": name})
        note = CLOSING_COMMENT if disposition == "FALSE POSITIVE" else AMBIGUOUS_COMMENT if disposition == "AMBIGUOUS" else TRUE_POSITIVE_COMMENT
        self.note(url, token, item, note)
        print("  ✓ Note added")
        result = {"reference": item["reference"], "disposition": disposition, "note": note, "attachments": attached, "closed": False, "url": item.get("web_url")}
        if disposition == "FALSE POSITIVE":
            # DefectDojo refuses a finding that is both false positive and active or verified.
            stored = self.patch(url, token, finding_id, {"false_p": True, "active": False, "verified": False})
            result["closed"] = bool(stored.get("false_p")) and not stored.get("active")
            result["action"] = "closed" if result["closed"] else "close not applied"
            print("  ✓ Marked false positive (inactive)" if result["closed"] else f"  ! DefectDojo kept false_p={stored.get('false_p')} active={stored.get('active')}")
        elif disposition == "TRUE POSITIVE":
            values = {"verified": True}
            if item.get("state", {}).get("false_p"):
                values.update({"false_p": False, "active": True})
                print("  ! It was marked false positive; reopening it as an active, verified finding")
            stored = self.patch(url, token, finding_id, values)
            result["action"] = "verified" if stored.get("verified") else "verify not applied"
            print("  ✓ Marked verified; finding left active" if stored.get("verified") else "  ! DefectDojo did not store verified=true")
        else:
            result["action"] = "noted"
            print("  ✓ Finding left unchanged apart from the note")
        return result

    def validate_token(self, url: str, token: str) -> None:
        request(f"{url}/api/v2/findings/?limit=1", label=self.label, headers=self.auth_headers(token), hints=_HINTS)

    def semgrep_applicable(self, item: dict) -> bool:
        return "semgrep" in item.get("context", {}).get("finding_source", "").lower()


ADAPTER = DefectDojo()
