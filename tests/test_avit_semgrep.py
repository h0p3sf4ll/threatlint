"""Exact scanner identity, product correlation, and complete pagination."""

import json
import urllib.parse
from types import SimpleNamespace

import pytest

from threatlint import avit_resolve as ar
from threatlint import avit_semgrep as matching
from threatlint import semgrep_platform as sp
from threatlint import servicenow as sn

TARGET = {"organization": "synthetic-org", "project": "Project Name", "name": "repo", "branch": "feature"}
REPOSITORY = "synthetic-org/Project Name/repo"
CONTEXT = {"file_path": "file.py", "rule": "r", "line": "42", "branch": "feature"}
REPORT_AVIT = "AVIT000000000000001"
REPORT_CONTEXT = {**CONTEXT, "avit": REPORT_AVIT, "file_path": "app/utils/auth.py", "line": ""}
PUNCTUATED_REPORT = f"**Original finding**: {REPORT_AVIT}; r; Semgrep Code; app/utils/auth.py:97.  \n"


def finding(identifier=1, **overrides):
    return {"id": identifier, "rule_name": "r", "repository": {"name": REPOSITORY}, "ref": "feature",
            "location": {"file_path": "file.py", "line": 42}, "status": "open", **overrides}


def paged(rows):
    def query(path, token, **kwargs):
        page = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query).get("page", ["0"])[0]
        return {"findings": rows if page == "0" else []}
    return query


@pytest.fixture(autouse=True)
def deployment(monkeypatch):
    monkeypatch.setattr(sp, "deployment", lambda *args: {"slug": "synthetic", "id": 7})


def match(monkeypatch, query, *, kind="sast", context=None, target=None, report_text="synthetic"):
    monkeypatch.setattr(ar, "_semgrep", query)
    return ar.semgrep_matches("synthetic", kind, target or TARGET, context or CONTEXT, report_text=report_text)


def test_transport_keeps_auth_headers_and_original_opener(monkeypatch):
    seen = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return b'{"num_triaged": 1}'

    def open_request(request, **kwargs):
        seen.append((request, kwargs))
        return Response()

    monkeypatch.setattr(sn, "_OPENER", SimpleNamespace(open=open_request))
    assert ar._semgrep("/synthetic", "synthetic-token", body={"synthetic": True}) == {"num_triaged": 1}
    request, kwargs = seen[0]
    assert request.headers["Authorization"] == "Bearer synthetic-token"
    assert json.loads(request.data) == {"synthetic": True}
    assert kwargs == {"timeout": 120}


def test_original_report_line_and_path_collaborators_are_used(monkeypatch):
    monkeypatch.setattr(ar, "_report_line", lambda *args: 42)
    monkeypatch.setattr(ar, "_same_path", lambda *args: True)
    _, matches = match(monkeypatch, paged([finding(location={"file_path": "different.py", "line": 42})]),
                       context={**CONTEXT, "line": ""})
    assert [row["id"] for row in matches] == [1]


def test_report_line_with_terminal_period_keeps_exact_path_rule_and_three_line_window(monkeypatch):
    rows = [finding(line, location={"file_path": "app/utils/auth.py", "line": line})
            for line in (93, 94, 97, 100, 101)]
    rows.extend([
        finding(201, rule_name="other.r", location={"file_path": "app/utils/auth.py", "line": 97}),
        finding(202, location={"file_path": "other/app/utils/auth.py", "line": 97}),
        finding(203, location={"file_path": "app/utils/auth.py", "line": 97}, status="ignored"),
    ])
    calls = []

    def query(path, token, **kwargs):
        calls.append(urllib.parse.parse_qs(urllib.parse.urlsplit(path).query))
        return paged(rows)(path, token, **kwargs)

    _, matches = match(monkeypatch, query, context=REPORT_CONTEXT, report_text=PUNCTUATED_REPORT)
    assert [row["id"] for row in matches] == [94, 97, 100]
    assert all(call["repos"] == [REPOSITORY] and call["ref"] == ["feature"] for call in calls)
    assert all(row["project"] == REPOSITORY and row["ref"] == "feature" and row["rule"] == "r"
               and row["path"] == "app/utils/auth.py" for row in matches)


@pytest.mark.parametrize("overrides", [{"repository": {"name": "other-org/Project Name/repo"}}, {"ref": "another-branch"}])
def test_report_line_fallback_still_rejects_wrong_repository_or_branch(monkeypatch, overrides):
    row = finding(location={"file_path": "app/utils/auth.py", "line": 97}, **overrides)
    with pytest.raises(ar.ResolveError, match="repository|branch"):
        match(monkeypatch, paged([row]), context=REPORT_CONTEXT, report_text=PUNCTUATED_REPORT)


def test_report_line_from_another_file_is_rejected_before_finding_queries(monkeypatch):
    report = PUNCTUATED_REPORT.replace("app/utils/auth.py:97.", "other/utils/auth.py:97.")
    with pytest.raises(ar.ResolveError, match="flagged line"):
        match(monkeypatch, lambda *args, **kwargs: pytest.fail("no finding query with a mismatched report path"),
              context=REPORT_CONTEXT, report_text=report)


@pytest.mark.parametrize(("target", "expected"), [
    ({"organization": "owner", "name": "repo"}, "owner/repo"),
    (TARGET, REPOSITORY),
])
def test_canonical_project_keeps_all_identity_components(target, expected):
    assert matching.tuning_project(target, []) == expected


def test_canonical_repository_and_branch_are_sent_and_retained(monkeypatch):
    calls = []

    def query(path, token):
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
        calls.append(params)
        return {"findings": [finding()] if params["page"] == ["0"] else []}

    dep, matches = match(monkeypatch, query)
    assert all(call["repos"] == [REPOSITORY] and call["ref"] == ["feature"] and call["dedup"] == ["false"] for call in calls)
    assert dep["project"] == matches[0]["project"] == REPOSITORY
    assert matching.tuning_project(TARGET, matches) == REPOSITORY


@pytest.mark.parametrize("overrides", [{"repository": {"name": "other-org/Project Name/repo"}}, {"ref": "another-branch"}])
def test_ignored_repository_or_branch_filters_fail_closed(monkeypatch, overrides):
    with pytest.raises(ar.ResolveError, match="repository|branch"):
        match(monkeypatch, paged([finding(**overrides)]))


def test_matching_uses_exact_rule_and_exact_repository_relative_path(monkeypatch):
    rows = [finding(1, rule_name="other.r"), finding(2, location={"file_path": "other/file.py", "line": 42}), finding(3)]
    _, matches = match(monkeypatch, paged(rows))
    assert [row["id"] for row in matches] == [3]
    assert matching.same_path("./file.py", "/file.py")
    assert not matching.same_path("../file.py", "file.py")


def test_pagination_continues_after_twenty_short_pages(monkeypatch):
    def query(path, token):
        page = int(urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["page"][0])
        return {"findings": [] if page == 22 else [finding(page + 1, location={"file_path": "file.py" if page == 21 else "other.py", "line": 42})]}

    _, matches = match(monkeypatch, query)
    assert [row["id"] for row in matches] == [22]


def test_repeated_pages_are_an_error_not_partial_success(monkeypatch):
    with pytest.raises(ar.ResolveError, match="repeated"):
        match(monkeypatch, lambda *args: {"findings": [finding()]})


def test_servicenow_secret_category_can_resolve_to_code(monkeypatch):
    def query(path, token):
        assert "/findings?" in path
        return paged([finding()])(path, token)

    dep, matches = match(monkeypatch, query, kind="secrets")
    assert dep["product"] == matches[0]["product"] == "sast"


def test_already_ignored_code_finding_is_not_misclassified_as_secrets(monkeypatch):
    def query(path, token):
        assert "/findings?" in path
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
        return {"findings": [finding(status="ignored")] if params["status"] == ["ignored"] and params["page"] == ["0"] else []}

    dep, matches = match(monkeypatch, query, kind="secrets")
    assert dep["product"] == "sast" and matches[0]["status"] == "ignored"

def test_secrets_match_requires_rule_hash_branch_repository_and_file(monkeypatch):
    def query(path, token):
        if "/findings?" in path:
            return {"findings": []}
        base = {"repository": {"name": REPOSITORY}, "ref": "feature", "ruleHashId": "hash",
                "type": "Service name is not a rule", "findingPath": "file.py:42", "status": "FINDING_STATUS_OPEN"}
        return {"findings": [{"id": "1", **base}, {"id": "2", **base, "ruleHashId": "different"},
                             {"id": "3", **base, "ref": "different"}]}

    dep, matches = match(monkeypatch, query, kind="secrets", context={**CONTEXT, "rule_hash_id": "hash"})
    assert dep["product"] == "secrets"
    assert [row["id"] for row in matches] == [1]
    assert matches[0]["rule"] == "hash"


def _secrets(rows):
    def query(path, token):
        if "/findings?" in path:
            return {"findings": []}  # no Semgrep Code finding: correlate in the Secrets product
        base = {"repository": {"name": REPOSITORY}, "ref": "feature", "type": "AWS", "status": "FINDING_STATUS_OPEN"}
        return {"findings": [{**base, **row} for row in rows]}
    return query


def test_secrets_without_a_rule_hash_matches_the_finding_at_the_avits_exact_location(monkeypatch):
    query = _secrets([{"id": "1", "ruleHashId": "h-at-location", "findingPath": "file.py:43"},
                      {"id": "2", "ruleHashId": "h-other-file", "findingPath": "other.py:42"},
                      {"id": "3", "ruleHashId": "h-far-line", "findingPath": "file.py:90"},
                      {"id": "4", "ruleHashId": "h-other-branch", "findingPath": "file.py:42", "ref": "main"},
                      {"id": "5", "ruleHashId": "h-closed", "findingPath": "file.py:42", "status": "FINDING_STATUS_FIXED"}])
    dep, matches = match(monkeypatch, query, kind="secrets")
    assert dep["product"] == "secrets"
    assert [row["id"] for row in matches] == [1], "only the open finding on this repository, branch, file, and line"
    assert matches[0]["rule"] == "h-at-location", "the matched finding's own ruleHashId is used, never the service type"


def test_secrets_refuses_to_guess_between_different_rules_at_one_location(monkeypatch):
    query = _secrets([{"id": "1", "ruleHashId": "h-one", "findingPath": "file.py:42"},
                      {"id": "2", "ruleHashId": "h-two", "findingPath": "file.py:41"}])
    with pytest.raises(ar.ResolveError, match="different rules .*--semgrep-rule-hash-id"):
        match(monkeypatch, query, kind="secrets")


def test_secrets_with_nothing_at_the_location_matches_nothing(monkeypatch):
    dep, matches = match(monkeypatch, _secrets([{"id": "1", "ruleHashId": "h", "findingPath": "elsewhere.py:42"}]), kind="secrets")
    assert dep["product"] == "secrets" and matches == []


@pytest.mark.parametrize("change", [{"line": ""}, {"line": "0"}, {"branch": ""}, {"rule": ""}])
def test_missing_scope_is_rejected_before_queries(monkeypatch, change):
    monkeypatch.setattr(ar, "_report_line", lambda *args: None)
    with pytest.raises(ar.ResolveError):
        match(monkeypatch, lambda *args: pytest.fail("No incomplete-scope request"),
              context={**CONTEXT, **change}, target={**TARGET, "branch": ""})


def test_missing_project_owner_is_rejected_for_tuning():
    with pytest.raises(ar.ResolveError, match="organization"):
        matching.tuning_project({"name": "repo"}, [])
