"""ISST repository/branch discovery and headless outcome write-back."""

from __future__ import annotations

import json
import urllib.parse

import pytest

from threatlint import isst, servicenow as sn
from threatlint.avit_report import ResolveError


INSTANCE = "https://example.service-now.com"
ISST = "ISST1234567"
AVIT = "AVIT000000000000001"
OTHER_BRANCH = "AVIT000000000000002"
OTHER_PROJECT = "AVIT000000000000003"
SYS_ID = "a" * 32
ISST_ROW = {
    "sys_id": {"value": SYS_ID}, "number": {"value": ISST},
    "sys_class_name": {"value": "u_isst_task", "display_value": "Information Security Scan Task"},
    "u_scm_tool": {"display_value": "Azure DevOps"},
    "u_organization_name": {"display_value": "contoso"},
    "u_project_name": {"display_value": "Platform"},
    "u_repository": {"display_value": "compliance-backend"},
    "u_repository_url": {"display_value": "https://dev.azure.com/contoso/Platform/_git/compliance-backend"},
    "u_project_branch": {"display_value": "develop"},
}


def avit(number: str, *, branch: str = "develop", project: str = "Platform") -> dict:
    return {
        "sys_id": {"value": number[-1] * 32}, "number": {"value": number},
        "u_scm_tool": {"display_value": "ADO"},
        "u_organization_name": {"display_value": "contoso"},
        "u_project_name": {"display_value": project},
        "u_repository": {"display_value": "compliance-backend"},
        "u_project_branch": {"display_value": branch},
    }


class FakeServiceNow:
    def __init__(self, isst_row=None, avits=None, attachments=None):
        self.isst_row = isst_row or ISST_ROW
        self.avits = avits if avits is not None else [avit(AVIT), avit(OTHER_BRANCH, branch="main"),
                                                       avit(OTHER_PROJECT, project="Different")]
        self.attachments = attachments if attachments is not None else []
        self.calls = []

    def __call__(self, url, *, data=None, headers, method=None):
        self.calls.append((method or ("POST" if data is not None else "GET"), url, data))
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path.endswith("/api/now/table/task"):
            return {"result": [self.isst_row]}
        if parsed.path.endswith("/api/now/table/u_isst_task"):
            return {"result": [self.isst_row]}
        if parsed.path.endswith(f"/api/now/table/{sn.AVIT_TABLE}"):
            assert query["sysparm_query"] in (["u_repository=compliance-backend"],
                                                ["repository=compliance-backend"])
            return {"result": self.avits if query["sysparm_query"][0].startswith("u_repository=") else []}
        if parsed.path.endswith("/api/now/attachment"):
            return {"result": self.attachments}
        if parsed.path.endswith("/api/now/attachment/file"):
            assert data.startswith(b"PK")
            return {"result": {"sys_id": "b" * 32}}
        if parsed.path.endswith(f"/api/now/table/u_isst_task/{SYS_ID}") and method == "PATCH":
            assert "state" not in json.loads(data)
            return {"result": {"number": ISST}}
        raise AssertionError(url)


def test_isst_discovers_only_exact_repo_and_branch_from_its_task_subclass(monkeypatch):
    fake = FakeServiceNow()
    monkeypatch.setattr(sn, "_request_json", fake)
    monkeypatch.setattr(sn, "field_labels", lambda *_: {})
    record, numbers = isst.discover(INSTANCE, "token", ISST.lower())
    assert numbers == [AVIT]
    assert record["table"] == "u_isst_task" and record["sys_id"] == SYS_ID
    assert record["target"]["branch"] == "develop"
    assert record["target"]["web_url"].endswith("/_git/compliance-backend")
    assert all(method == "GET" for method, _url, _data in fake.calls)


def test_isst_unions_both_repository_columns_without_duplicate_avits(monkeypatch):
    fake = FakeServiceNow(avits=[avit(AVIT)])
    original = fake.__call__
    second_number = "AVIT000000100065237"
    second = avit(second_number)
    second["repository"] = second.pop("u_repository")

    def mixed_columns(url, *, data=None, headers, method=None):
        if f"/table/{sn.AVIT_TABLE}?" in url:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["sysparm_query"][0]
            fake.calls.append((method or "GET", url, data))
            return {"result": [avit(AVIT), second] if query.startswith("repository=") else [avit(AVIT)]}
        return original(url, data=data, headers=headers, method=method)

    monkeypatch.setattr(sn, "_request_json", mixed_columns)
    monkeypatch.setattr(sn, "field_labels", lambda *_: {})
    _record, numbers = isst.discover(INSTANCE, "token", ISST)
    assert numbers == [AVIT, second_number]
    queries = [urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["sysparm_query"][0]
               for _method, url, _data in fake.calls if f"/table/{sn.AVIT_TABLE}?" in url]
    assert queries == ["u_repository=compliance-backend",
                       "repository=compliance-backend"]


def test_isst_can_derive_repository_from_url_and_branch_from_description(monkeypatch):
    row = {"sys_id": {"value": SYS_ID}, "number": {"value": ISST},
           "sys_class_name": {"value": "u_isst_task"},
           "description": {"value": "Repository URL: https://dev.azure.com/contoso/Platform/_git/compliance-backend\nBranch Name: refs/heads/develop"}}
    fake = FakeServiceNow(isst_row=row)
    monkeypatch.setattr(sn, "_request_json", fake)
    monkeypatch.setattr(sn, "field_labels", lambda *_: {})
    record, numbers = isst.discover(INSTANCE, "token", ISST)
    assert numbers == [AVIT] and record["target"]["organization"] == "contoso"


def test_isst_uses_unique_task_class_metadata_when_task_rows_are_hidden(monkeypatch):
    def request(url, **_kwargs):
        path = urllib.parse.urlsplit(url).path
        if path.endswith("/table/task"):
            return {"result": []}
        if path.endswith("/table/sys_db_object"):
            return {"result": [{"name": "u_isst_task", "label": "Information Security Task"}]}
        if path.endswith("/table/u_isst_task"):
            return {"result": [ISST_ROW]}
        raise AssertionError(url)

    monkeypatch.setattr(sn, "_request_json", request)
    record = isst._record(INSTANCE, "token", ISST)
    assert record["table"] == "u_isst_task" and record["sys_id"] == SYS_ID


def test_isst_can_follow_scan_assessment_for_repo_and_branch(monkeypatch):
    assessment_id = "b" * 32
    row = {"sys_id": {"value": SYS_ID}, "number": {"value": ISST},
           "sys_class_name": {"value": "u_isst_task"},
           "scan_asmt_details": {"value": assessment_id,
                                 "link": f"{INSTANCE}/api/now/table/x_inpe_information_scan_assessments/{assessment_id}"}}
    assessment = {"sys_id": {"value": assessment_id},
                  "repo_url": {"display_value": "https://dev.azure.com/contoso/Platform/_git/compliance-backend"},
                  "repo_name": {"display_value": "compliance-backend"},
                  "project_ado": {"display_value": "Platform"},
                  "branch_name": {"display_value": "develop"}}
    fake = FakeServiceNow(isst_row=row)
    original = fake.__call__

    def request(url, **kwargs):
        if f"/x_inpe_information_scan_assessments/{assessment_id}" in url:
            return {"result": assessment}
        return original(url, **kwargs)

    monkeypatch.setattr(sn, "_request_json", request)
    monkeypatch.setattr(sn, "field_labels", lambda *_: {})
    record, numbers = isst.discover(INSTANCE, "token", ISST)
    assert numbers == [AVIT]
    assert record["target"]["organization"] == "contoso"
    assert record["target"]["project"] == "Platform"
    assert record["target"]["branch"] == "develop"


def test_isst_rejects_conflicting_repository_and_missing_branch(monkeypatch):
    row = {**ISST_ROW, "u_repository": {"display_value": "wrong-repository"}}
    fake = FakeServiceNow(isst_row=row)
    monkeypatch.setattr(sn, "_request_json", fake)
    with pytest.raises(ResolveError, match="conflicts with its repository URL"):
        isst.discover(INSTANCE, "token", ISST)
    assert not any(f"/table/{sn.AVIT_TABLE}" in url for _method, url, _data in fake.calls)

    fake = FakeServiceNow(isst_row={key: value for key, value in ISST_ROW.items() if key != "u_project_branch"})
    monkeypatch.setattr(sn, "_request_json", fake)
    with pytest.raises(ResolveError, match="exact branch name"):
        isst.discover(INSTANCE, "token", ISST)


def test_isst_rejects_ambiguous_avit_on_same_repo_branch(monkeypatch):
    incomplete = avit(AVIT)
    incomplete.pop("u_organization_name")
    fake = FakeServiceNow(avits=[incomplete])
    monkeypatch.setattr(sn, "_request_json", fake)
    monkeypatch.setattr(sn, "field_labels", lambda *_: {})
    with pytest.raises(ResolveError, match="incomplete repository identity"):
        isst.discover(INSTANCE, "token", ISST)


def test_true_positive_report_is_attached_and_linked_without_closing_isst(monkeypatch):
    fake = FakeServiceNow()
    monkeypatch.setattr(sn, "_request_json", fake)
    record = {"number": ISST, "table": "u_isst_task", "sys_id": SYS_ID, "avits": [AVIT]}
    name = f"{AVIT}-threatlint-fp-review-20261104T190000123456Z.docx"
    result = isst.summarize(INSTANCE, "token", record, [{"avit": AVIT, "disposition": "TRUE POSITIVE", "completed": True,
                                                         "attachment_name": name, "report_bytes": b"PKword"}])
    assert not result["closure_ready"]
    assert result["attachment_links"][AVIT] == f"{INSTANCE}/sys_attachment.do?sys_id={'b' * 32}"
    assert any("/attachment/file?" in url for _method, url, _data in fake.calls)
    patches = [json.loads(data) for method, _url, data in fake.calls if method == "PATCH"]
    assert len(patches) == 1 and "True positives detected by Threatlint" in patches[0]["comments"]
    assert result["attachment_links"][AVIT] in patches[0]["comments"]
    assert "state" not in patches[0]


def test_all_completed_false_positives_suggest_isst_and_scan_closure(monkeypatch):
    fake = FakeServiceNow()
    monkeypatch.setattr(sn, "_request_json", fake)
    record = {"number": ISST, "table": "u_isst_task", "sys_id": SYS_ID, "avits": [AVIT]}
    result = isst.summarize(INSTANCE, "token", record, [{"avit": AVIT, "disposition": "FALSE POSITIVE", "completed": True}])
    assert result["closure_ready"]
    assert "This ISST and SCAN request can be closed" in result["comment"]
    assert not any("/attachment/file?" in url for _method, url, _data in fake.calls)


def test_incomplete_false_positive_never_suggests_closure(monkeypatch):
    fake = FakeServiceNow()
    monkeypatch.setattr(sn, "_request_json", fake)
    record = {"number": ISST, "table": "u_isst_task", "sys_id": SYS_ID, "avits": [AVIT]}
    result = isst.summarize(INSTANCE, "token", record, [{"avit": AVIT, "disposition": "FALSE POSITIVE", "completed": False}])
    assert not result["closure_ready"] and "Keep this ISST and SCAN request open" in result["comment"]
    assert "can be closed" not in result["comment"]


def test_invalid_true_positive_report_stops_before_writes(monkeypatch):
    fake = FakeServiceNow()
    monkeypatch.setattr(sn, "_request_json", fake)
    record = {"number": ISST, "table": "u_isst_task", "sys_id": SYS_ID, "avits": [AVIT]}
    with pytest.raises(ResolveError, match="valid Word report"):
        isst.summarize(INSTANCE, "token", record, [{"avit": AVIT, "disposition": "TRUE POSITIVE", "completed": True,
                                                    "attachment_name": f"{AVIT}-threatlint-fp-review.docx", "report_bytes": b"not Word"}])
    assert not any(method in ("POST", "PATCH") for method, _url, _data in fake.calls)


def test_existing_true_positive_attachment_is_reused(monkeypatch):
    name = f"{AVIT}-threatlint-fp-review.docx"
    fake = FakeServiceNow(attachments=[{"sys_id": "c" * 32, "file_name": name}])
    monkeypatch.setattr(sn, "_request_json", fake)
    record = {"number": ISST, "table": "u_isst_task", "sys_id": SYS_ID, "avits": [AVIT]}
    result = isst.summarize(INSTANCE, "token", record, [{"avit": AVIT, "disposition": "TRUE POSITIVE", "completed": True,
                                                         "attachment_name": name, "report_bytes": b"PKword"}])
    assert result["attachment_links"][AVIT].endswith("c" * 32)
    assert not any("/attachment/file?" in url for _method, url, _data in fake.calls)


def test_isst_comment_requires_matching_stored_record(monkeypatch):
    fake = FakeServiceNow()
    original = fake.__call__

    def wrong_record(url, *, data=None, headers, method=None):
        if method == "PATCH":
            fake.calls.append((method, url, data))
            return {"result": {"number": "ISST9999999", "sys_id": "b" * 32}}
        return original(url, data=data, headers=headers, method=method)

    monkeypatch.setattr(sn, "_request_json", wrong_record)
    record = {"number": ISST, "table": "u_isst_task", "sys_id": SYS_ID, "avits": [AVIT]}
    with pytest.raises(ResolveError, match="did not confirm the comment"):
        isst.summarize(INSTANCE, "token", record, [{"avit": AVIT, "disposition": "FALSE POSITIVE", "completed": True}])
    assert any(method == "PATCH" for method, _url, _data in fake.calls)


def test_summarize_number_reads_avit_outcomes_downloads_tp_reports_and_attaches(monkeypatch):
    """`isst summarize` (CLI path): discover AVITs, read each one's disposition, download only the true-positive
    report, and attach it to the ISST without closing it."""
    from threatlint import sctask
    record = {"number": ISST, "table": "u_isst_task", "sys_id": SYS_ID, "avits": [AVIT, OTHER_BRANCH]}
    monkeypatch.setattr(isst, "discover", lambda instance, token, number: (record, [AVIT, OTHER_BRANCH]))
    name = f"{AVIT}-threatlint-fp-review.docx"
    outcomes = {AVIT: {"avit": AVIT, "disposition": "TRUE POSITIVE", "report": "att1", "report_name": name},
                OTHER_BRANCH: {"avit": OTHER_BRANCH, "disposition": "FALSE POSITIVE", "report": None, "report_name": None}}
    monkeypatch.setattr(sctask, "avit_outcome", lambda instance, token, avit: outcomes[avit])
    monkeypatch.setattr(sctask, "_download", lambda instance, token, attachment_id: b"PKword")
    captured = {}
    def fake_summarize(instance, token, rec, items):
        captured["items"] = items
        return {"isst": ISST, "attachment_links": {AVIT: "u"}, "closure_ready": False, "comment": "ok"}
    monkeypatch.setattr(isst, "summarize", fake_summarize)
    result = isst.summarize_number(INSTANCE, "token", ISST, yes=True)
    assert result["isst"] == ISST
    tp = next(item for item in captured["items"] if item["avit"] == AVIT)
    assert tp["report_bytes"] == b"PKword" and tp["attachment_name"] == name and tp["completed"]
    fp = next(item for item in captured["items"] if item["avit"] == OTHER_BRANCH)
    assert "report_bytes" not in fp and fp["completed"]


def test_summarize_number_errors_when_a_true_positive_has_no_report(monkeypatch):
    from threatlint import sctask
    record = {"number": ISST, "table": "u_isst_task", "sys_id": SYS_ID, "avits": [AVIT]}
    monkeypatch.setattr(isst, "discover", lambda *a, **k: (record, [AVIT]))
    monkeypatch.setattr(sctask, "avit_outcome", lambda *a, **k: {"avit": AVIT, "disposition": "TRUE POSITIVE", "report": None, "report_name": None})
    with pytest.raises(ResolveError, match="no readable Threatlint report"):
        isst.summarize_number(INSTANCE, "token", ISST, yes=True)


def test_isst_discovery_has_no_avit_limit(monkeypatch):
    """An ISST may name any number of AVITs; the Workbench reviews them one at a time, so discovery never caps them."""
    many = [f"AVIT{9000000 + index:07d}" for index in range(57)]
    fake = FakeServiceNow(avits=[avit(number) for number in many])
    monkeypatch.setattr(sn, "_request_json", fake)
    monkeypatch.setattr(sn, "field_labels", lambda *_: {})
    _record, numbers = isst.discover(INSTANCE, "token", ISST)
    assert numbers == many
