import io
import json
import types

import pytest

from threatlint import avit_resolve as ar
from threatlint import sctask
from threatlint import servicenow as sn

INSTANCE = "https://example.service-now.com"
DESCRIPTION = ("Please mark the below issues as false positives\n\nAVIT000000095891574:\nThe SELECT statement ...\n\n"
               "AVIT000000097930184:\nThe SQL statement ... AVIT000000095891574 again")


def test_avits_are_parsed_from_the_description_in_order_without_duplicates():
    assert sctask.avits_in(DESCRIPTION) == ["AVIT000000095891574", "AVIT000000097930184"]
    assert sctask.parse_sctask_numbers("sctask14120565") == ["SCTASK14120565"]


class FakeServiceNow:
    def __init__(self, notes):
        self.notes, self.calls = notes, []

    def __call__(self, url, *, data=None, headers, method=None):
        self.calls.append((method or ("POST" if data is not None else "GET"), url, data))
        if "/table/sc_task?" in url:
            return {"result": [{"sys_id": "a" * 32, "number": "SCTASK14120565", "state": "-5", "description": DESCRIPTION}]}
        if f"/table/{sn.AVIT_TABLE}?" in url:
            avit = next(a for a in self.notes if a in url)
            return {"result": [{"sys_id": avit[-1] * 32, "number": avit, "state": "Open", "work_notes": self.notes[avit]}]}
        if "/attachment?" in url:
            return {"result": [] if "table_name%3Dsc_task" in url or "table_name=sc_task" in url else [
                {"sys_id": "c" * 32, "file_name": f"{avit}{sctask.REPORT_SUFFIX}"} for avit in self.notes]}
        if "/attachment/file" in url:
            return {"result": {"sys_id": "d" * 32}}
        if method == "PATCH":
            return {"result": {"state": json.loads(data).get("state", "-5")}}
        raise AssertionError(url)


def _run(monkeypatch, notes, leave_open=False):
    fake = FakeServiceNow(notes)
    monkeypatch.setattr(sn, "_request_json", fake)
    monkeypatch.setattr(sctask, "_download", lambda *a: b"PK-docx")
    result = sctask.close(INSTANCE, "t", "SCTASK14120565", yes=True, out=io.StringIO(), leave_open=leave_open)
    patch = json.loads(next(d for m, _u, d in fake.calls if m == "PATCH"))
    uploads = [u for m, u, _d in fake.calls if "/attachment/file" in u]
    return result, patch, uploads


def test_task_closes_with_each_report_and_points_developers_at_true_positives(monkeypatch):
    result, patch, uploads = _run(monkeypatch, {"AVIT000000095891574": ar.CLOSING_COMMENT, "AVIT000000097930184": ar.TRUE_POSITIVE_COMMENT})
    assert result["closed"] and patch["state"] == sctask.CLOSED_STATE
    assert patch["comments"].startswith("Closed by Threatlint")
    assert "AVIT000000095891574: false positive, closed by Threatlint" in patch["comments"]
    assert "AVIT000000097930184: true positive, still open" in patch["comments"] and "review the attached report" in patch["comments"]
    assert len(uploads) == 2 and all("table_name=sc_task" in u for u in uploads)


def test_task_stays_open_while_an_avit_is_undecided(monkeypatch):
    result, patch, _uploads = _run(monkeypatch, {"AVIT000000095891574": ar.CLOSING_COMMENT, "AVIT000000097930184": ar.AMBIGUOUS_COMMENT})
    assert not result["closed"] and "state" not in patch and "could not be decided" in patch["comments"]


def test_leave_open_comments_that_the_task_can_be_closed(monkeypatch):
    result, patch, uploads = _run(monkeypatch, {"AVIT000000095891574": ar.CLOSING_COMMENT, "AVIT000000097930184": ar.CLOSING_COMMENT}, leave_open=True)
    assert not result["closed"] and "state" not in patch and len(uploads) == 2
    assert patch["comments"].startswith("Reviewed by Threatlint. Every AVIT below has a decision, so this task can be closed.")


def test_latest_repeated_avit_report_is_copied_even_when_task_has_older_report(monkeypatch):
    avit = "AVIT000000095891574"
    versioned = f"{avit}-threatlint-fp-review-20261104T180000123456Z.docx"
    fake = FakeServiceNow({avit: ar.TRUE_POSITIVE_COMMENT})
    original = fake.__call__

    def request(url, **kwargs):
        if "/attachment?" in url:
            if "table_name%3Dsc_task" in url or "table_name=sc_task" in url:
                return {"result": [{"file_name": f"{avit}{sctask.REPORT_SUFFIX}"}]}
            return {"result": [
                {"sys_id": "b" * 32, "file_name": f"{avit}{sctask.REPORT_SUFFIX}"},
                {"sys_id": "c" * 32, "file_name": versioned},
                {"sys_id": "d" * 32, "file_name": f"{avit}-threatlint-fp-review-unsafe.docx"},
            ]}
        return original(url, **kwargs)

    monkeypatch.setattr(sn, "_request_json", request)
    monkeypatch.setattr(sctask, "_download", lambda _instance, _token, attachment_id: b"new report" if attachment_id == "c" * 32 else b"old report")
    outcome = sctask.avit_outcome(INSTANCE, "t", avit)
    assert outcome["report"] == "c" * 32 and outcome["report_name"] == versioned

    # A task whose description names this AVIT should receive the new version,
    # while the older fixed-name attachment remains as review history.
    monkeypatch.setattr(sctask, "avits_in", lambda _text: [avit])
    sctask.close(INSTANCE, "t", "SCTASK14120565", yes=True, out=io.StringIO())
    uploads = [(url, data) for _method, url, data in fake.calls if "/attachment/file" in url]
    assert len(uploads) == 1
    assert versioned in uploads[0][0] and uploads[0][1] == b"new report"


def test_decided_avit_without_readable_report_cannot_close_task(monkeypatch):
    avit = "AVIT000000095891574"
    fake = FakeServiceNow({avit: ar.TRUE_POSITIVE_COMMENT})
    monkeypatch.setattr(sn, "_request_json", fake)
    monkeypatch.setattr(sctask, "avits_in", lambda _text: [avit])
    monkeypatch.setattr(sctask, "avit_outcome", lambda *_args: {
        "avit": avit, "disposition": "TRUE POSITIVE", "state": "Open", "report": None,
    })
    with pytest.raises(ar.ResolveError, match="no readable Threatlint report"):
        sctask.close(INSTANCE, "t", "SCTASK14120565", yes=True, out=io.StringIO())
    assert not any(method == "PATCH" or "/attachment/file" in url for method, url, _data in fake.calls)


@pytest.mark.parametrize("state", ["Closed", "3"])
def test_closed_true_positive_cannot_claim_to_be_open_on_task(monkeypatch, state):
    avit = "AVIT000000095891574"
    fake = FakeServiceNow({avit: ar.TRUE_POSITIVE_COMMENT})
    monkeypatch.setattr(sn, "_request_json", fake)
    monkeypatch.setattr(sctask, "avits_in", lambda _text: [avit])
    monkeypatch.setattr(sctask, "avit_outcome", lambda *_args: {
        "avit": avit, "disposition": "TRUE POSITIVE", "state": state,
        "report": "c" * 32, "report_name": f"{avit}{sctask.REPORT_SUFFIX}",
    })
    with pytest.raises(ar.ResolveError, match="remain closed in ServiceNow"):
        sctask.close(INSTANCE, "t", "SCTASK14120565", yes=True, out=io.StringIO())
    assert not any(method == "PATCH" or "/attachment/file" in url for method, url, _data in fake.calls)


def test_malformed_task_attachment_list_stops_before_comment_or_close(monkeypatch):
    avit = "AVIT000000095891574"
    fake = FakeServiceNow({avit: ar.TRUE_POSITIVE_COMMENT})
    original = fake.__call__

    def malformed(url, **kwargs):
        if "/attachment?" in url and ("table_name%3Dsc_task" in url or "table_name=sc_task" in url):
            return {"result": {"bad": "shape"}}
        return original(url, **kwargs)

    monkeypatch.setattr(sn, "_request_json", malformed)
    monkeypatch.setattr(sctask, "avits_in", lambda _text: [avit])
    with pytest.raises(ar.ResolveError, match="readable attachment list"):
        sctask.close(INSTANCE, "t", "SCTASK14120565", yes=True, out=io.StringIO())
    assert not any(method == "PATCH" or "/attachment/file" in url for method, url, _data in fake.calls)
