"""One-page PDF summary attached beside each Finding Review Word report."""
from __future__ import annotations

import io
import json
import re
import zlib
from pathlib import Path

import pytest

from threatlint import isst, one_pager, sctask, servicenow as sn
from threatlint import avit_resolve as ar

EXAMPLE = (Path(__file__).resolve().parents[1] / "web" / "examples" / "fp-review.md").read_text(encoding="utf-8")
AVIT = "AVIT000000000000001"


def _text(pdf: bytes) -> str:
    """The page's drawn strings, for assertions about content."""
    stream = re.search(rb"stream\n(.*?)\nendstream", pdf, re.S).group(1)
    content = zlib.decompress(stream).decode("cp1252")
    return " ".join(re.findall(r"\(((?:\\.|[^\\)])*)\) Tj", content)).replace("\\(", "(").replace("\\)", ")")


def _pages(pdf: bytes) -> int:
    return pdf.count(b"/Type /Page ")


def test_attachment_name_prefixes_the_word_report_name():
    assert one_pager.attachment_name(f"{AVIT}-threatlint-fp-review-20261126T015900123456Z.docx") == \
        f"[ONE PAGER SUMMARY] {AVIT}-threatlint-fp-review-20261126T015900123456Z.pdf"


def test_true_positive_page_leads_with_risk_code_and_fix():
    page = one_pager.summary(EXAMPLE, finding_id="FP-001")
    assert (page["disposition"], page["severity"], page["confidence"]) == ("TRUE POSITIVE", "HIGH", "CONFIRMED")
    assert page["location"] == "example/api/customers.py:41-44" and page["rule"] == "example.sql-query-construction"
    assert page["bottom_line"].startswith("In this fictional SQLite handler")
    assert any(line.startswith("-query = f\"SELECT") for line in page["fix"])
    assert any(line.startswith("+query = \"SELECT") for line in page["fix"])
    pdf = one_pager.render(page)
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF") and _pages(pdf) == 1
    text = _text(pdf)
    for expected in ("TRUE POSITIVE", "BOTTOM LINE", "WHAT IS AT RISK", "PROPOSED FIX \\(NOT APPLIED\\)".replace("\\", ""), "DONE WHEN"):
        assert expected in text


def test_false_positive_page_explains_safety_and_never_proposes_a_code_fix():
    page = one_pager.summary(EXAMPLE, finding_id="FP-002")
    assert page["disposition"] == "FALSE POSITIVE" and page["fix"] == []
    assert page["bottom_line"].startswith("In the illustrated SQLite API, the statement is constant")
    text = _text(one_pager.render(page))
    assert "WHY IT IS NOT EXPLOITABLE" in text and "BLAST RADIUS OF ANY SUPPRESSION" in text
    assert "PROPOSED FIX" not in text and "No vulnerability was confirmed" in text


def test_the_avit_selects_its_finding_and_appears_on_the_page():
    report = EXAMPLE.replace("**Original finding**: scanner-18; example.sql-query-construction",
                             f"**Original finding**: {AVIT}; example.sql-query-construction; Semgrep 1.99; example/api/orders.py:26")
    page = one_pager.summary(report, AVIT)
    assert (page["id"], page["avit"], page["location"]) == ("FP-002", AVIT, "example/api/orders.py:26")
    assert AVIT in _text(one_pager.render(page))


def test_long_reviews_are_shrunk_and_shortened_to_one_page():
    long = "The handler trusts a caller-controlled value across several layers. " * 120
    code = "\n".join(f"line_{n} = request.args['value_{n}']  # {'x' * 120}" for n in range(80))
    diff = "\n".join(f"-old_{n}()\n+new_{n}()" for n in range(60))
    report = (f"# Finding Review: {'Very long repository name ' * 6}\n\n#### [FP-001] — {'A very long finding title ' * 12}\n\n"
              f"**Disposition**: TRUE POSITIVE\n**Severity**: CRITICAL\n**Confidence**: PLAUSIBLE\n**Decision basis**: CONSERVATIVE DEFAULT\n"
              f"**Owner**: {'Platform ' * 20}\n**Effort**: {'Large ' * 30}\n\n**Finding and impact**: {long}\n\n"
              f"**Evidence**: `src/app/handler.py:10-90`:\n\n```python\n{code}\n```\n\n**Assessment and alternative interpretation**: {long}\n\n"
              f"**Blocking Evidence**: {long}\n\n**Proposed fix patch**:\n\n```diff\n{diff}\n```\n\n"
              f"**Regression Tests**: {long}\n\n**Acceptance Criteria**: {long}\n")
    pdf = one_pager.build(report)
    assert _pages(pdf) == 1
    text = _text(pdf)
    assert "EVIDENCE STILL NEEDED" in text and "more line(s) in the Word report" in text


def test_non_latin_text_is_encoded_without_failing():
    report = EXAMPLE.replace("Customer lookup builds SQL", "Customer → lookup ✓ 顧客 builds SQL")
    assert _pages(one_pager.build(report, finding_id="FP-001")) == 1


def test_a_report_without_findings_is_rejected():
    with pytest.raises(one_pager.OnePagerError):
        one_pager.build("# Finding Review: Empty\n\nNo findings.\n")


def test_cli_writes_the_pdf(tmp_path):
    report, out = tmp_path / "review.md", tmp_path / "summary.pdf"
    report.write_text(EXAMPLE, encoding="utf-8")
    assert one_pager.main([str(report), str(out), "--finding", "FP-002"]) == 0
    assert _pages(out.read_bytes()) == 1
    assert one_pager.main([str(report), str(tmp_path / "x.pdf"), "--finding", "FP-404"]) == 1


def test_isst_attaches_the_summary_beside_each_true_positive_report(monkeypatch):
    calls = []

    def request(url, *, data=None, headers, method=None):
        calls.append((method or ("POST" if data is not None else "GET"), url, data))
        if "/api/now/attachment?" in url:
            return {"result": []}
        if "/attachment/file" in url:
            return {"result": {"sys_id": "b" * 32}}
        return {"result": {"number": "ISST0000001"}} if method == "PATCH" else {"result": {}}

    monkeypatch.setattr(sn, "_request_json", request)
    name = f"{AVIT}-threatlint-fp-review-20261104T190000123456Z.docx"
    summary = one_pager.build(EXAMPLE, finding_id="FP-001")
    record = {"number": "ISST0000001", "table": "u_isst_task", "sys_id": "a" * 32, "avits": [AVIT]}
    isst.summarize("https://example.service-now.com", "t", record, [{"avit": AVIT, "disposition": "TRUE POSITIVE", "completed": True,
                                                                    "attachment_name": name, "report_bytes": b"PKword", "summary_bytes": summary}])
    uploads = [(url, data) for method, url, data in calls if "/attachment/file?" in url]
    assert [data for _url, data in uploads] == [b"PKword", summary]
    assert "ONE+PAGER+SUMMARY" in uploads[1][0] and "content" not in uploads[1][0]


def test_sctask_copies_the_avit_summary_with_its_report(monkeypatch):
    report = f"{AVIT}{sctask.REPORT_SUFFIX}"
    summary = one_pager.attachment_name(report)

    def request(url, *, data=None, headers, method=None):
        calls.append((method or ("POST" if data is not None else "GET"), url, data))
        if "/table/sc_task?" in url:
            return {"result": [{"sys_id": "a" * 32, "number": "SCTASK0000001", "state": "-5", "description": AVIT}]}
        if f"/table/{sn.AVIT_TABLE}?" in url:
            return {"result": [{"sys_id": "1" * 32, "number": AVIT, "state": "Open", "work_notes": ar.TRUE_POSITIVE_COMMENT}]}
        if "/attachment?" in url:
            return {"result": [] if "sc_task" in url else [{"sys_id": "c" * 32, "file_name": report},
                                                         {"sys_id": "e" * 32, "file_name": summary}]}
        if "/attachment/file" in url:
            return {"result": {"sys_id": "d" * 32}}
        return {"result": {"state": json.loads(data).get("state", "-5")}}

    calls: list = []
    monkeypatch.setattr(sn, "_request_json", request)
    monkeypatch.setattr(sctask, "_download", lambda _i, _t, attachment: {"c" * 32: b"PK-docx", "e" * 32: b"%PDF-summary"}[attachment])
    sctask.close("https://example.service-now.com", "t", "SCTASK0000001", yes=True, out=io.StringIO(), leave_open=True)
    uploads = [data for method, url, data in calls if "/attachment/file" in url]
    assert uploads == [b"PK-docx", b"%PDF-summary"]
