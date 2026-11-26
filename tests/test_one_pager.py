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
    assert page["bottom_line"].startswith("Confirmed high-severity finding at customers.py:41-44: customer lookup builds SQL")
    assert "In this fictional SQLite handler" in page["bottom_line"] and "Fix:" in page["bottom_line"]
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
    assert page["bottom_line"].startswith("False positive at orders.py:25-28: in the illustrated SQLite API, the statement is constant")
    assert page["bottom_line"].endswith("No code change is needed.")
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


LIVE_SHAPE = (Path(__file__).resolve().parent / "fixtures" / "one-pager-live-shape.md").read_text(encoding="utf-8")
_FONT = {"F1": "R", "F2": "B", "F3": "C"}


def _runs(pdf: bytes) -> list[tuple[float, float, float, float, str]]:
    """(left, bottom, right, top, text) for every string drawn on the page."""
    stream = zlib.decompress(re.search(rb"stream\n(.*?)\nendstream", pdf, re.S).group(1))
    runs = []
    pattern = rb"BT /(F\d) ([\d.]+) Tf [\d. ]+ rg (-?[\d.]+) Tc ([\d.]+) ([\d.]+) Td \(((?:\\.|[^\\)])*)\) Tj ET"
    for font, size, spacing, x, y, raw in re.findall(pattern, stream):
        data = re.sub(rb"\\(.)", rb"\1", raw)
        size, x, y = float(size), float(x), float(y)
        width = one_pager._width(data, _FONT[font.decode()], size) + float(spacing) * max(0, len(data) - 1)
        runs.append((x, y - 0.2 * size, x + width, y + 0.75 * size, data.decode("cp1252")))
    return runs


def _assert_no_overlap(pdf: bytes) -> None:
    runs = _runs(pdf)
    assert runs
    for left, bottom, right, top, text in runs:
        assert left >= 39.5 and right <= 612 - 39.5, f"outside the margins: {text!r}"
        assert bottom >= 30 and top <= 792 - 30, f"outside the page: {text!r}"
    for index, first in enumerate(runs):
        for second in runs[index + 1:]:
            if first[0] < second[2] - 0.5 and second[0] < first[2] - 0.5 and first[1] < second[3] - 0.5 and second[1] < first[3] - 0.5:
                raise AssertionError(f"overlapping text: {first[4]!r} and {second[4]!r}")


def test_live_report_shape_gets_a_specific_bottom_line_and_concrete_fix_code():
    page = one_pager.summary(LIVE_SHAPE, avit=AVIT)
    bottom = page["bottom_line"]
    assert bottom.startswith("Confirmed critical-severity finding at LedgerController.cs:96: SQL injection in LedgerController.Index.")
    assert "An attacker can add predicates, UNION queries or stacked statements" in bottom
    assert "Fix: use constant SQL with @region bound as SqlDbType.NVarChar" in bottom
    assert "The rule's claim" not in bottom and "(lines 39" not in bottom
    assert page["confidence"] == "CONFIRMED"
    assert page["fix_kind"] == "code"
    assert any("command.Parameters.Add(\"@region\"" in line for line in page["fix"])
    assert not any("String.Format" in line for line in page["fix"]), "the vulnerable 'before' block is not the fix"
    assert page["repository"] == "contoso-ledger (Example_Project)"


def test_live_report_shape_keeps_wording_and_lists_intact():
    page = one_pager.summary(LIVE_SHAPE, avit=AVIT)
    sections = dict(page["left"] + page["right"])
    assert sections["How to apply the fix"] == "Use constant SQL with @region bound as SqlDbType.NVarChar at lines 87, 93, 100, 205 and 211."
    assert "Implementation Notes" not in sections["How to apply the fix"] and "Fix all six" not in sections["How to apply the fix"]
    assert sections["Done when"].count("\n") == 2 and all(line.startswith("\u2022 ") for line in sections["Done when"].splitlines())
    assert sections["Tests to add (not run)"].startswith("1. Attack rejection:")
    assert not re.search(r"\s\d[.)]$", sections["Tests to add (not run)"]), "no dangling list number"
    assert "Rejected." in sections["Why this is a true positive"] and "Proposed Fix" not in sections["Why this is a true positive"]
    assert "Regression Tests" not in sections["Done when"]
    text = _text(one_pager.render(page))
    assert "Evidence-supported" in text and "Supported By Inspected Evidence" not in text
    assert "CODE REVIEWED \xb7 LEDGERCONTROLLER.CS:96" in text


@pytest.mark.parametrize(("source", "expected"), [
    ("the complete patch is **PROPOSED \u2014 NOT APPLIED** and belongs to the fix step.", "The complete patch is proposed, not applied and belongs to the fix step."),
    ("(all **NOT RUN**; they need a new project)", "(all not run; they need a new project)"),
    ("**PROPOSED \u2014 NOT APPLIED**: Bind the value.", "Bind the value."),
    ("contoso_ledger (Example_Project) and *emphasis*", "contoso_ledger (Example_Project) and emphasis"),
    ("Before (vulnerable):\nUse a parameter.", "Use a parameter."),
])
def test_prose_keeps_sentences_whole(source, expected):
    assert one_pager._prose(source) == expected


@pytest.mark.parametrize("which", ["FP-001", "FP-002", "live", "stress"])
def test_nothing_on_the_page_overlaps_or_leaves_the_margins(which):
    if which == "live":
        report = LIVE_SHAPE
    elif which == "stress":
        report = LIVE_SHAPE.replace(
            "SQL injection in LedgerController.Index: request region is formatted into SQL text through a static field",
            "SQL injection in LedgerController.Index and ValidationLedger.Export: request region and validated flags are formatted "
            "into SQL text through static fields shared across every user's requests") \
            .replace("webApp/Contoso_Ledger_LATEST_PROD/Controllers/LedgerController.cs:96",
                     "webApp/CONTOSO_LEDGER_WEBAPPLICATION_LATEST_PRODUCTION_RELEASE/Controllers/Finance/LedgerController.cs:96") \
            .replace("csharp.dotnet-core.sqli.systemdata-taint.systemdata-taint",
                     "csharp.dotnet-core.security.audit.sqli.systemdata-taint-with-static-field-propagation.systemdata-taint") \
            .replace("**Decision basis**: Supported by inspected evidence (not a conservative default)",
                     "**Decision basis**: An unusually long custom basis statement that no chip could ever hold on one line")
    else:
        report = EXAMPLE
    page = one_pager.summary(report, avit=AVIT if which in ("live", "stress") else "", finding_id="" if which in ("live", "stress") else which)
    pdf = one_pager.render(page)
    assert _pages(pdf) == 1
    _assert_no_overlap(pdf)


def test_impact_lead_in_on_its_own_line_still_drives_the_bottom_line():
    report = LIVE_SHAPE.replace("**Impact.** A single quote ends the literal.", "**Impact.**\nA single quote ends the literal.")
    page = one_pager.summary(report, avit=AVIT)
    assert "An attacker can add predicates, UNION queries or stacked statements" in page["bottom_line"]
    assert "non-numeric parameter" not in page["bottom_line"], "the rule's claim is not the bottom line"
    assert dict(page["left"])["What is at risk"].startswith("A single quote ends the literal.")


def test_long_location_keeps_its_file_name_and_line():
    path = "webApp/CONTOSO_LEDGER_WEBAPPLICATION_LATEST_PRODUCTION_RELEASE/Controllers/Finance/LedgerController.cs:96"
    report = LIVE_SHAPE.replace("webApp/Contoso_Ledger_LATEST_PROD/Controllers/LedgerController.cs:96", path)
    text = _text(one_pager.render(one_pager.summary(report, avit=AVIT)))
    assert "LedgerController.cs:96" in text, "the file name and line stay whole on one line"
    assert "\u2026/" in text, "leading folders are elided, not the file name or line"


STEPWISE = LIVE_SHAPE.replace(
    "**Finding and impact**:\n\n**The rule's claim.**",
    "**Finding and impact**\nLedgerController derives from Controller and imports the SQL client, which matches the rule's pattern.\n"
    "- **Reachability**: The action is public and the route exposes it for any HTTP method.\n"
    "- **Attack**: The attacker can append UNION predicates or stacked batches to the query.\n"
    "- **Effect**: That gives reads across all regions and writes up to the login's rights.\n\n**Ignored.**",
).replace("**Impact.** A single quote ends the literal.", "**Notes.** A single quote ends the literal.").replace(
    "Before (vulnerable):", "`LedgerController.cs:87` (main query). Before:").replace(
    "After:\n```csharp\nconst string",
    "After:\n```csharp\nusing (SqlCommand command = LedgerSql.Create(LedgerSql.Main, conn, region))\n```\n\n"
    "`:96` (the flagged sink). Before:\n```csharp\nnew SqlCommand(String.Format(query, region), conn)\n```\n\nAfter:\n"
    "```csharp\nusing (SqlCommand command = LedgerSql.Create(LedgerSql.Mapping, conn, region))\n```\n\n"
    "New file Controllers/LedgerSql.cs:\n```csharp\nconst string")


def test_bottom_line_uses_what_an_attacker_can_do_not_the_rule_match():
    page = one_pager.summary(STEPWISE, avit=AVIT)
    assert "The attacker can append UNION predicates or stacked batches to the query." in page["bottom_line"]
    assert "derives from Controller" not in page["bottom_line"] and "route exposes" not in page["bottom_line"]
    risk = dict(page["left"])["What is at risk"]
    assert risk.startswith("\u2022 The attacker can append UNION") and "reads across all regions" in risk
    assert "matches the rule" not in risk


def test_fix_code_leads_with_the_flagged_line_then_the_new_helper():
    page = one_pager.summary(STEPWISE, avit=AVIT)
    labels = [line for line in page["fix"] if line.startswith("\u2014 ")]
    assert labels[:2] == ["\u2014 :96 (the flagged sink)", "\u2014 New file Controllers/LedgerSql.cs"]
    assert not any("String.Format" in line for line in page["fix"]), "'Before' blocks are not fix code"
    how = dict(page["right"])["How to apply the fix"]
    assert "Before" not in how and "After" not in how and "LedgerController.cs:87" not in how
    _assert_no_overlap(one_pager.render(page))


def test_long_paths_wrap_after_a_folder():
    lines = one_pager._wrap("webApp/Contoso_Ledger/Controllers/Finance/LedgerController.cs:96", "B", 8.3, 160)
    assert all(line.endswith(b"/") for line in lines[:-1]) and lines[-1].endswith(b"/LedgerController.cs:96")
    # A folder wider than the column must break inside, but the file name and line still stay whole.
    lines = one_pager._wrap("webApp/CONTOSO_LEDGER_LATEST_PROD/Controllers/LedgerController.cs:96", "B", 8.3, 160)
    assert lines[-1].endswith(b"LedgerController.cs:96") and b"LedgerController" not in b"".join(lines[:-1])


def test_owner_and_effort_sentences_are_not_cut_short():
    effort = ("About 0.5 day. That covers one helper class, six call-site edits and a new xUnit test project, "
              "because none exists today.")
    report = LIVE_SHAPE.replace("**Effort**: About 0.5 engineer-day. The fix touches six call sites in one controller.",
                                f"**Effort**: {effort}")
    page = one_pager.summary(report, avit=AVIT)
    assert page["effort"] == effort and page["owner"].endswith("(suggested, not an agreed owner)")
    pdf = one_pager.render(page)
    text = _text(pdf)
    assert "because none exists today." in text and "not an agreed owner)" in text
    _assert_no_overlap(pdf)


def test_shortened_text_ends_on_a_complete_sentence_when_one_exists():
    text = ("All six statements move to fixed SQL text with typed parameters. Lines 95 to 98 stay as they are, because they "
            "now receive a parameterised command and nothing else in the data access path changes at all.")
    assert one_pager._prose(text, 150) == "All six statements move to fixed SQL text with typed parameters."


def test_fix_text_drops_dividers_and_dash_led_markers_and_resolves_pronouns():
    fix = ("---\n\u2014 **PROPOSED \u2014 NOT APPLIED** New helper Data/LedgerQueries.cs. It holds constant SQL with "
           "@region placeholders and binds the values as typed parameters.")
    assert one_pager._prose(fix).startswith("New helper Data/LedgerQueries.cs. It holds")
    assert one_pager._fix_sentence(fix) == ("New helper Data/LedgerQueries.cs: it holds constant SQL with @region placeholders "
                                            "and binds the values as typed parameters.")
    report = LIVE_SHAPE.replace("**Proposed Fix** (direction only; the complete patch is **PROPOSED \u2014 NOT APPLIED** and belongs "
                                "to the separate fix step): Use constant SQL with `@region` bound as `SqlDbType.NVarChar` at lines "
                                "87, 93, 100, 205 and 211.", "**Proposed Fix**:\n" + fix)
    bottom = one_pager.summary(report, avit=AVIT)["bottom_line"]
    assert "Fix: new helper Data/LedgerQueries.cs: it holds constant SQL" in bottom and "---" not in bottom


def test_bottom_line_keeps_all_three_parts_inside_its_box():
    long_fix = ("New helper Data/LedgerQueries.cs. It holds constant SQL with @region and @validated placeholders and binds "
                "the values as SqlDbType.NVarChar parameters through one command factory shared by every call site.")
    report = LIVE_SHAPE.replace("**Proposed Fix** (direction only; the complete patch is **PROPOSED \u2014 NOT APPLIED** and belongs "
                                "to the separate fix step): Use constant SQL with `@region` bound as `SqlDbType.NVarChar` at lines "
                                "87, 93, 100, 205 and 211.", "**Proposed Fix**:\n" + long_fix)
    page = one_pager.summary(report, avit=AVIT)
    drawn = one_pager._bottom_lines(page["bottom_line"])
    assert len(drawn) <= one_pager._BOTTOM_LINES and not drawn[-1].endswith(_encode_ellipsis())
    assert page["bottom_line"].startswith("Confirmed critical-severity finding") and "Fix: new helper Data/LedgerQueries.cs" in page["bottom_line"]
    assert "An attacker can add predicates" in page["bottom_line"]


def test_overflowing_bottom_line_ends_with_an_ellipsis_never_a_silent_cut():
    drawn = one_pager._bottom_lines("word " * 200)
    assert len(drawn) == one_pager._BOTTOM_LINES and drawn[-1].endswith(_encode_ellipsis())


def _encode_ellipsis() -> bytes:
    return "\u2026".encode("cp1252")


def test_lists_keep_whole_items_rather_than_ending_mid_sentence():
    text = ("- No String.Format builds SQL from the region anywhere in the controller.\n"
            "- Regression assertions 1 to 5 pass in CI and the owner attaches the run output.\n"
            "- A Semgrep rescan of the fixed commit no longer reports the fingerprint or any sibling finding at the other lines.")
    shortened = one_pager._prose(text, 200)
    assert shortened.splitlines() == ["\u2022 No String.Format builds SQL from the region anywhere in the controller.",
                                      "\u2022 Regression assertions 1 to 5 pass in CI and the owner attaches the run output."]


def test_bulleted_impact_and_punctuated_severity_are_understood():
    report = LIVE_SHAPE.replace("**Severity**: CRITICAL (my own assessment)", "**Severity**: HIGH. It becomes CRITICAL without platform authentication.")
    report = report.replace("**Impact.** A single quote ends the literal. From there an attacker can add predicates, UNION queries or stacked "
                            "statements to the batch, which runs as the SQL login loaded from Key Vault (lines 39\u201354; values not inspected).",
                            "- **Reachability:** The route exposes the action to any client.\n"
                            "- **Impact:** An attacker can close the literal and append UNION queries or stacked T-SQL.")
    page = one_pager.summary(report, avit=AVIT)
    assert page["severity"] == "HIGH"
    assert page["bottom_line"].startswith("Confirmed high-severity finding at LedgerController.cs:96")
    assert "An attacker can close the literal and append UNION queries or stacked T-SQL." in page["bottom_line"]
    assert "Severity \xb7 HIGH." not in _text(one_pager.render(page))


def test_bottom_line_skips_labelled_structure_and_names_the_fix_action():
    report = LIVE_SHAPE.replace(
        "**Finding and impact**:\n\n**The rule's claim.** A non-numeric parameter of a public action reaches a System.Data.SqlClient "
        "sink without passing through any of the rule's sanitisers. The inspected code meets every condition:",
        "**Finding and impact**:\n- Entry point: Index is a public action on LedgerController reached through the default route.\n"
        "- Path to SQL: the region is stored in a static field and formatted into three SQL strings.")
    report = report.replace("**Impact.** A single quote ends the literal. From there an attacker can add predicates, UNION queries or stacked "
                            "statements to the batch, which runs as the SQL login loaded from Key Vault (lines 39\u201354; values not inspected).",
                            "**Notes.** Nothing else.")
    report = report.replace("Use constant SQL with `@region` bound as `SqlDbType.NVarChar` at lines 87, 93, 100, 205 and 211.",
                            "The fix moves the SQL templates into a small helper that binds the region as a parameter.")
    report = report.replace("**Acceptance Criteria**:\n- No SQL", "**Acceptance Criteria**:\nall six queries use parameters.\n- No SQL")
    page = one_pager.summary(report, avit=AVIT)
    assert "Entry point" not in page["bottom_line"] and "Path to SQL" not in page["bottom_line"]
    assert "Fix: move the SQL templates into a small helper that binds the region as a parameter" in page["bottom_line"]
    assert dict(page["right"])["Done when"].startswith("All six queries use parameters.")


@pytest.mark.parametrize(("word", "base"), [("moves", "move"), ("binds", "bind"), ("replaces", "replace"), ("passes", "pass"),
                                            ("fixes", "fix"), ("adds", "add"), ("uses", "use")])
def test_base_verb(word, base):
    assert one_pager._base_verb(word) == base
