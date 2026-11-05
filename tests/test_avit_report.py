"""Report parsing is independent of ServiceNow sessions and Semgrep APIs."""

import pytest

from threatlint import avit_report
from threatlint import avit_resolve

AVIT = "AVIT000000000000001"


def finding(disposition="FALSE POSITIVE", identifier="FP-001", avit=AVIT):
    return (
        f"#### [{identifier}] — Synthetic finding\n"
        f"**Original finding**: {avit}; rule; src/a.py:42\n"
        f"**Disposition**: {disposition}\n"
        "**Confidence**: HIGH (source traced)\n"
        "**Evidence**: `src/a.py:42` binds the parameter.\n"
        "**Verified Safe Behavior**: The bound value cannot change query syntax.\n"
    )


@pytest.mark.parametrize("disposition", ["TRUE POSITIVE", "FALSE POSITIVE"])
def test_numbered_verdicts_keep_metadata(disposition):
    assert avit_report.verdict_for(finding(disposition.lower()), AVIT) == {
        "id": "FP-001", "title": "Synthetic finding",
        "disposition": disposition, "confidence": "HIGH",
    }


def test_plain_single_finding_uses_report_title_and_verdict_alias():
    report = f"# Single finding\n\n**Original finding**: {AVIT}\n**Verdict**: **AMBIGUOUS**\n"
    verdict = avit_report.verdict_for(report, AVIT)
    assert {key: verdict[key] for key in ("id", "title", "disposition", "confidence")} == {
        "id": "", "title": "Single finding", "disposition": "TRUE POSITIVE", "confidence": "",
    }
    assert verdict["unverified"] is True
    assert verdict["decision_basis"] == "CONSERVATIVE DEFAULT"


def test_heading_fallback_keeps_the_avit_without_an_original_finding_line():
    report = f"## FP-001 — {AVIT}\nDisposition: TRUE POSITIVE\n"
    assert avit_report.verdict_for(report, AVIT)["disposition"] == "TRUE POSITIVE"


def test_duplicate_consistent_findings_keep_the_first_but_conflicts_fail():
    assert avit_report.verdict_for(finding() + finding(identifier="FP-002"), AVIT)["id"] == "FP-001"
    with pytest.raises(avit_report.ResolveError, match="conflicting dispositions"):
        avit_report.verdict_for(finding() + finding("TRUE POSITIVE", "FP-002"), AVIT)
    with pytest.raises(avit_report.ResolveError, match="conflicting dispositions"):
        avit_report.verdict_for(finding() + "**Verdict**: TRUE POSITIVE\n", AVIT)


def test_prefix_avit_numbers_are_distinct_in_numbered_and_plain_reports():
    short, long = "AVIT1234567", "AVIT12345678"
    numbered = finding("TRUE POSITIVE", "FP-001", long) + finding("FALSE POSITIVE", "FP-002", short)
    assert avit_report.verdict_for(numbered, short)["disposition"] == "FALSE POSITIVE"
    assert avit_report.verdict_for(numbered, long)["disposition"] == "TRUE POSITIVE"

    plain = f"# Review\n**Original finding**: {long}; rule\n**Disposition**: TRUE POSITIVE\n"
    with pytest.raises(avit_report.ResolveError, match="no finding"):
        avit_report.verdict_for(plain, short)


def test_avit_embedded_in_another_identifier_is_not_selected():
    target = "AVIT1234567"
    for source in (f"X{target}", f"{target}X"):
        with pytest.raises(avit_report.ResolveError, match="no finding"):
            avit_report.verdict_for(finding(avit=source), target)
        with pytest.raises(avit_report.ResolveError, match="no finding"):
            avit_report.verdict_for(f"## FP-001 — {source}\nDisposition: FALSE POSITIVE\n", target)


@pytest.mark.parametrize(
    ("report", "message"),
    [
        ("No finding here", "no finding"),
        (finding("undecided"), "has no TRUE POSITIVE"),
        (f"Original finding: {AVIT}\nOriginal finding: OTHER\nVerdict: TRUE POSITIVE", "no finding"),
    ],
)
def test_missing_or_unscoped_verdicts_are_rejected(report, message):
    with pytest.raises(avit_report.ResolveError, match=message):
        avit_report.verdict_for(report, AVIT)


def test_report_line_requires_the_requested_avit_and_a_terminal_line_number():
    assert avit_report.report_line(finding(), AVIT) == 42
    assert avit_report.report_line(finding(), "AVIT000000000000002") is None
    assert avit_report.report_line(finding().replace(":42\n", ":42 details\n"), AVIT) is None


def test_original_imports_keep_the_parser_and_error_identity():
    assert avit_resolve.ResolveError is avit_report.ResolveError
    assert avit_resolve.verdict_for is avit_report.verdict_for
    assert avit_resolve._report_line is avit_report.report_line
