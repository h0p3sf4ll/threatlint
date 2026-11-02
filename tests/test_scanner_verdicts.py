"""Pure report syntax and compatibility of the scanner base's verdict-selection seam."""

import re

import pytest

from threatlint.scanners import base, verdicts


def finding(reference="DOJO-123", disposition="FALSE POSITIVE", identifier="FP-001"):
    return (
        f"#### [{identifier}] — Example\n\n"
        f"**Original finding**: {reference}; rule; tool; src/file.py:42\n"
        f"**Disposition**: {disposition}\n"
        "**Confidence**: CONFIRMED (source inspected)\n"
    )


def test_candidates_retain_original_finding_and_normalize_fields():
    [(original, verdict)] = verdicts.candidates("# Report\n\n" + finding(disposition="false positive"))
    assert original == "DOJO-123; rule; tool; src/file.py:42"
    assert verdict == {"id": "FP-001", "title": "Example", "disposition": "FALSE POSITIVE", "confidence": "CONFIRMED"}


@pytest.mark.parametrize("heading", ["##", "###", "####", "#####", "######"])
def test_heading_fallback_and_verdict_alias(heading):
    report = f"{heading} [FP-009] SONAR-abcdef\nVerdict: ambiguous\n"
    assert base.verdict_for(report, "SONAR-abcdef") == {
        "id": "FP-009", "title": "SONAR-abcdef", "disposition": "AMBIGUOUS", "confidence": "",
    }


def test_original_finding_takes_precedence_over_a_reference_in_the_title():
    report = finding().replace("Example", "DOJO-999")
    with pytest.raises(base.ScannerError, match="no finding"):
        base.verdict_for(report, "DOJO-999")


def test_conflicting_dispositions_remain_an_actionable_error():
    report = finding() + "\n" + finding(disposition="TRUE POSITIVE", identifier="FP-002")
    with pytest.raises(base.ScannerError, match="conflicting dispositions"):
        base.verdict_for(report, "DOJO-123")


def test_repeated_consistent_dispositions_keep_first_verdict():
    report = finding() + "\n" + finding(identifier="FP-002")
    assert base.verdict_for(report, "DOJO-123")["id"] == "FP-001"


def test_missing_disposition_is_not_inferred():
    with pytest.raises(base.ScannerError, match="has no TRUE POSITIVE"):
        base.verdict_for(finding(disposition="UNKNOWN"), "DOJO-123")


@pytest.mark.parametrize(
    ("text", "expected"),
    [("DOJO-123", True), ("(dojo-123)", True), ("DOJO-1234", False), ("X-DOJO-123", False), ("DOJO-123-X", False)],
)
def test_reference_token_boundaries(text, expected):
    assert verdicts.mentions(text, "DOJO-123") is expected
    assert base.mentions(text, "DOJO-123") is expected


def test_report_line_and_base_import_remain_compatible():
    assert base.report_line is verdicts.report_line
    assert base.report_line(finding(), "DOJO-123") == 42
    assert base.report_line(finding("DOJO-1234"), "DOJO-123") is None


def test_base_reference_matcher_remains_patchable(monkeypatch):
    monkeypatch.setattr(base, "mentions", lambda text, reference: reference == "synthetic")
    assert base.verdict_for(finding(), "synthetic")["id"] == "FP-001"


def test_base_disposition_pattern_remains_patchable(monkeypatch):
    monkeypatch.setattr(base, "_DISPOSITION", re.compile("AMBIGUOUS"))
    assert base.verdict_for(finding(disposition="AMBIGUOUS"), "DOJO-123")["disposition"] == "AMBIGUOUS"
    with pytest.raises(base.ScannerError, match="has no TRUE POSITIVE"):
        base.verdict_for(finding(disposition="FALSE POSITIVE"), "DOJO-123")
