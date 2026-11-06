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


@pytest.mark.parametrize("location", [
    "src/a.py:42.  ", "`src/a.py:42`", "`src/a.py:42`.  ",
    "src/a.py:42-45", "`src/a.py:42–45`.",
])
def test_report_line_accepts_location_formatting_and_valid_ranges(location):
    report = f"**Original finding**: {AVIT}; rule; Semgrep Code; {location}\n"
    assert avit_report.report_line(report, AVIT, "src/a.py") == 42


def test_report_line_accepts_the_observed_sentence_terminated_original_finding():
    avit = "AVIT000000000000097"
    report = (
        f"Original finding: {avit}; python.jwt.security.unverified-jwt-decode.unverified-jwt-decode; "
        "Semgrep Code SAST, version not supplied; app/utils/auth.py:97.  \n"
        "Location: app/utils/auth.py:97\n"
    )
    assert avit_report.report_line(report, avit, "app/utils/auth.py") == 97


@pytest.mark.parametrize("location", [
    "src/a.py:0", "src/a.py:0-2", "src/a.py:42-0", "src/a.py:42-41",
    "src/a.py:-1", "src/a.py:42-", "src/a.py:42 details", "src/a.py:42. More details.",
])
def test_report_line_rejects_invalid_ranges_and_trailing_prose(location):
    report = f"Original finding: {AVIT}; rule; {location}\n"
    assert avit_report.report_line(report, AVIT) is None


def test_report_line_requires_an_exact_avit_in_an_anchored_original_field():
    short, long = "AVIT1234567", "AVIT12345678"
    assert avit_report.report_line(finding(avit=long), short) is None
    for original in (f"X{short}", f"{short}X", f"{short}, {long}"):
        assert avit_report.report_line(finding(avit=original), short) is None
    assert avit_report.report_line(f"Evidence mentions Original finding: {short}; rule; a.py:42\n", short) is None
    assert avit_report.report_line(f"Original finding: {short}; rule; unknown\nLocation: a.py:42\n", short) is None
    assert avit_report.report_line(f"Location: a.py:42\nEvidence: {short}; a.py:42\n", short) is None
    assert avit_report.report_line(f"Original finding: `{short}`; rule; a.py:42\n", short.lower()) == 42


def test_report_line_rejects_conflicting_duplicates_and_accepts_consistent_locations():
    assert avit_report.report_line(finding() + finding(identifier="FP-002"), AVIT) == 42
    for changed in ("src/a.py:43", "src/other.py:42", "src/a.py:42-45", "unknown"):
        assert avit_report.report_line(finding() + finding().replace("src/a.py:42", changed), AVIT) is None


def test_report_line_checks_the_full_expected_path_with_only_existing_path_normalization():
    for expected in ("src/a.py", "./src/a.py", "/src/a.py", "src\\a.py"):
        assert avit_report.report_line(finding(), AVIT, expected) == 42
    for expected in ("a.py", "other/src/a.py", "src/../src/a.py", "src/b.py"):
        assert avit_report.report_line(finding(), AVIT, expected) is None


def test_original_imports_keep_the_parser_and_error_identity():
    assert avit_resolve.ResolveError is avit_report.ResolveError
    assert avit_resolve.verdict_for is avit_report.verdict_for
    assert avit_resolve._report_line is avit_report.report_line


@pytest.mark.parametrize('label', ['**{}**:', '**{}:**', '- **{}**:', '- **{}:**', '* **{}:**', '{}:'])
def test_metadata_fields_accept_consistent_markdown_formatting(label):
    report = (f'# Finding Review\n{label.format("Original finding")} {AVIT}; rule; src/a.py:42\n'
              f'{label.format("Disposition")} TRUE POSITIVE\n'
              f'{label.format("Confidence")} CONFIRMED\n')
    parsed = avit_report.verdict_for(report, AVIT)
    assert parsed['disposition'] == 'TRUE POSITIVE'
    assert parsed['confidence'] == 'CONFIRMED'
    assert not parsed.get('unverified')
    assert avit_report.report_line(report, AVIT, 'src/a.py') == 42


@pytest.mark.parametrize('fence', ['```', '~~~'])
def test_fenced_example_decisions_and_finding_headings_cannot_override_real_verdict(fence):
    example = (f'{fence}markdown\n#### [FP-999] — Quoted example\n'
               f'**Original finding**: {AVIT}; rule; src/other.py:99\n'
               '**Disposition**: AMBIGUOUS\n**Confidence**: THEORETICAL\n'
               '**Decision basis**: CONSERVATIVE DEFAULT\n' + fence + '\n')
    report = example + finding() + example
    assert avit_report.verdict_for(report, AVIT) == avit_report.verdict_for(finding(), AVIT)
    assert avit_report.report_line(report, AVIT) == 42


def test_only_fenced_original_finding_cannot_identify_a_report():
    report = '```markdown\n' + finding() + '```\n'
    with pytest.raises(avit_report.ResolveError, match='no finding'):
        avit_report.verdict_for(report, AVIT)
    assert avit_report.report_line(report, AVIT) is None


def test_real_conflicting_bulleted_verdict_still_fails_closed():
    with pytest.raises(avit_report.ResolveError, match='conflicting dispositions'):
        avit_report.verdict_for(finding() + '- **Verdict:** TRUE POSITIVE\n', AVIT)


def test_crlf_metadata_is_parsed_the_same_as_lf():
    report = finding().replace('\n', '\r\n')
    assert avit_report.verdict_for(report, AVIT) == avit_report.verdict_for(finding(), AVIT)
    assert avit_report.report_line(report, AVIT) == 42


@pytest.mark.parametrize('indent', ['    ', '\t'])
def test_indented_code_examples_cannot_supply_a_missing_verdict(indent):
    report = (f'#### [FP-001] — Synthetic finding\n**Original finding**: {AVIT}; src/a.py:42\n'
              f'\n{indent}**Disposition**: TRUE POSITIVE\n{indent}**Confidence**: CONFIRMED\n')
    with pytest.raises(avit_report.ResolveError, match='has no TRUE POSITIVE'):
        avit_report.verdict_for(report, AVIT)
