"""Binary disposition defaults preserve evidence limits and never fabricate verification."""

import pytest

from threatlint import avit_report, finding_review as review
from threatlint.integrations.common import verdict_for as integration_verdict

AVIT = 'AVIT1234567'
PROOF = ('**Evidence**: `src/query.py:12` passes input separately from the SQL template.\n'
         '**Verified Safe Behavior**: The database driver binds the input as data.\n')


def section(ident='FP-001', reference=AVIT, disposition='FALSE POSITIVE', proof=PROOF):
    return (f'#### [{ident}] — Query\n**Original finding**: {reference}; rule; src/query.py:12\n'
            f'**Disposition**: {disposition}\n**Confidence**: THEORETICAL\n{proof}')


def test_legacy_ambiguous_is_tp_without_increasing_confidence():
    source = '# False Positive Review: example\n' + section(disposition='AMBIGUOUS', proof='')
    result = review.normalize_report(source)
    assert result.startswith('# Finding Review: example\n')
    assert '**Disposition**: TRUE POSITIVE' in result
    assert '**Confidence**: THEORETICAL' in result
    assert '**Decision basis**: CONSERVATIVE DEFAULT' in result
    assert 'does not establish exploit reproduction' in result
    assert review.normalize_report(result) == result
    parsed = avit_report.verdict_for(result, AVIT)
    assert parsed['unverified'] is True and parsed['disposition'] == 'TRUE POSITIVE'


@pytest.mark.parametrize('proof', ['', '**Evidence**: unknown\n**Verified Safe Behavior**: N/A\n',
                                   '**Evidence**: src/query.py:12 was inspected.\n'])
def test_fp_requires_both_evidence_and_verified_safe_behavior(proof):
    report = section(proof=proof)
    parsed = avit_report.verdict_for(report, AVIT)
    assert parsed['disposition'] == 'TRUE POSITIVE'
    assert parsed['unverified'] is True
    normalized = review.normalize_report(report)
    assert '**Disposition**: FALSE POSITIVE' not in normalized


def test_other_finding_proof_cannot_authorize_false_positive():
    report = section(proof='') + section('FP-002', 'AVIT1234568')
    parsed = avit_report.verdict_for(report, AVIT)
    assert parsed['disposition'] == 'TRUE POSITIVE' and parsed['unverified']
    assert avit_report.verdict_for(report, 'AVIT1234568')['disposition'] == 'FALSE POSITIVE'
    normalized = review.normalize_report(report)
    assert normalized.count('**Disposition**: FALSE POSITIVE') == 1
    assert normalized.count('**Disposition**: TRUE POSITIVE') == 1


def test_proven_fp_is_unchanged_and_does_not_gain_unverified_flag():
    assert avit_report.verdict_for(section(), AVIT)['disposition'] == 'FALSE POSITIVE'
    assert not avit_report.verdict_for(section(), AVIT).get('unverified')


def test_generic_integration_uses_same_conservative_default():
    parsed = integration_verdict(section(reference='DOJO-123', proof=''), 'DOJO-123')
    assert parsed['disposition'] == 'TRUE POSITIVE' and parsed['unverified']


def test_conflicting_labels_in_one_declaration_fail_closed():
    with pytest.raises(review.FindingReviewError, match='conflicting'):
        review.normalize_report(section(disposition='TRUE POSITIVE / FALSE POSITIVE'))


def test_fenced_examples_cannot_supply_fp_proof_or_declared_verdicts():
    source = section(proof='```md\n' + PROOF + '**Disposition**: AMBIGUOUS\n```\n')
    result = review.normalize_report(source)
    assert '**Disposition**: TRUE POSITIVE' in result
    assert '```md\n' + PROOF + '**Disposition**: AMBIGUOUS\n```' in result
    assert review.has_fp_evidence(source) is False


def test_real_evidence_section_can_contain_quoted_code():
    source = section(proof='**Evidence**:\n```python\ncursor.execute(query, params)\n```\n'
                           '**Verified Safe Behavior**: The parameters are bound as data.\n')
    assert review.has_fp_evidence(source)
    assert '**Disposition**: FALSE POSITIVE' in review.normalize_report(source)


@pytest.mark.parametrize('label', ['**{}**:', '**{}:**', '- **{}**:', '- **{}:**', '* **{}:**'])
def test_proof_accepts_markdown_bold_and_bullet_formatting(label):
    proof = (label.format('Evidence') + ' `src/query.py:12` binds the input as data.\n'
             + label.format('Verified Safe Behavior') + ' The bound parameter cannot change query syntax.\n')
    source = '# Finding Review\n' + section(proof=proof)
    assert review.has_fp_evidence(source)
    assert review.normalize_report(source) == source
    assert avit_report.verdict_for(source, AVIT)['disposition'] == 'FALSE POSITIVE'


def test_canonical_fp_with_evidence_table_and_bulleted_safe_behavior_stays_fp():
    source = '# Finding Review\n' + section(proof=(
        '##### Evidence\n'
        '| Location | Inspected behavior |\n| --- | --- |\n'
        '| `tests/test_client.py:12` | The test builds a synthetic header assertion. |\n'
        '| `tests/test_client.py:18` | The HTTP client is mocked; the assertion is not production output. |\n'
        '- **Verified Safe Behavior**: This synthetic assertion reaches only the mocked client and exposes no real credential.\n'
        '- **Proposed Tuning**: Narrow the rule to exclude this proven synthetic test case.\n'
    ))
    assert review.normalize_report(source) == source
    assert avit_report.verdict_for(source, AVIT)['disposition'] == 'FALSE POSITIVE'


def test_evidence_table_and_colon_inside_bold_safe_behavior_stay_false_positive():
    source = '# Finding Review\n' + section(proof=(
        '**Evidence**\n'
        '| Location | Inspected behavior |\n| --- | --- |\n'
        '| `tests/test_client.py:12` | The header assertion uses a synthetic value. |\n'
        '| `tests/test_client.py:18` | The client is mocked and makes no real request. |\n'
        '**Verified Safe Behavior:** The inspected test data reaches only a mocked client, with no real credential exposure.\n'
        '**Proposed Tuning:** Exclude only the independently verified synthetic test fixture.\n'
    ))
    assert review.normalize_report(source) == source
    assert avit_report.verdict_for(source, AVIT)['disposition'] == 'FALSE POSITIVE'


@pytest.mark.parametrize('missing', ['Evidence', 'Verified Safe Behavior'])
@pytest.mark.parametrize('placeholder', ['', 'unknown', 'N/A'])
def test_adjacent_bulleted_fields_do_not_supply_missing_proof(missing, placeholder):
    proof = (f'**Evidence:** {placeholder if missing == "Evidence" else "src/query.py:12 was inspected."}\n'
             f'- **Verified Safe Behavior:** {placeholder if missing == "Verified Safe Behavior" else "The driver binds input as data."}\n'
             '- **Proposed Tuning:** A substantive proposal does not substitute for missing proof.\n')
    source = section(proof=proof)
    assert not review.has_fp_evidence(source)
    assert avit_report.verdict_for(source, AVIT).get('unverified') is True


def test_fenced_conservative_basis_does_not_overwrite_the_actual_decision():
    source = section() + '```markdown\n- **Decision basis:** CONSERVATIVE DEFAULT\n```\n'
    assert not avit_report.verdict_for(source, AVIT).get('unverified')
    assert review.report_fields(source, 'Decision basis') == []
    assert review.normalize_verdict({'disposition': 'AMBIGUOUS'}, body=source)['unverified']


def test_real_conservative_basis_remains_unverified_with_bold_bullet_formatting():
    source = section(disposition='TRUE POSITIVE') + '- **Decision basis:** CONSERVATIVE DEFAULT\n'
    assert avit_report.verdict_for(source, AVIT)['unverified'] is True


def test_section_heading_must_match_the_whole_alias():
    source = section(proof='##### Evidence to obtain\nInspect the missing source file.\n' + PROOF.splitlines()[1] + '\n')
    assert not review.has_fp_evidence(source)


def test_crlf_report_keeps_actual_fields_and_conservative_defaults():
    source = '# Finding Review\r\n' + section().replace('\n', '\r\n')
    assert review.normalize_report(source) == source
    assert review.report_fields(source, 'Disposition') == ['FALSE POSITIVE']
    ambiguous = source.replace('FALSE POSITIVE', 'AMBIGUOUS')
    normalized = review.normalize_report(ambiguous)
    assert avit_report.verdict_for(normalized, AVIT)['unverified'] is True


def test_indented_code_examples_cannot_supply_missing_proof():
    source = section(proof=''.join('    ' + line + '\n' for line in PROOF.splitlines()))
    assert not review.has_fp_evidence(source)
    assert avit_report.verdict_for(source, AVIT)['unverified'] is True
