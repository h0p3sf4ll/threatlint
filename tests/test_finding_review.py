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
