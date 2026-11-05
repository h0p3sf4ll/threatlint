'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { dispositionState, normalizeReviewMarkdown } = require('../lib/finding-disposition.cjs');
const { parseReport } = require('../lib/reports.cjs');

test('legacy ambiguity becomes an unverified true positive without asserting confirmation', () => {
  assert.deepEqual(dispositionState('AMBIGUOUS'), { disposition: 'TRUE POSITIVE', unverified: true });
  const source = '# False Positive Review: demo\n\n#### [FP-001] — Missing runtime evidence\n**Disposition**: AMBIGUOUS\n**Confidence**: THEORETICAL\n**Blocking Evidence**: Production edge configuration is unavailable.\n';
  const normalized = normalizeReviewMarkdown(source);
  assert.match(normalized, /^# Finding Review: demo/);
  assert.match(normalized, /\*\*Disposition\*\*: TRUE POSITIVE/);
  assert.match(normalized, /CONSERVATIVE DEFAULT/);
  assert.match(normalized, /\*\*Confidence\*\*: THEORETICAL/);
  assert.match(normalized, /Production edge configuration is unavailable/);
  const finding = parseReport(normalized, 'appsec-fp-reviewer').findings[0];
  assert.equal(finding.disposition, 'TRUE POSITIVE');
  assert.equal(finding.unverified, true);
});

test('report normalization preserves examples inside code fences and is idempotent', () => {
  const source = '# Finding Review: demo\n\n```md\n# False Positive Review: example\n**Disposition**: AMBIGUOUS\n```\n';
  assert.equal(normalizeReviewMarkdown(source), source);
  assert.equal(normalizeReviewMarkdown(normalizeReviewMarkdown(source)), source);
});

test('a claimed FP without proof remains open as unverified TP', () => {
  const source = '# Finding Review\n\n#### [FP-001] — Unproven\n**Disposition**: FALSE POSITIVE\n**Confidence**: PLAUSIBLE\n**Evidence**: src/query.py:12 reaches execute.\n';
  const parsed = parseReport(source, 'appsec-fp-reviewer');
  assert.equal(parsed.findings[0].disposition, 'TRUE POSITIVE');
  assert.equal(parsed.findings[0].unverified, true);
  assert.match(parsed.markdown, /CONSERVATIVE DEFAULT/);
});

test('one finding cannot borrow another findings FP proof', () => {
  const source = '# Finding Review\n\n#### [FP-001] — Unproven\n**Disposition**: FALSE POSITIVE\n' +
    '\n#### [FP-002] — Proven\n**Disposition**: FALSE POSITIVE\n**Evidence**: src/query.py:12 binds the value.\n**Verified Safe Behavior**: Parameter binding covers the same value on every execution path.\n';
  const parsed = parseReport(source, 'appsec-fp-reviewer');
  assert.equal(parsed.findings[0].disposition, 'TRUE POSITIVE');
  assert.equal(parsed.findings[0].unverified, true);
  assert.equal(parsed.findings[1].disposition, 'FALSE POSITIVE');
  assert.equal(parsed.findings[1].unverified, false);
});

test('fenced proof headings cannot authorize an FP while real evidence can quote code', () => {
  const head = '# Finding Review\n\n#### [FP-001] — Query\n**Disposition**: FALSE POSITIVE\n';
  const proof = '**Evidence**: src/query.py:12 binds input.\n**Verified Safe Behavior**: Parameters are data.\n';
  assert.equal(parseReport(head + '```md\n' + proof + '```\n', 'appsec-fp-reviewer').findings[0].disposition, 'TRUE POSITIVE');
  const real = '**Evidence**:\n```python\ncursor.execute(query, params)\n```\n**Verified Safe Behavior**: Parameters are data.\n';
  assert.equal(parseReport(head + real, 'appsec-fp-reviewer').findings[0].disposition, 'FALSE POSITIVE');
});

test('duplicate headings do not let an unproven finding borrow proof', () => {
  const heading = '#### [FP-001] — Query\n**Disposition**: FALSE POSITIVE\n';
  const proof = '**Evidence**: src/query.py:12 binds input.\n**Verified Safe Behavior**: Parameters are data.\n';
  const result = parseReport('# Finding Review\n' + heading + '\n' + heading + proof, 'appsec-fp-reviewer');
  assert.equal(result.findings[0].disposition, 'TRUE POSITIVE');
  assert.equal(result.findings[1].disposition, 'FALSE POSITIVE');
  assert.ok(result.quality.issues.some(issue => /Duplicate finding IDs/.test(issue)));
});
