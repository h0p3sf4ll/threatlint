'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { dispositionState, normalizeReviewMarkdown, hasFpEvidence } = require('../lib/finding-disposition.cjs');
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

test('canonical bulleted safe behavior preserves a confirmed FP with an evidence table', () => {
  const source = '# Finding Review\n\n#### [FP-001] — Mock request assertion\n' +
    '**Disposition**: FALSE POSITIVE\n**Severity**: INFO\n**Confidence**: CONFIRMED\n' +
    '##### Evidence\n\n| Location | Inspected behavior |\n| --- | --- |\n' +
    '| `tests/request.test.js:14` | The header value is a synthetic constant asserted against a mocked request. |\n\n' +
    '- **Verified Safe Behavior**: The test uses a local mock and a literal placeholder; no production credential is present.\n';
  const result = parseReport(source, 'appsec-fp-reviewer');
  assert.equal(result.markdown, source);
  assert.equal(result.findings[0].disposition, 'FALSE POSITIVE');
  assert.equal(result.findings[0].confidence, 'CONFIRMED');
  assert.equal(result.findings[0].unverified, false);
  assert.deepEqual(result.findings[0].evidence, ['tests/request.test.js:14']);
  assert.equal(normalizeReviewMarkdown(result.markdown), source);
});

test('a standalone bold Evidence label and colon-inside-bold safe behavior preserve a confirmed FP', () => {
  const source = '# Finding Review\n\n#### [FP-001] — Synthetic request assertion\n' +
    '**Disposition**: FALSE POSITIVE\n**Severity**: INFO\n**Confidence**: CONFIRMED\n\n' +
    '**Evidence**\n\n| Location | Inspected behavior |\n| --- | --- |\n' +
    '| `tests/request.test.js:14` | The test compares a literal sample header with a mocked request. |\n\n' +
    '**Verified Safe Behavior:** The sample value is confined to a local test and never authorizes a network request.\n';
  const normalized = normalizeReviewMarkdown(source);
  const result = parseReport(normalized, 'appsec-fp-reviewer');
  assert.equal(normalized, source);
  assert.equal(result.markdown, source);
  assert.equal(result.findings[0].disposition, 'FALSE POSITIVE');
  assert.equal(result.findings[0].confidence, 'CONFIRMED');
  assert.equal(result.findings[0].unverified, false);
  assert.deepEqual(result.findings[0].evidence, ['tests/request.test.js:14']);
});

test('proof sections support bold labels, bullet labels, and headings with either colon placement', () => {
  const renderers = [
    name => `**${name}**:`,
    name => `**${name}:**`,
    name => `- **${name}**:`,
    name => `  * **${name}:**`,
    name => `+ **${name}:**`,
    name => `##### ${name}\n`,
  ];
  for (const label of renderers) {
    const proof = `${label('Evidence')} src/query.py:12 binds input.\n` +
      `${label('Verified Safe Behavior')} Parameters are always bound as data.\n`;
    const source = '# Finding Review\n\n#### [FP-001] — Query\n**Disposition:** FALSE POSITIVE\n' + proof;
    assert.equal(hasFpEvidence(proof), true, proof);
    const result = parseReport(source, 'appsec-fp-reviewer');
    assert.equal(result.markdown, source);
    assert.equal(result.findings[0].disposition, 'FALSE POSITIVE');
    assert.equal(result.findings[0].unverified, false);
  }
});

test('empty and placeholder proof cannot borrow content from the next bullet field', () => {
  for (const placeholder of ['', 'unknown', 'N/A', 'not inspected', 'TBD']) {
    const proof = `- **Evidence:** ${placeholder}\n` +
      '- **Verified Safe Behavior:** Parameters are always bound as data.\n';
    assert.equal(hasFpEvidence(proof), false, placeholder);
    assert.equal(hasFpEvidence('- **Evidence:** src/query.py:12 binds input.\n' +
      `- **Verified Safe Behavior:** ${placeholder}\n- **Resolution Plan:** Inspect caller paths and deployment configuration.\n`), false);
  }
  assert.equal(hasFpEvidence('```md\n- **Evidence:** src/query.py:12 binds input.\n' +
    '- **Verified Safe Behavior:** Parameters are always bound as data.\n```\n'), false);
});

test('proof requires complete labels and blank standalone sections do not borrow later fields', () => {
  const safe = '**Verified Safe Behavior:** Parameters are always bound as data.\n';
  for (const evidence of ['**Evidence**Suffix: unrelated prose', '**Evidence gap**: missing source',
    '##### Evidence gap\nMissing source', '**Evidence**\n**Other**\nUnrelated prose',
    '**Evidence**\n# Appendix\nUnrelated prose', '**Evidence:**\n**Other:** Unrelated prose']) {
    assert.equal(hasFpEvidence(`${evidence}\n${safe}`), false, evidence);
  }
  assert.equal(hasFpEvidence('**Evidence**\nsrc/query.py:12 binds input.\n' +
    '**Verified Safe Behavior**\n**Resolution Plan**\nInspect the caller before deciding.\n'), false);
});

test('unproven bullet and colon-inside-bold dispositions stay conservative', () => {
  for (const label of ['**Disposition:**', '- **Disposition**:', '* **Verdict:**']) {
    const source = `# Finding Review\n\n#### [FP-001] — Query\n${label} FALSE POSITIVE\n` +
      '**Evidence:** src/query.py:12 reaches execute.\n';
    const result = parseReport(source, 'appsec-fp-reviewer');
    assert.equal(result.findings[0].disposition, 'TRUE POSITIVE');
    assert.equal(result.findings[0].unverified, true);
    assert.match(result.markdown, /CONSERVATIVE DEFAULT/);
  }
});

test('fenced disposition and conservative examples do not override the actual finding fields', () => {
  const source = '# Finding Review\n\n#### [FP-001] — Confirmed issue\n' +
    '```md\n**Disposition:** AMBIGUOUS\n**Decision basis:** CONSERVATIVE DEFAULT\n' +
    '**Validation status:** UNVERIFIED\n**Confidence:** THEORETICAL\n```\n' +
    '- **Disposition:** TRUE POSITIVE\n- **Confidence:** CONFIRMED\n' +
    '**Evidence**: src/query.py:12 directly interpolates the caller input.\n';
  const result = parseReport(source, 'appsec-fp-reviewer');
  assert.equal(result.findings[0].disposition, 'TRUE POSITIVE');
  assert.equal(result.findings[0].confidence, 'CONFIRMED');
  assert.equal(result.findings[0].unverified, false);
  assert.equal(result.markdown, source);
});

test('indented code examples cannot supply proof or override actual finding metadata', () => {
  for (const indent of ['    ', '\t', ' \t']) {
    const examples = ['**Disposition:** AMBIGUOUS', '**Decision basis:** CONSERVATIVE DEFAULT',
      '**Validation status:** UNVERIFIED', '**Confidence:** THEORETICAL',
      '**Evidence:** src/query.py:12 binds input.',
      '**Verified Safe Behavior:** Parameters are always bound as data.']
      .map(line => indent + line).join('\n') + '\n';
    assert.equal(hasFpEvidence(examples), false);
    const source = '# Finding Review\n\n#### [FP-001] — Confirmed issue\n' + examples +
      '\n**Disposition:** TRUE POSITIVE\n**Confidence:** CONFIRMED\n';
    const result = parseReport(source, 'appsec-fp-reviewer');
    assert.equal(result.markdown, source);
    assert.equal(result.findings[0].disposition, 'TRUE POSITIVE');
    assert.equal(result.findings[0].confidence, 'CONFIRMED');
    assert.equal(result.findings[0].unverified, false);
  }
});

test('up to three leading spaces still allow actual bullet proof and metadata', () => {
  for (const indent of ['', ' ', '  ', '   ']) {
    const source = '# Finding Review\n\n#### [FP-001] — Bound value\n' +
      ['- **Disposition:** FALSE POSITIVE', '- **Confidence:** CONFIRMED',
        '- **Evidence:** src/query.py:12 binds input.',
        '- **Verified Safe Behavior:** Parameters are always bound as data.']
        .map(line => indent + line).join('\n') + '\n';
    const result = parseReport(source, 'appsec-fp-reviewer');
    assert.equal(result.markdown, source);
    assert.equal(result.findings[0].disposition, 'FALSE POSITIVE');
    assert.equal(result.findings[0].confidence, 'CONFIRMED');
    assert.equal(result.findings[0].unverified, false);
  }
});
