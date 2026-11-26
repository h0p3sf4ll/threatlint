'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const onePager = require('../lib/one-pager.cjs');

const EXAMPLE = path.join(__dirname, '../examples/fp-review.md');

test('the summary is named after its Word report', () => {
  assert.equal(onePager.attachmentName('AVIT0000001-threatlint-fp-review-20261126T015900123456Z.docx'),
    '[ONE PAGER SUMMARY] AVIT0000001-threatlint-fp-review-20261126T015900123456Z.pdf');
});

test('the Python renderer produces a one-page PDF for the selected finding', async () => {
  const file = await onePager.attachment(EXAMPLE, 'AVIT0000001-threatlint-fp-review.docx', { avit: 'AVIT0000001', findingId: 'FP-002' });
  assert.equal(file.type, 'application/pdf');
  assert.equal(file.content.subarray(0, 5).toString(), '%PDF-');
  assert.equal(file.content.toString('latin1').split('/Type /Page ').length - 1, 1);
});

test('the CLI receives the report, AVIT, and a validated finding id, and its temporary file is removed', async () => {
  let seen;
  const runCli = async args => {
    seen = args;
    fs.writeFileSync(args[2], '%PDF-1.4 stub');
    return { code: 0, stdout: args[2], stderr: '' };
  };
  const content = await onePager.render(EXAMPLE, { avit: 'AVIT0000001', findingId: 'FP-001', runCli });
  assert.equal(content.toString(), '%PDF-1.4 stub');
  assert.deepEqual([seen[0], seen[1], ...seen.slice(3)], ['one-pager', EXAMPLE, '--avit', 'AVIT0000001', '--finding', 'FP-001']);
  assert.equal(fs.existsSync(path.dirname(seen[2])), false);
  await onePager.render(EXAMPLE, { findingId: '--finding; rm', runCli });
  assert.ok(!seen.includes('--finding'), 'an invalid finding id is never passed to the CLI');
});

test('a failed render blocks posting, and only a report without findings may go without a summary', async () => {
  const failing = async () => ({ code: 1, stdout: '', stderr: 'ERROR: The report has no finding FP-404' });
  await assert.rejects(onePager.attachment(EXAMPLE, 'A.docx', { runCli: failing }), error => error.status === 500 && /nothing was posted: The report has no finding FP-404/.test(error.message));
  await assert.rejects(onePager.optionalAttachment(EXAMPLE, 'A.docx', { runCli: failing }), /nothing was posted/);
  const empty = async () => ({ code: 3, stdout: '', stderr: 'ERROR: The report has no structured finding to summarize' });
  assert.equal(await onePager.optionalAttachment(EXAMPLE, 'A.docx', { runCli: empty }), null);
  await assert.rejects(onePager.attachment(EXAMPLE, 'A.docx', { runCli: empty }), error => error.code === 'one_pager_no_findings');
  const notPdf = async args => { fs.writeFileSync(args[2], 'not a pdf'); return { code: 0, stdout: '', stderr: '' }; };
  await assert.rejects(onePager.attachment(EXAMPLE, 'A.docx', { runCli: notPdf }), /could not be generated/);
  await assert.rejects(onePager.render(path.join(os.tmpdir(), 'missing-report.md')), error => error.status === 409);
});
