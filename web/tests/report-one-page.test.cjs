'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { parseReport } = require('../lib/reports.cjs');
const { primaryFinding } = require('../lib/report-one-page.cjs');
const { createWorkbench } = require('../server.js');

const REVIEW = [
  '# Finding Review: Example deployment', '',
  '#### [FP-001] — Debug mode is enabled', '',
  '**Severity**: HIGH', '**Disposition**: TRUE POSITIVE', '**Confidence**: CONFIRMED',
  '**Finding and impact**: Error details can reveal internal configuration.',
  '**Evidence**: The deployed setting is recorded at `server/settings.py:12`.', '',
  '```python', 'DEBUG = True', '```', '',
  '**Proposed fix**: Disable debug mode in production.',
  '**Proposed fix patch**:', '', '```diff', '@@ -12 +12 @@', '-DEBUG = True', '+DEBUG = False', '```', '',
  '#### [FP-002] — Candidate missing deployment evidence', '',
  '**Severity**: CRITICAL', '**Disposition**: TRUE POSITIVE', '**Decision basis**: CONSERVATIVE DEFAULT',
  '**Evidence**: Recorded response only.', '```http', 'HTTP/1.1 200 OK', '```', '',
  '**Resolution plan**: Check the deployed configuration.', '',
].join('\n');

test('the default one-page summary covers the most severe genuine finding', () => {
  const { findings } = parseReport(REVIEW, 'appsec-fp-reviewer');
  assert.equal(primaryFinding(findings).id, 'FP-001');
  assert.equal(primaryFinding([{ id: 'A-1', disposition: 'FALSE POSITIVE', severity: 'CRITICAL' }, { id: 'A-2', severity: 'LOW' }]).id, 'A-2');
});

test('a saved report downloads a one-page PDF for the default or selected finding', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-test-onepager-'));
  const repo = path.join(dir, 'repo');
  fs.mkdirSync(repo);
  const workbench = createWorkbench({ storageDir: dir, integrations: { convertToWord: async () => {} } });
  try {
    const sessionId = workbench.store.create(repo);
    const report = await workbench.generateReport('appsec-fp-reviewer', REVIEW, sessionId);
    await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
    const { port } = workbench.server.address();
    const url = `http://127.0.0.1:${port}/api/report/${sessionId}/${report.agentId}/${report.timestamp}/onepager`;
    const response = await fetch(url);
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type'), /application\/pdf/);
    assert.match(response.headers.get('content-disposition'), /ONE PAGER SUMMARY\] FP-001-threatlint-review\.pdf/);
    const pdf = Buffer.from(await response.arrayBuffer());
    assert.equal(pdf.subarray(0, 5).toString(), '%PDF-');
    assert.equal(pdf.toString('latin1').split('/Type /Page ').length - 1, 1);
    const other = await fetch(url + '?finding=FP-002');
    assert.equal(other.status, 200);
    assert.match(other.headers.get('content-disposition'), /FP-002-threatlint-review\.pdf/);
    assert.equal((await fetch(url + '?finding=FP-999')).status, 404);
    assert.equal((await fetch(url.replace('/onepager', '/pptx'))).status, 404, 'the PowerPoint export was removed');
  } finally {
    await workbench.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
