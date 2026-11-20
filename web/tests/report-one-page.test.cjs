'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { parseReport } = require('../lib/reports.cjs');
const { onePageFinding, primaryFinding } = require('../lib/report-one-page.cjs');
const { readMatching } = require('../lib/zip.cjs');
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

test('one-page summaries use finding-scoped source and proposed changes', () => {
  const { findings } = parseReport(REVIEW, 'appsec-fp-reviewer');
  const selected = primaryFinding(findings);
  assert.equal(selected.id, 'FP-001');
  const page = onePageFinding(selected);
  assert.equal(page.originalCode, 'DEBUG = True');
  assert.equal(page.fixedCode, 'DEBUG = False');
  assert.equal(page.originalCodeSource, 'server/settings.py:12');
  assert.equal(page.impact, 'Error details can reveal internal configuration.');
  const unverified = onePageFinding(findings[1]);
  assert.equal(unverified.status, 'Unverified finding');
  assert.equal(unverified.originalCode, '');
  assert.equal(unverified.fixedCode, '');
});

test('a saved report exports a single slide for the default or selected finding', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-test-slide-'));
  const repo = path.join(dir, 'repo');
  fs.mkdirSync(repo);
  const workbench = createWorkbench({ storageDir: dir, integrations: { convertToWord: async () => {} } });
  try {
    const sessionId = workbench.store.create(repo);
    const report = await workbench.generateReport('appsec-fp-reviewer', REVIEW, sessionId);
    await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
    const { port } = workbench.server.address();
    const url = `http://127.0.0.1:${port}/api/report/${sessionId}/${report.agentId}/${report.timestamp}/pptx`;
    const response = await fetch(url);
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type'), /presentationml\.presentation/);
    assert.match(response.headers.get('content-disposition'), /FP-001-threatlint-one-page\.pptx/);
    const slides = readMatching(Buffer.from(await response.arrayBuffer()), /^ppt\/slides\/slide\d+\.xml$/);
    assert.equal(slides.length, 1);
    assert.match(slides[0].text, /DEBUG = True/);
    assert.match(slides[0].text, /DEBUG = False/);
    assert.match(slides[0].text, /Error details can reveal internal configuration\./);
    const other = await fetch(url + '?finding=FP-002');
    assert.equal(other.status, 200);
    const [otherSlide] = readMatching(Buffer.from(await other.arrayBuffer()), /^ppt\/slides\/slide\d+\.xml$/);
    assert.match(otherSlide.text, /Candidate missing deployment evidence/);
    assert.doesNotMatch(otherSlide.text, /DEBUG =|HTTP\/1\.1/);
    assert.equal((await fetch(url + '?finding=FP-999')).status, 404);
  } finally {
    await workbench.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
