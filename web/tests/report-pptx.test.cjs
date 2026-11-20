'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createFindingPptx } = require('../lib/report-pptx.cjs');
const { entries, readMatching } = require('../lib/zip.cjs');

test('PowerPoint export has one editable slide with source, suggested fix, impact, and status', async () => {
  const buffer = await createFindingPptx({
    id: 'FP-014', severity: 'MEDIUM', status: 'TRUE POSITIVE (unverified)',
    title: 'Missing transport header <proxy>', location: 'infra/edge.conf:19',
    originalCodeSource: 'infra/edge.conf:19–21', originalCode: 'location / {\n    proxy_pass http://app;\n}',
    fixedCode: 'add_header Strict-Transport-Security\n    "max-age=31536000" always;',
    impact: 'Browsers lack an HTTPS-only policy for future visits.',
  });
  assert.ok(Buffer.isBuffer(buffer));
  const [slide, ...extraSlides] = readMatching(buffer, /^ppt\/slides\/slide\d+\.xml$/);
  assert.equal(extraSlides.length, 0);
  assert.match(slide.text, /<p:sp>/);
  assert.match(slide.text, /<a:t>Missing transport header &lt;proxy&gt;<\/a:t>/);
  assert.match(slide.text, /TRUE POSITIVE \(unverified\)/);
  assert.match(slide.text, /infra\/edge\.conf:19–21/);
  assert.match(slide.text, /proxy_pass http:\/\/app/);
  assert.match(slide.text, /Proposed fixed code/);
  assert.match(slide.text, /add_header Strict-Transport-Security/);
  assert.match(slide.text, /Browsers lack an HTTPS-only policy/);
  assert.ok(!entries(buffer).some(entry => /^ppt\/(?:media|embeddings)\/.+/.test(entry.name)));
  assert.ok(!entries(buffer).some(entry => entry.name.endsWith('/')));
});

test('PowerPoint export describes missing code and avoids copying credentials into the package', async () => {
  const buffer = await createFindingPptx({
    title: 'Reported issue', status: 'NOT TRIAGED',
    fixedCode: 'const api_key = \'fixture-value-never-copy\';\nAuthorization: Bearer fixture-authorization-never-copy',
    impact: 'Potential impact reported\0',
  });
  const parts = readMatching(buffer, /\.(?:xml|rels)$/).map(part => part.text).join('\n');
  assert.match(parts, /NOT TRIAGED/);
  assert.match(parts, /does not include a source excerpt/);
  assert.match(parts, /\[REDACTED\]/);
  assert.doesNotMatch(parts, /fixture-value-never-copy|fixture-authorization-never-copy|TargetMode="External"|\0/);

  const fallback = await createFindingPptx({ remediation: 'Check the applied edge configuration.' });
  const [slide] = readMatching(fallback, /^ppt\/slides\/slide\d+\.xml$/);
  assert.match(slide.text, /Check the applied edge configuration/);
  assert.doesNotMatch(slide.text, /Proposed fixed code/);
});
