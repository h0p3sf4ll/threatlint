'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createStore } = require('../lib/store.cjs');
const { createReportWriter } = require('../lib/report-writer.cjs');
const { convertToWord } = require('./helpers/docx.cjs');

function fixture(t, converter) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-writer-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const store = createStore(directory);
  return { writer: createReportWriter(store, { convertToWord: converter }), sessionId: store.create(directory) };
}

describe('Report conversion boundary', () => {
  const markdown = '# Review — synthetic fixture\nNo material findings.\n';

  it('reserves unique paths before concurrent same-agent conversions yield', async t => {
    const gates = [];
    const { writer, sessionId } = fixture(t, (mdPath, docxPath) => new Promise(resolve => {
      gates.push(() => { fs.writeFileSync(docxPath, fs.readFileSync(mdPath)); resolve(); });
    }));
    t.mock.method(Date, 'now', () => 123456789);
    const first = writer.save('appsec-fp-reviewer', '# First\nNo material findings.', sessionId);
    const second = writer.save('appsec-fp-reviewer', '# Second\nNo material findings.', sessionId);
    assert.equal(gates.length, 2);
    gates[1](); gates[0]();
    const [a, b] = await Promise.all([first, second]);
    assert.notEqual(a.mdPath, b.mdPath); assert.notEqual(a.docxPath, b.docxPath);
    assert.match(fs.readFileSync(a.mdPath, 'utf8'), /First/);
    assert.match(fs.readFileSync(b.mdPath, 'utf8'), /Second/);
  });

  it('uses the injected converter without a shell or Python dependency', async t => {
    const calls = [];
    const { writer, sessionId } = fixture(t, async (...args) => { calls.push(args); await convertToWord(...args); });
    const report = await writer.save('appsec-code-reviewer', markdown, sessionId);
    assert.deepEqual(calls, [[report.mdPath, report.docxPath]]);
    assert.equal(fs.readFileSync(report.mdPath, 'utf8'), markdown);
    assert.equal(fs.readFileSync(report.docxPath, 'utf8'), 'PK-docx');
    assert.equal(writer.metadata(report).hasDocx, true);
    assert.equal(report.conversionNote, null);
  });

  it('preserves Markdown and reports unavailable Word conversion', async t => {
    const { writer, sessionId } = fixture(t, async () => { throw new Error('Synthetic conversion failure'); });
    const report = await writer.save('appsec-code-reviewer', markdown, sessionId);
    assert.equal(fs.readFileSync(report.mdPath, 'utf8'), markdown);
    assert.equal(report.docxPath, null);
    assert.equal(writer.metadata(report).docxUrl, null);
    assert.match(report.conversionNote, /Word export unavailable/);
  });

  it('does not advertise a Word file the converter failed to create', async t => {
    const { writer, sessionId } = fixture(t, async () => {});
    const report = await writer.save('appsec-code-reviewer', markdown, sessionId);
    assert.equal(report.docxPath, null);
    assert.equal(writer.metadata(report).hasDocx, false);
    assert.match(report.conversionNote, /Word export unavailable/);
  });
});
