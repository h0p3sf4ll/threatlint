'use strict';
process.env.THREATLINT_HOME = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'threatlint-home-'));
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { WebSocket } = require('ws');
const { createWorkbench } = require('../server.js');
const { redactSecrets, resolveOutcome } = require('../lib/avit-batch.cjs');

// Deterministic Word export.
const stubDir = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-docx-'));
const stub = path.join(stubDir, process.platform === 'win32' ? 'docx.cmd' : 'docx');
fs.writeFileSync(stub, process.platform === 'win32' ? '@echo PK-docx> %3\r\n' : '#!/bin/sh\nprintf PK-docx > "$3"\n', { mode: 0o755 });
process.env.THREATLINT_PYTHON = stub;

const FP = 'AVIT000000000000001', TP = 'AVIT000000000000002', OUT = 'AVIT000000000000003';
let storage;
const SECRET = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
const report = (avit, disposition) => `# FP Review\n\n#### [FP-001] — finding\n**Original finding**: ${avit}; rule.x.y; Semgrep Code; app.yaml:2\n**Disposition**: ${disposition}\n**Severity**: INFO\n**Confidence**: CONFIRMED\n**Evidence**: app.yaml:2 — value ${SECRET}\nBlast radius: one rule. Acceptance criteria: x. Proposed fix: y.\n`;

describe('False positive review batch', () => {
  let wb, base;
  const calls = [];
  before(async () => {
    const threatlintCli = async args => {
      calls.push(args);
      const [, command, avit] = args;
      if (command === 'fetch') {
        if (avit === OUT) return { code: 1, stdout: '', stderr: `ERROR: None of the requested AVITs are in the AVR CodeSecurity view (${OUT}).` };
        fs.writeFileSync(args[args.indexOf('-o') + 1], `## ${avit}\n`); return { code: 0, stdout: '✓', stderr: '' };
      }
      if (command === 'checkout') {
        const dir = args[args.indexOf('--dir') + 1];
        fs.mkdirSync(path.join(dir, '.git'), { recursive: true }); fs.writeFileSync(path.join(dir, 'app.yaml'), `name: svc\nAPI_KEY: "${SECRET}"\n`);
        return { code: 0, stdout: `✓ Checked out\n${JSON.stringify({ kind: 'secrets', name: 'svc', branch: 'main', file_path: 'app.yaml' })}\n`, stderr: '' };
      }
      if (command === 'resolve') {
        const md = fs.readFileSync(args[args.indexOf('--report') + 1], 'utf8');
        assert.ok(!md.includes(SECRET), 'the secret is redacted before the report is saved or uploaded');
        assert.ok(fs.existsSync(args[args.indexOf('--docx') + 1]));
        return avit === FP ? { code: 0, stdout: '  ✓ Attached x.docx\n  ✓ Closed as false positive\n  ✓ Semgrep ignored 1 finding(s)\n', stderr: '' }
          : { code: 0, stdout: '  ✓ Attached x.docx\n  ✓ Work note added; AVIT left open\n', stderr: '' };
      }
      throw new Error(`unexpected ${args.join(' ')}`);
    };
    storage = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-store-'));
    wb = createWorkbench({ storageDir: storage,
      runProvider: async args => { const avit = /servicenow-(AVIT\d+)/.exec(args.userMessage)[1]; const text = report(avit, avit === FP ? 'FALSE POSITIVE' : 'TRUE POSITIVE'); args.onEvent({ type: 'text_chunk', text }); return text; },
      integrations: { semgrepVersion: async () => '1.107.0', threatlintCli } });
    await new Promise(resolve => wb.server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${wb.server.address().port}`;
  });
  after(() => wb.close());

  it('reviews, reports, and resolves each AVIT individually', async () => {
    const socket = new WebSocket(base.replace('http:', 'ws:'), { origin: base });
    await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
    const events = await new Promise(resolve => {
      const seen = [];
      socket.on('message', raw => { const event = JSON.parse(raw); seen.push(event); if (event.type === 'avit_batch_complete' || event.type === 'avit_batch_error') resolve(seen); });
      socket.send(JSON.stringify({ action: 'run_avit_batch', avits: `${FP}\n${TP}, ${OUT}`, provider: 'lmstudio', model: 'fixture' }));
    });
    socket.close();
    const final = Object.fromEntries(events.filter(event => event.type === 'avit_item' && event.done).map(event => [event.avit, event]));
    assert.equal(final[FP].stage, 'done'); assert.equal(final[FP].disposition, 'FALSE POSITIVE'); assert.equal(final[FP].outcome.closed, true);
    assert.equal(final[TP].stage, 'done'); assert.equal(final[TP].outcome.leftOpen, true);
    assert.equal(final[OUT].stage, 'out-of-scope');
    assert.equal(final[FP].report, undefined, 'no local report is offered');
    const reportDirs = calls.filter(args => args[1] === 'resolve').map(args => args[args.indexOf('--report') + 1]);
    assert.equal(new Set(reportDirs).size, 2, 'one report per AVIT');
    for (const file of reportDirs) assert.ok(!fs.existsSync(file), 'reports are not kept locally');
    assert.deepEqual(calls.filter(args => args[1] === 'resolve').map(args => args[2]), [FP, TP], 'one closure per AVIT, in order');
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(storage, 'sessions.json'), 'utf8')), [], 'no report history kept');
    for (const args of calls.filter(item => item[1] === 'checkout')) assert.ok(!fs.existsSync(args[args.indexOf('--dir') + 1]), 'checkouts are deleted');
  });
  it('redacts credential-like values from the flagged file and parses resolve output', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-red-'));
    fs.writeFileSync(path.join(dir, 'f.yaml'), `KEY: ${SECRET}\npath: some/dir/with-digits-123456789\n`);
    const { markdown, count } = redactSecrets(`value ${SECRET} and some/dir/with-digits-123456789`, dir, 'f.yaml');
    assert.equal(count, 1); assert.ok(!markdown.includes(SECRET)); assert.ok(markdown.includes('some/dir/with-digits-123456789'));
    assert.deepEqual(resolveOutcome('  ✓ Attached a\n  ! ServiceNow kept state 3 / \n').closed, 'state not applied');
  });
});
