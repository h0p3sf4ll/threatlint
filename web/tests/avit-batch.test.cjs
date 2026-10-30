'use strict';
process.env.THREATLINT_HOME = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'threatlint-home-'));
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { WebSocket } = require('ws');
const { createWorkbench } = require('../server.js');
const { redactSecrets, resolveOutcome, parseBatchInput, planBatch, terminalResult, outcomeActions } = require('../lib/avit-batch.cjs');

// Deterministic Word export.
const stubDir = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-docx-'));
const stub = path.join(stubDir, process.platform === 'win32' ? 'docx.cmd' : 'docx');
fs.writeFileSync(stub, process.platform === 'win32' ? '@echo PK-docx> %3\r\n' : '#!/bin/sh\nprintf PK-docx > "$3"\n', { mode: 0o755 });
// Node will not execFile a .cmd (CVE-2024-27980), so Windows converts with the real python-docx instead.
if (process.platform !== 'win32') process.env.THREATLINT_PYTHON = stub;

const FP = 'AVIT000000000000001', TP = 'AVIT000000000000002', OUT = 'AVIT000000000000003';
let storage;
const SECRET = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
const report = (avit, disposition) => `# FP Review\n\n#### [FP-001] — finding\n**Original finding**: ${avit}; rule.x.y; Semgrep Code; app.yaml:2\n**Disposition**: ${disposition}\n**Severity**: INFO\n**Confidence**: CONFIRMED\n**Evidence**: app.yaml:2 — value ${SECRET}\nBlast radius: one rule. Acceptance criteria: x. Proposed fix: y.\n`;

describe('False positive review batch', () => {
  let wb, base;
  const calls = [];
  let adoMissing = false;
  const taskAvits = {};
  before(async () => {
    const threatlintCli = async args => {
      calls.push(args);
      if (args[0] === 'setup') return { code: 0, stdout: JSON.stringify([{ name: 'ServiceNow OAuth client', configured: true }, { name: 'Azure DevOps PAT', configured: !adoMissing, fix: 'threatlint ado login --organization <org>' }, { name: 'Semgrep API token', configured: true }]), stderr: '' };
      if (args[0] === 'sctask' && args[1] === 'avits') {
        if (taskAvits[args[2]] === null) return { code: 1, stdout: '', stderr: `ERROR: ${args[2]} was not found` };
        const avits = taskAvits[args[2]] || [FP, TP];
        return { code: avits.length ? 0 : 1, stdout: `${avits.join('\n')}\n${JSON.stringify({ sctask: args[2], avits })}\n`, stderr: '' };
      }
      if (args[0] === 'sctask' && args[1] === 'close') return { code: 0, stdout: `  ✓ Attached x\n  ✓ Closed ${args[2]}\n`, stderr: '' };
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
  it('expands an SCTASK into its AVITs, reviews each, then closes the task', async () => {
    calls.length = 0;
    const socket = new WebSocket(base.replace('http:', 'ws:'), { origin: base });
    await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
    const events = await new Promise(resolve => {
      const seen = [];
      socket.on('message', raw => { const event = JSON.parse(raw); seen.push(event); if (event.type === 'avit_batch_complete' || event.type === 'avit_batch_error') resolve(seen); });
      socket.send(JSON.stringify({ action: 'run_avit_batch', avits: 'SCTASK14120565', provider: 'lmstudio', model: 'fixture' }));
    });
    socket.close();
    assert.deepEqual(calls.filter(args => args[1] === 'resolve').map(args => args[2]), [FP, TP], 'each AVIT in the task is resolved');
    const order = calls.map(args => args.slice(0, 2).join(' '));
    assert.ok(order.lastIndexOf('avit resolve') < order.indexOf('sctask close'), 'the task is closed after its AVITs');
    const done = events.filter(event => event.type === 'sctask_item' && event.done).pop();
    assert.equal(done.stage, 'done'); assert.match(done.detail, /Closed/);
  });
  const runBatch = async avits => {
    const socket = new WebSocket(base.replace('http:', 'ws:'), { origin: base });
    await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
    const events = await new Promise(resolve => {
      const seen = [];
      socket.on('message', raw => { const event = JSON.parse(raw); seen.push(event); if (event.type === 'avit_batch_complete' || event.type === 'avit_batch_error') resolve(seen); });
      socket.send(JSON.stringify({ action: 'run_avit_batch', avits, provider: 'lmstudio', model: 'fixture' }));
    });
    socket.close();
    return events;
  };
  it('expands several SCTASKs, deduplicates their AVITs, closes each after its own AVITs, and survives a failing task', async () => {
    calls.length = 0;
    const A = 'SCTASK1000001', B = 'SCTASK1000002', BAD = 'SCTASK1000003';
    Object.assign(taskAvits, { [A]: [FP], [B]: [FP, TP], [BAD]: null });
    const events = await runBatch(`${A}, ${BAD}; ${B}\n${TP}`);
    const order = calls.filter(args => args[0] === 'sctask' || args[1] === 'resolve').map(args => `${args[1]} ${args[2]}`);
    assert.deepEqual(order, [`avits ${A}`, `avits ${BAD}`, `avits ${B}`, `resolve ${FP}`, `close ${A}`, `resolve ${TP}`, `close ${B}`],
      'every task is read, each AVIT is reviewed once, and each task is closed right after its own AVITs');
    const start = events.find(event => event.type === 'avit_batch_start');
    assert.deepEqual(start.avits, [FP, TP]); assert.deepEqual(start.sctasks, [A, B]); assert.equal(start.truncated, null);
    const final = Object.fromEntries(events.filter(event => event.type === 'sctask_item' && event.done).map(event => [event.sctask, event]));
    assert.equal(final[BAD].stage, 'error'); assert.match(final[BAD].detail, /not found/); assert.equal(final[BAD].result, 'error');
    assert.equal(final[A].result, 'closed'); assert.equal(final[B].result, 'closed');
    assert.deepEqual(events.find(event => event.sctask === B && event.avits).shared, [FP], 'the AVIT shared with an earlier task is reported as reviewed once');
    assert.ok(events.every(event => typeof event.at === 'string' && !Number.isNaN(Date.parse(event.at))), 'every event is timestamped');
    const fp = events.filter(event => event.avit === FP && !event.tool).map(event => event.action || event.stage);
    assert.deepEqual(fp, ['fetching', 'checkout', 'triage', 'reported', 'resolving', 'attached', 'closed', 'semgrep-ignored', 'done'], 'each step and ServiceNow action is its own event');
    assert.equal(events.filter(event => event.type === 'avit_item' && event.done).find(event => event.avit === TP).result, 'noted');
    for (const key of Object.keys(taskAvits)) delete taskAvits[key];
  });
  it('reports the AVITs over the batch limit as skipped instead of dropping them', async () => {
    calls.length = 0;
    const many = Array.from({ length: 52 }, (_, index) => `AVIT${String(9000000 + index)}`);
    taskAvits.SCTASK2000001 = many;
    const events = await runBatch(`${FP} SCTASK2000001`);
    const start = events.find(event => event.type === 'avit_batch_start');
    assert.equal(start.avits.length, 53); assert.deepEqual(start.truncated, { total: 53, reviewed: 50, skipped: many.slice(49) });
    const skipped = events.filter(event => event.type === 'avit_item' && event.stage === 'skipped');
    assert.deepEqual(skipped.map(event => event.avit), many.slice(49)); assert.ok(skipped.every(event => event.done && event.result === 'skipped'));
    assert.equal(calls.filter(args => args[1] === 'fetch').length, 50, 'only the first 50 are reviewed');
    assert.match(events.find(event => event.sctask && event.avits).detail, /3 over the 50-AVIT limit/);
    delete taskAvits.SCTASK2000001;
  });
  it('parses mixed AVIT/SCTASK lists and plans a deduplicated batch', () => {
    const parsed = parseBatchInput(' sctask1000001, AVIT0000001;AVIT0000002\n\nSCTASK1000002\tavit0000001 SCTASK1000001 ');
    assert.deepEqual(parsed.sctasks, ['SCTASK1000001', 'SCTASK1000002']);
    assert.deepEqual(parsed.avits, ['AVIT0000001', 'AVIT0000002']);
    assert.deepEqual(parsed.order, ['SCTASK1000001', 'AVIT0000001', 'AVIT0000002', 'SCTASK1000002']);
    assert.throws(() => parseBatchInput('AVIT0000001, INC0001234'), /Not an AVIT or SCTASK number: INC0001234/);
    assert.throws(() => parseBatchInput(' ,; '), /at least one/);
    const plan = planBatch(parsed.order, { SCTASK1000001: ['AVIT0000009', 'AVIT0000001'], SCTASK1000002: ['AVIT0000002', 'AVIT0000008'] }, 3);
    assert.deepEqual(plan.all, ['AVIT0000009', 'AVIT0000001', 'AVIT0000002', 'AVIT0000008']);
    assert.deepEqual(plan.shared, { SCTASK1000002: ['AVIT0000002'] });
    assert.deepEqual(plan.kept, ['AVIT0000009', 'AVIT0000001', 'AVIT0000002']); assert.deepEqual(plan.skipped, ['AVIT0000008']);
    assert.equal(terminalResult('done', { outcome: { closed: true } }), 'closed');
    assert.equal(terminalResult('done', { outcome: { leftOpen: true } }), 'noted');
    assert.equal(terminalResult('out-of-scope'), 'skipped'); assert.equal(terminalResult('error'), 'error');
    assert.deepEqual(outcomeActions({ attached: true, closed: true, semgrep: ['✓ Published org-private rule x.tuned'] }, 'FALSE POSITIVE').map(item => item.kind), ['attached', 'closed', 'tuned']);
  });
  it('refuses to start until every required credential is configured', async () => {
    adoMissing = true;
    const socket = new WebSocket(base.replace('http:', 'ws:'), { origin: base });
    await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
    const event = await new Promise(resolve => {
      socket.on('message', raw => { const value = JSON.parse(raw); if (value.type === 'avit_batch_error' || value.type === 'avit_batch_start') resolve(value); });
      socket.send(JSON.stringify({ action: 'run_avit_batch', avits: FP, provider: 'lmstudio', model: 'fixture' }));
    });
    socket.close(); adoMissing = false;
    assert.equal(event.type, 'avit_batch_error'); assert.match(event.message, /Azure DevOps PAT \(threatlint ado login/);
  });
  it('redacts credential-like values from the flagged file and parses resolve output', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-red-'));
    fs.writeFileSync(path.join(dir, 'f.yaml'), `KEY: ${SECRET}\npath: some/dir/with-digits-123456789\n`);
    const { markdown, count } = redactSecrets(`value ${SECRET} and some/dir/with-digits-123456789`, dir, 'f.yaml');
    assert.equal(count, 1); assert.ok(!markdown.includes(SECRET)); assert.ok(markdown.includes('some/dir/with-digits-123456789'));
    assert.deepEqual(resolveOutcome('  ✓ Attached a\n  ! ServiceNow kept state 3 / \n').closed, 'state not applied');
  });
});
