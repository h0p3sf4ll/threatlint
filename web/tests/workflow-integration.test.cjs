'use strict';
process.env.THREATLINT_HOME = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'threatlint-home-'));
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createPipeline, runModel } = require('../lib/pipeline.cjs');
const { createStore } = require('../lib/store.cjs');
const { createReportWriter } = require('../lib/report-writer.cjs');
const { createDesignInputs } = require('../lib/design-inputs.cjs');
const { createScanImports } = require('../lib/scan-import.cjs');
const { convertToWord } = require('./helpers/docx.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => { let resolve; const promise = new Promise(yes => { resolve = yes; }); return { promise, resolve }; };
const settings = { provider: 'lmstudio', model: 'fixture' };
const A = 'appsec-code-reviewer', B = 'appsec-auth-reviewer', C = 'appsec-security-test-planner';

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-workflow-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const store = createStore(root), sessionId = store.create(root);
  const reports = createReportWriter(store, { convertToWord });
  return { root, store, reports, sessionId };
}

test('pipeline overlaps independent reviewers and saves declared provenance with deterministic upstream evidence', async t => {
  const { store, reports, sessionId } = fixture(t), designInputs = createDesignInputs();
  store.sessions.get(sessionId).provenance = { provider: 'github', repository: 'fixture/repo', branch: 'main', commit: 'a'.repeat(40) };
  const bundle = await designInputs.create([{ name: 'design.md', content: Buffer.from('Synthetic design context') }]);
  const gates = new Map([[A, deferred()], [B, deferred()]]), seen = [], events = [];
  const pipeline = createPipeline({ sessions: store.sessions, reports, designInputs, override: async args => {
    seen.push(args);
    if (gates.has(args.agentId)) await gates.get(args.agentId).promise;
    return `# ${args.agentId}\nNo material findings.\n`;
  } });
  const pending = pipeline.run({ sessionId, agentIds: [A, B, C], ...settings, designInputsId: bundle.id }, event => events.push(event), new AbortController());
  await tick(); assert.deepEqual(seen.map(args => args.agentId), [A, B]);
  assert.ok(seen.slice(0, 2).every(args => !args.userMessage.includes('PREVIOUS AGENT EVIDENCE')));
  gates.get(B).resolve(); await tick(); gates.get(A).resolve();
  assert.equal(await pending, 'complete');
  const consumer = seen.find(args => args.agentId === C).userMessage;
  assert.ok(consumer.indexOf(`(${A};`) < consumer.indexOf(`(${B};`));
  assert.match(consumer, /Synthetic design context/);
  assert.match(consumer, /SELECTED SOURCE PROVENANCE/);
  const final = store.sessions.get(sessionId).reports.find(report => report.agentId === C);
  assert.deepEqual(final.source.execution.dependsOn, [A, B]);
  assert.deepEqual(final.source.upstreamReports.map(report => report.agentId), [A, B]);
  assert.equal(final.source.repository.commit, 'a'.repeat(40));
  assert.match(final.source.designInputs.files[0].sha256, /^[a-f0-9]{64}$/);
  assert.equal(final.source.designInputs.files[0].text, undefined);
  assert.equal(events.find(event => event.type === 'pipeline_start').execution.mode, 'auto');
});

test('invalid dependencies and missing design storage fail before any model run', async t => {
  const { store, reports, sessionId } = fixture(t);
  const pipeline = createPipeline({ sessions: store.sessions, reports, override: () => assert.fail('must not call model') });
  const run = extra => pipeline.run({ sessionId, agentIds: [A, B], ...settings, ...extra }, () => {}, new AbortController());
  await assert.rejects(run({ designInputsId: 'requested' }), /upload them again/);
  await assert.rejects(run({ execution: { dependencies: { [A]: [B], [B]: [A] } } }), /cycle/);
  assert.equal(store.sessions.get(sessionId).reports.length, 0);
});

test('findings triage consumes an earlier threat model even without an attached scanner file', async t => {
  const { store, reports, sessionId } = fixture(t), seen = [], gate = deferred();
  const modeler = 'appsec-threat-modeler', triage = 'appsec-fp-reviewer';
  const pipeline = createPipeline({ sessions: store.sessions, reports, integrations: { semgrepVersion: async () => 'fixture' }, override: async args => {
    seen.push(args);
    if (args.agentId === modeler) await gate.promise;
    return `# ${args.agentId}\nNo material findings.\n`;
  } });
  const pending = pipeline.run({ sessionId, agentIds: [modeler, triage], ...settings }, () => {}, new AbortController());
  await tick(); assert.deepEqual(seen.map(args => args.agentId), [modeler]); gate.resolve();
  assert.equal(await pending, 'complete');
  assert.match(seen[1].userMessage, /PREVIOUS AGENT EVIDENCE \(appsec-threat-modeler;/);
});

test('shared model admission limits unrelated runs and cancels queued requests', async () => {
  const gate = deferred(), observed = [], controllers = Array.from({ length: 5 }, () => new AbortController());
  const requests = controllers.map((controller, index) => runModel({ settings, signal: controller.signal, override: async () => { observed.push(index); await gate.promise; return index; } }));
  const cancelled = assert.rejects(requests[4], /Cancelled/);
  await tick(); assert.deepEqual(observed, [0, 1, 2, 3]);
  controllers[4].abort(); gate.resolve();
  await cancelled; assert.deepEqual(await Promise.all(requests.slice(0, 4)), [0, 1, 2, 3]);
  assert.deepEqual(observed, [0, 1, 2, 3]);
});

test('independent scan imports overlap, drain on shutdown and never save cancelled analysis', async t => {
  const { store, reports } = fixture(t), entered = [], cancelled = [];
  const imports = createScanImports({ store, reports, override: args => new Promise((_resolve, reject) => {
    entered.push(args);
    args.signal.addEventListener('abort', () => { cancelled.push(args); reject(new Error('Cancelled')); }, { once: true });
  }) });
  const content = fs.readFileSync(path.join(__dirname, 'fixtures/scan-import/invicti.xml'));
  const first = await imports.create({ filename: 'first.xml', content, fields: settings });
  const second = await imports.create({ filename: 'second.xml', content, fields: settings });
  await tick(); assert.equal(entered.length, 2);
  await imports.close();
  assert.equal(cancelled.length, 2);
  assert.equal(imports.get(first.job.id).status, 'error');
  assert.equal(imports.get(second.job.id).status, 'error');
  assert.ok([...store.sessions.values()].every(session => !session.reports.length));
  await assert.rejects(imports.create({ filename: 'late.xml', content }), /shutting down/);
});
