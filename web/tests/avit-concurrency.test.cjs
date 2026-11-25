'use strict';
const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const WebSocket = require('ws');

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-parallel-home-'));
const environmentNames = ['THREATLINT_HOME', 'THREATLINT_SNOW_INSTANCE', 'THREATLINT_SNOW_CLIENT_ID', 'THREATLINT_SNOW_CLIENT_SECRET', 'THREATLINT_BATCH_CONCURRENCY', 'THREATLINT_MODEL_CONCURRENCY'];
const previousEnvironment = Object.fromEntries(environmentNames.map(name => [name, process.env[name]]));
process.env.THREATLINT_HOME = home;
for (const name of environmentNames.slice(1, 4)) delete process.env[name];
process.env.THREATLINT_BATCH_CONCURRENCY = '3';
process.env.THREATLINT_MODEL_CONCURRENCY = '8';
after(() => {
  for (const name of environmentNames) { if (previousEnvironment[name] === undefined) delete process.env[name]; else process.env[name] = previousEnvironment[name]; }
  fs.rmSync(home, { recursive: true, force: true });
});

const { createAvitBatch, avitExecution } = require('../lib/avit-batch.cjs');
const { createAvitRuns } = require('../lib/avit-runs.cjs');
const { createStore } = require('../lib/store.cjs');
const { createReportWriter } = require('../lib/report-writer.cjs');
const avit = index => 'AVIT' + String(1000000 + index);
const review = id => `# Finding Review\n\n## [FP-001] Synthetic finding\n**Original finding**: ${id}; fixture; code; file.js:1\n**Disposition**: TRUE POSITIVE\n**Severity**: HIGH\n**Confidence**: CONFIRMED\n**Evidence**: file.js:1 uses the unchecked value.\n**Proposed fix**: Validate the value.\n`;
const abortError = () => Object.assign(new Error('Cancelled'), { name: 'AbortError' });
async function bounded(promise) {
  let timer;
  try { return await Promise.race([promise, new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error('Fixture barrier did not complete')), 5000); })]); }
  finally { clearTimeout(timer); }
}
function abortable(promise, signal) {
  if (signal.aborted) return Promise.reject(abortError());
  return new Promise((resolve, reject) => {
    const abort = () => { signal.removeEventListener('abort', abort); reject(abortError()); };
    signal.addEventListener('abort', abort, { once: true });
    promise.then(value => { signal.removeEventListener('abort', abort); resolve(value); }, error => { signal.removeEventListener('abort', abort); reject(error); });
  });
}
function fixture(t, hooks = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-parallel-'));
  const store = createStore(directory), reports = createReportWriter(store, { convertToWord: async (_md, docx) => { await Promise.resolve(); fs.writeFileSync(docx, 'Synthetic Word artifact'); } });
  const events = [], calls = [], models = [], removals = [], held = [], pending = [], waiters = [];
  const context = {
    directory, store, reports, events, calls, models, removals,
    gate() { let release; const promise = new Promise(resolve => { release = resolve; }); held.push(release); return { promise, release }; },
    send(event) { events.push(event); for (const waiter of [...waiters]) if (waiter.predicate(event)) { waiters.splice(waiters.indexOf(waiter), 1); waiter.resolve(event); } },
    event(predicate) { const found = events.find(predicate); if (found) return Promise.resolve(found); return bounded(new Promise(resolve => waiters.push({ predicate, resolve }))); },
  };
  const threatlintCli = async (args, options = {}) => {
    calls.push({ args, options });
    if (hooks.cli) { const result = await hooks.cli(args, options, context); if (result !== undefined) return result; }
    const [kind, command, id] = args;
    if (kind === 'setup') return { code: 0, stdout: '[]', stderr: '' };
    if (['sctask', 'isst'].includes(kind) && command === 'avits') return { code: 0, stdout: JSON.stringify({ avits: hooks.groups[id] }), stderr: '' };
    if (command === 'fetch') { fs.writeFileSync(args[args.indexOf('-o') + 1], `## ${id}\n`); return { code: 0, stdout: '', stderr: '' }; }
    if (command === 'checkout') {
      if (id === hooks.removed) return { code: 1, stdout: '', stderr: 'ERROR: repository fixture was not found' };
      const repo = args[args.indexOf('--dir') + 1]; fs.mkdirSync(repo, { recursive: true }); fs.writeFileSync(path.join(repo, 'file.js'), 'fixture source\n');
      return { code: 0, stdout: JSON.stringify({ kind: 'sca', name: 'fixture', branch: 'main', ...(hooks.fixPr ? { scm: 'github', organization: 'fixture' } : {}) }), stderr: '' };
    }
    if (command === 'prepare-fix') return { code: 0, stdout: JSON.stringify({ status: 'ready', issues: [] }), stderr: '' };
    if (['resolve', 'fix-pr', 'close-removed', 'close', 'summarize'].includes(command)) {
      context.writeActive = (context.writeActive || 0) + 1; context.maxWriteActive = Math.max(context.maxWriteActive || 0, context.writeActive);
      assert.equal(options.signal, undefined, 'an admitted update finishes without an abort signal');
      try {
        if (command === 'resolve') {
          const report = args[args.indexOf('--report') + 1], markdown = fs.readFileSync(report, 'utf8');
          assert.ok(markdown.includes(id)); assert.deepEqual([...new Set(markdown.match(/AVIT\d+/g))], [id]);
          assert.ok(fs.existsSync(args[args.indexOf('--docx') + 1]));
        }
        if (hooks.write) await hooks.write(args, context);
        if (command === 'fix-pr') return { code: 0, stdout: JSON.stringify({ status: 'created', url: 'https://github.com/fixture/repo/pull/1' }), stderr: '' };
        return { code: 0, stdout: command === 'resolve' ? '  ✓ Attached report.docx\n  ✓ Work note added; AVIT left open\n' : command === 'close' ? `  ✓ Closed ${id}\n` : 'Completed\n', stderr: '' };
      } finally { context.writeActive--; }
    }
    throw new Error('Unexpected fixture command');
  };
  const override = async args => {
    const id = /servicenow-(AVIT\d+)\.md/.exec(args.userMessage)[1]; models.push({ id, args });
    context.modelActive = (context.modelActive || 0) + 1; context.maxModelActive = Math.max(context.maxModelActive || 0, context.modelActive);
    try { if (hooks.model) await hooks.model(id, args, context); return review(id); }
    finally { context.modelActive--; }
  };
  const integrations = { threatlintCli, semgrepVersion: async () => '1.186.0', removeAvitTemporaryDirectory: async (work, options) => {
    removals.push(work); if (hooks.cleanup) await hooks.cleanup(work, context); await fs.promises.rm(work, options);
  } };
  const stale = hooks.pendingCleanup ? fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-avit-')) : null;
  if (stale) fs.writeFileSync(path.join(directory, 'pending-avit-cleanup.json'), JSON.stringify([stale]));
  const batch = createAvitBatch({ store, reports, override, integrations });
  Object.assign(context, { batch, integrations, override, message: { provider: 'lmstudio', model: 'fixture', createFixPr: !!hooks.fixPr,
    servicenow: { instance: 'https://fixture.service-now.com', clientId: 'synthetic-client', clientSecret: 'synthetic-secret' } },
    run(ids, options = {}, controller = new AbortController()) { const promise = batch.run({ ...context.message, avits: ids.join(' '), ...options }, context.send, controller); pending.push(promise); return promise; } });
  t.after(async () => { for (const release of held) release(); await Promise.allSettled(pending); if (stale) fs.rmSync(stale, { recursive: true, force: true }); fs.rmSync(directory, { recursive: true, force: true }); });
  return context;
}

test('default three reviews overlap, later results do not wait for the first, and report/checkouts stay isolated', async t => {
  const ids = Array.from({ length: 5 }, (_, index) => avit(index + 1)); let started;
  const startedPromise = new Promise(resolve => { started = resolve; }), gates = new Map();
  const f = fixture(t, { model: async (id, args, context) => { if (context.models.length === 3) started(); await abortable(gates.get(id).promise, args.signal); } });
  for (const id of ids) gates.set(id, f.gate());
  const running = f.run(ids); await bounded(startedPromise);
  assert.equal(f.modelActive, 3); assert.equal(f.calls.some(call => call.args[1] === 'resolve'), false);
  assert.deepEqual(new Set(f.models.map(row => row.id)), new Set(ids.slice(0, 3)));
  gates.get(ids[1]).release(); await f.event(event => event.avit === ids[1] && event.done);
  await f.event(event => event.avit === ids[3] && event.stage === 'triage');
  assert.equal(f.events.some(event => event.avit === ids[0] && event.done), false);
  for (const gate of gates.values()) gate.release(); await running;
  assert.equal(f.maxModelActive, 3); assert.equal(f.maxWriteActive, 1);
  assert.deepEqual(f.events.find(event => event.type === 'avit_batch_start').execution, { mode: 'auto', maxConcurrency: 3 });
  assert.equal(f.events.filter(event => event.type === 'avit_item' && event.done).length, 5);
  const reports = f.calls.filter(call => call.args[1] === 'resolve').map(call => call.args[call.args.indexOf('--report') + 1]);
  assert.equal(new Set(reports).size, 5); assert.equal(new Set(f.models.map(row => row.args.repoPath)).size, 5);
  assert.equal(f.store.sessions.size, 0); for (const report of reports) assert.equal(fs.existsSync(report), false);
  for (const work of f.removals) assert.equal(fs.existsSync(work), false);
  assert.equal(f.events.at(-1).type, 'avit_batch_complete');
});

test('explicit sequential mode admits one finding and the configured maximum admits eight, never nine', async t => {
  let first;
  const firstStarted = new Promise(resolve => { first = resolve; });
  const sequential = fixture(t, { model: async (id, args) => { if (id === avit(1)) { first(); await abortable(gate.promise, args.signal); } } }), gate = sequential.gate();
  const pending = sequential.run([avit(1), avit(2)], { execution: { mode: 'sequential', maxConcurrency: 8 } }); await bounded(firstStarted);
  assert.equal(sequential.calls.filter(call => call.args[1] === 'fetch').length, 1); gate.release(); await pending; assert.equal(sequential.maxModelActive, 1);
  let eight;
  const eightStarted = new Promise(resolve => { eight = resolve; }); const parallel = fixture(t, { cli: async (args, options, context) => {
    if (args[1] === 'fetch') { if (context.calls.filter(call => call.args[1] === 'fetch').length === 8) eight(); await abortable(fetchGate.promise, options.signal); }
  } }), fetchGate = parallel.gate();
  const all = parallel.run(Array.from({ length: 9 }, (_, index) => avit(index + 1)), { execution: { maxConcurrency: 8 } }); await bounded(eightStarted);
  assert.equal(parallel.calls.filter(call => call.args[1] === 'fetch').length, 8); fetchGate.release(); await all;
  assert.equal(parallel.events.filter(event => event.done && event.avit).length, 9);
});

test('all external updates use one lane, including fix PRs, removed repositories and shared group finalization', async t => {
  const ids = [avit(1), avit(2), avit(3), avit(4)], A = 'SCTASK1000001', B = 'ISST1000001'; let entered;
  const enteredPromise = new Promise(resolve => { entered = resolve; }); let initial = true;
  const f = fixture(t, { groups: { [A]: [ids[0], ids[1]], [B]: [ids[1], ids[2]] }, removed: ids[3], fixPr: true, write: async (args, context) => {
    if (initial) { initial = false; entered(); await updateGate.promise; }
    if (['close', 'summarize'].includes(args[1])) for (const id of contextGroups[args[2]]) assert.ok(context.events.some(event => event.avit === id && event.done), 'group updates wait for all of their own final outcomes');
  } }), contextGroups = { [A]: [ids[0], ids[1]], [B]: [ids[1], ids[2]] }, updateGate = f.gate();
  const running = f.run([A, B, ids[3]], { execution: { maxConcurrency: 4 } }); await bounded(enteredPromise);
  assert.equal(f.writeActive, 1); assert.equal(f.calls.filter(call => ['resolve', 'close-removed'].includes(call.args[1])).length, 1);
  updateGate.release(); await running; assert.equal(f.maxWriteActive, 1);
  assert.equal(f.calls.filter(call => call.args[1] === 'fetch' && call.args[2] === ids[1]).length, 1);
  assert.equal(f.calls.filter(call => call.args[1] === 'close').length, 1); assert.equal(f.calls.filter(call => call.args[1] === 'summarize').length, 1);
  const writes = f.calls.filter(call => ['resolve', 'fix-pr', 'close-removed', 'close', 'summarize'].includes(call.args[1])).map(call => call.args);
  for (const id of ids.slice(0, 3)) { const index = writes.findIndex(args => args[1] === 'resolve' && args[2] === id); assert.equal(writes[index + 1][1], 'fix-pr'); assert.equal(writes[index + 1][2], id); }
});

test('a ready group completes without waiting for an unrelated slow finding', async t => {
  const group = 'SCTASK1000001'; const f = fixture(t, { groups: { [group]: [avit(1)] }, model: async (id, args) => { if (id === avit(2)) await abortable(slow.promise, args.signal); } }), slow = f.gate();
  const running = f.run([group, avit(2)]);
  await f.event(event => event.sctask === group && event.done); assert.equal(f.events.some(event => event.avit === avit(2) && event.done), false);
  slow.release(); await running; assert.equal(f.calls.filter(call => call.args[1] === 'close').length, 1);
});

test('Stop cancels queued updates and new reviews, but drains an admitted update and cleanup before completion', async t => {
  let writing, cleaning;
  const writingPromise = new Promise(resolve => { writing = resolve; }), cleaningPromise = new Promise(resolve => { cleaning = resolve; });
  const f = fixture(t, { model: async (id, args) => { if (id !== avit(1)) await abortable(modelsHeld.promise, args.signal); }, write: async () => { writing(); await writingHeld.promise; }, cleanup: async work => {
    if (f.models.find(row => row.id === avit(1))?.args.repoPath.startsWith(work + path.sep)) { cleaning(); await cleanupHeld.promise; }
  } }), modelsHeld = f.gate(), writingHeld = f.gate(), cleanupHeld = f.gate();
  const controller = new AbortController(); let settled = false;
  const running = f.run([avit(1), avit(2), avit(3), avit(4)], {}, controller).finally(() => { settled = true; });
  await bounded(writingPromise); modelsHeld.release(); await f.event(event => event.avit === avit(2) && event.stage === 'reported');
  controller.abort(); await Promise.resolve(); assert.equal(settled, false); assert.equal(f.calls.filter(call => call.args[1] === 'resolve').length, 1);
  writingHeld.release(); await bounded(cleaningPromise); assert.equal(settled, false); cleanupHeld.release(); await running;
  assert.equal(f.calls.filter(call => call.args[1] === 'fetch' && call.args[2] === avit(4)).length, 0);
  assert.equal(f.calls.filter(call => call.args[1] === 'resolve').length, 1); assert.equal(f.events.at(-1).cancelled, true);
  assert.ok(f.events.some(event => event.avit === avit(2) && event.stage === 'cancelled' && event.done));
});

test('one failed review or locked checkout cleanup does not stop independent findings', async t => {
  const f = fixture(t, { model: async id => { if (id === avit(1)) throw new Error('Synthetic model failure'); }, cleanup: async () => { throw new Error('Synthetic checkout lock'); } });
  await f.run([avit(1), avit(2), avit(3), avit(4)]);
  assert.equal(f.events.find(event => event.avit === avit(1) && event.done).stage, 'error');
  assert.equal(f.events.filter(event => event.stage === 'done' && event.avit).length, 3); assert.equal(f.events.at(-1).type, 'avit_batch_complete');
  assert.ok(f.events.some(event => event.action === 'cleanup-warning'));
  // The deliberately locked synthetic temp roots belong to this test, not user data.
  for (const directory of f.removals) fs.rmSync(directory, { recursive: true, force: true });
});

test('validation rejects unsupported budgets before cleanup or CLI work and AVIT counts have no implicit ceiling', async t => {
  const f = fixture(t, { pendingCleanup: true }); for (const execution of [{ maxConcurrency: 0 }, { maxConcurrency: 9 }, { maxModelRuns: 64 }, { plannedModelRuns: 0 }]) {
    await assert.rejects(f.run([avit(1)], { execution }), /Concurrency|budgets/);
  }
  assert.equal(f.calls.length, 0); assert.equal(f.removals.length, 0); assert.equal(f.events.length, 0);
  const runs = createAvitRuns(f.batch); assert.throws(() => runs.start({ avits: avit(1), execution: { maxConcurrency: 9 } }), /Concurrency/); assert.equal(runs.attach(() => {}).runId, null);
  await f.run(Array.from({ length: 65 }, (_, index) => avit(index + 1)));
  assert.equal(f.events.find(event => event.type === 'avit_batch_start').avits.length, 65);
  assert.equal(f.models.length, 65); assert.deepEqual(avitExecution({ mode: 'sequential', maxConcurrency: 8 }), { mode: 'sequential', maxConcurrency: 1 });
});

test('all children use one saved ServiceNow snapshot even if Settings change during a run', async t => {
  const config = require('../lib/threatlint-config.cjs');
  config.writeServiceNow({ instance: 'https://original.service-now.com', clientId: 'old-fixture-client', clientSecret: 'old-fixture-secret' });
  let changed = false;
  const f = fixture(t, { cli: async args => { if (args[1] === 'fetch' && !changed) { changed = true; config.writeServiceNow({ instance: 'https://changed.service-now.com', clientId: 'new-fixture-client', clientSecret: 'new-fixture-secret' }); } } });
  await f.run([avit(1), avit(2)], { servicenow: {} });
  for (const call of f.calls) { assert.equal(call.options.env.THREATLINT_SNOW_INSTANCE, 'https://original.service-now.com'); assert.equal(call.options.env.THREATLINT_SNOW_CLIENT_ID, 'old-fixture-client'); assert.equal(call.options.env.THREATLINT_SNOW_CLIENT_SECRET, 'old-fixture-secret'); }
  config.clearServiceNow();
});

test('Workbench shutdown waits for an active AVIT update and its cleanup, and start metadata replays concurrency', async t => {
  let writing, cleaning;
  const writingPromise = new Promise(resolve => { writing = resolve; }), cleaningPromise = new Promise(resolve => { cleaning = resolve; });
  const f = fixture(t, { write: async () => { writing(); await writeGate.promise; }, cleanup: async () => { cleaning(); await cleanupGate.promise; } }), writeGate = f.gate(), cleanupGate = f.gate();
  const { createWorkbench } = require('../server.js');
  const workbench = createWorkbench({ storageDir: f.directory, runProvider: f.override, integrations: { ...f.integrations, convertToWord: async (_md, docx) => fs.writeFileSync(docx, 'Synthetic Word artifact') } });
  await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
  const origin = 'http://127.0.0.1:' + workbench.server.address().port;
  const socket = new WebSocket(origin.replace('http:', 'ws:'), { origin });
  await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
  const events = []; socket.on('message', raw => events.push(JSON.parse(raw)));
  const socketEvent = predicate => bounded(new Promise(resolve => {
    const listener = raw => { const event = JSON.parse(raw); if (predicate(event)) { socket.off('message', listener); resolve(event); } };
    socket.on('message', listener);
  }));
  let closing;
  try {
    const started = socketEvent(event => event.type === 'fp_run_start');
    socket.send(JSON.stringify({ action: 'run_avit_batch', ...f.message, avits: avit(1), execution: { maxConcurrency: 2 } }));
    const [start] = await Promise.all([started, bounded(writingPromise)]); assert.deepEqual(start.execution, { mode: 'auto', maxConcurrency: 2 });
    const replayed = socketEvent(event => event.type === 'avit_batch_replay'); socket.send(JSON.stringify({ action: 'avit_batch_attach' }));
    const replay = await replayed; assert.equal(replay.active, true); assert.deepEqual(replay.events.find(event => event.type === 'fp_run_start').execution, start.execution);
    let settled = false; closing = workbench.close().then(() => { settled = true; }); await Promise.resolve(); assert.equal(settled, false);
    writeGate.release(); await bounded(cleaningPromise); assert.equal(settled, false); cleanupGate.release(); await closing;
    assert.equal(workbench.server.listening, false);
  } finally { writeGate.release(); cleanupGate.release(); socket.terminate(); if (closing) await closing; else await workbench.close(); }
});
