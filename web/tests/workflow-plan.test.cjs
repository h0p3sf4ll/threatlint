'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { buildPlan, executePlan } = require('../lib/workflow-plan.cjs');
const { AGENTS, CONTRACTS } = require('../lib/agents.cjs');
const A = 'appsec-code-reviewer', B = 'appsec-auth-reviewer', C = 'appsec-security-test-planner';
const deferred = () => { let resolve; const promise = new Promise(yes => { resolve = yes; }); return { promise, resolve }; };
const tick = () => new Promise(resolve => setImmediate(resolve));

test('every role has a distinct, runtime-loaded handoff contract', () => {
  assert.deepEqual(Object.keys(CONTRACTS), Object.keys(AGENTS));
  assert.equal(new Set(Object.values(CONTRACTS).map(contract => contract.inputs)).size, 22);
  for (const agent of Object.values(AGENTS)) {
    assert.ok(agent.systemPrompt.includes(agent.contract.boundaries));
    assert.equal(agent.inputHint, agent.contract.inputs);
  }
});

test('auto plans independent roots and upstream report barriers; sequential preserves ordered chains', () => {
  const plan = buildPlan([A, B, C]);
  assert.equal(plan.maxConcurrency, 3);
  assert.deepEqual(plan.nodes.map(node => node.dependsOn), [[], [], [A, B]]);
  assert.deepEqual(buildPlan([A, B, C], { mode: 'sequential' }).nodes.map(node => node.dependsOn), [[], [A], [A, B]]);
  assert.equal(buildPlan([A, B], { mode: 'sequential', maxConcurrency: 8 }).maxConcurrency, 1);
  const triage = 'appsec-fp-reviewer';
  assert.deepEqual(buildPlan(['appsec-threat-modeler', triage]).nodes[1].dependsOn, ['appsec-threat-modeler']);
  assert.deepEqual(buildPlan([triage]).nodes[0].dependsOn, []);
});

test('validates dependency references, cycles, modes and bounds before execution', () => {
  for (const execution of [{ mode: 'parallel' }, { maxConcurrency: 0 }, { maxConcurrency: 9 }, { maxConcurrency: 1.5 }, { dependencies: { other: [] } }, { dependencies: { [A]: [A] } }, { dependencies: { [A]: ['other'] } }, { dependencies: { [A]: [B], [B]: [A] } }, null, []]) {
    assert.throws(() => buildPlan([A, B], execution));
  }
  assert.deepEqual(buildPlan([A, B], { dependencies: { [A]: [B] } }).nodes[0].dependsOn, [B]);
});

test('parallel execution feeds deterministic source-order evidence to downstream reviewers', async () => {
  const gates = new Map([[A, deferred()], [B, deferred()]]), calls = [];
  const pending = executePlan(buildPlan([A, B, C], { maxConcurrency: 2 }), async (id, contexts) => {
    calls.push({ id, contexts });
    if (gates.has(id)) await gates.get(id).promise;
    return id;
  });
  await tick(); assert.deepEqual(calls.map(call => call.id), [A, B]);
  gates.get(B).resolve(); await tick(); assert.equal(calls.length, 2);
  gates.get(A).resolve();
  assert.equal((await pending).status, 'complete');
  assert.deepEqual(calls.at(-1), { id: C, contexts: [A, B] });
  assert.deepEqual(calls[0].contexts, []); assert.deepEqual(calls[1].contexts, []);
});

test('failed prerequisites skip dependent work even when independent work may continue', async () => {
  const called = [], skipped = [];
  const outcome = await executePlan(buildPlan([A, C, B], { maxConcurrency: 1 }), async id => {
    called.push(id); if (id === A) throw new Error('fixture'); return id;
  }, { continueOnError: true, onSkipped: (id, reason) => skipped.push({ id, reason }) });
  assert.equal(outcome.status, 'error'); assert.deepEqual(called, [A, B]);
  assert.equal(skipped[0].id, C); assert.match(skipped[0].reason, /upstream/);
});

test('stop-on-error never starts queued independent work', async () => {
  const called = [];
  const outcome = await executePlan(buildPlan([A, B], { maxConcurrency: 1 }), async id => { called.push(id); throw new Error('fixture'); });
  assert.equal(outcome.status, 'error'); assert.deepEqual(called, [A]); assert.equal(outcome.states.get(B), 'skipped');
});

test('cancellation stops queued tasks and drains active work before returning', async () => {
  const controller = new AbortController(), gate = deferred(), called = [];
  const pending = executePlan(buildPlan([A, B], { maxConcurrency: 1 }), async id => { called.push(id); await gate.promise; return id; }, { signal: controller.signal });
  await tick(); controller.abort(); gate.resolve();
  assert.equal((await pending).status, 'cancelled'); assert.deepEqual(called, [A]);
});

test('custom dependencies can target a later independent reviewer', async () => {
  const called = [];
  const outcome = await executePlan(buildPlan([A, B], { dependencies: { [A]: [B] } }), async (id, contexts) => { called.push({ id, contexts }); return id; });
  assert.equal(outcome.status, 'complete'); assert.deepEqual(called, [{ id: B, contexts: [] }, { id: A, contexts: [B] }]);
});

test('failure propagates through backward dependency edges without stranded pending agents', async () => {
  const D = 'appsec-crypto-reviewer';
  const outcome = await executePlan(buildPlan([A, B, D], { dependencies: { [A]: [B], [B]: [D] } }), async () => { throw new Error('fixture'); }, { continueOnError: true });
  assert.equal(outcome.status, 'error');
  assert.deepEqual([...outcome.states.values()], ['skipped', 'skipped', 'failed']);
});
