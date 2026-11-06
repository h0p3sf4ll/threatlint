'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { mapBounded, createLimiter } = require('../lib/concurrency.cjs');
const { executeInspectionCalls } = require('../lib/providers.cjs');
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const tick = () => new Promise(resolve => setImmediate(resolve));

test('bounded map overlaps work while preserving input order', async () => {
  const gates = Array.from({ length: 4 }, deferred), started = [];
  const pending = mapBounded([0, 1, 2, 3], async index => { started.push(index); await gates[index].promise; return index; }, { concurrency: 2 });
  await tick(); assert.deepEqual(started, [0, 1]);
  gates[1].resolve(); await tick(); assert.deepEqual(started, [0, 1, 2]);
  gates[2].resolve(); await tick(); assert.deepEqual(started, [0, 1, 2, 3]);
  gates[3].resolve(); gates[0].resolve();
  assert.deepEqual(await pending, [0, 1, 2, 3]);
});

test('bounded map stops admission on error and drains already running work', async () => {
  const gate = deferred(), started = []; let settled = false;
  const pending = mapBounded([0, 1, 2], async index => { started.push(index); if (!index) throw new Error('fixture'); await gate.promise; }, { concurrency: 2 });
  const checked = assert.rejects(pending, /fixture/).then(() => { settled = true; });
  await tick(); assert.deepEqual(started, [0, 1]); assert.equal(settled, false);
  gate.resolve(); await checked; assert.equal(settled, true);
});

test('bounded map cancels queued work and waits for admitted tasks', async () => {
  const gate = deferred(), controller = new AbortController(), started = [];
  const pending = mapBounded([0, 1, 2], async index => { started.push(index); await gate.promise; }, { concurrency: 2, signal: controller.signal });
  controller.abort(); gate.resolve();
  await assert.rejects(pending, /Cancelled/); assert.deepEqual(started, [0, 1]);
});

test('admission limiter is FIFO, removes cancelled entries and releases failed slots', async () => {
  const admit = createLimiter(1), gate = deferred(), started = [];
  const first = admit(async () => { started.push(1); await gate.promise; throw new Error('first failed'); });
  const firstChecked = assert.rejects(first, /first failed/);
  const controller = new AbortController();
  const second = admit(() => started.push(2), { signal: controller.signal });
  const secondChecked = assert.rejects(second, /Cancelled/);
  const third = admit(() => started.push(3));
  controller.abort(); gate.resolve();
  await Promise.all([firstChecked, secondChecked, third]); assert.deepEqual(started, [1, 3]);
});

test('admission queue has a bound and rejects pre-cancelled work', async () => {
  const admit = createLimiter(1, 1), gate = deferred();
  const first = admit(() => gate.promise), second = admit(() => 2);
  await assert.rejects(admit(() => 3), /queue is full/);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(admit(() => 4, { signal: controller.signal }), /Cancelled/);
  gate.resolve(); await Promise.all([first, second]);
});

test('inspection batch prevalidates every call before running any tool', async () => {
  let count = 0;
  const options = { execute: async () => { count++; }, onEvent: () => {} };
  const valid = { id: 'one', name: 'Read', input: { file_path: 'safe.txt' } };
  for (const invalid of [{ id: 'two', name: 'Write', input: {} }, { id: 'one', name: 'Read', input: {} }, { id: 'two', name: 'Read', input: [] }]) {
    await assert.rejects(executeInspectionCalls([valid, invalid], options), /Invalid/);
  }
  await assert.rejects(executeInspectionCalls(Array(65).fill(valid), options), /too many/);
  assert.equal(count, 0);
});

test('inspection results retain call identity under reversed completion', async () => {
  const gates = [deferred(), deferred()], events = [], started = [];
  const pending = executeInspectionCalls([0, 1].map(index => ({ id: String(index), name: 'Read', input: { index } })), {
    execute: async (_name, { index }) => { started.push(index); await gates[index].promise; return `value-${index}`; }, onEvent: event => events.push(event),
  });
  await tick(); assert.deepEqual(started, [0, 1]); gates[1].resolve(); await tick(); gates[0].resolve();
  assert.deepEqual(await pending, ['value-0', 'value-1']);
  assert.deepEqual(events.filter(event => event.type === 'tool_result').map(event => event.id), ['1', '0']);
});
