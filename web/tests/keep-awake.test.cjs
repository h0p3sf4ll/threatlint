'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { keepAwake } = require('../lib/keep-awake.cjs');

function fakeSpawn() {
  const started = [];
  const spawnImpl = (file, args) => { const child = { file, args, killed: false, on() {}, unref() {}, kill() { this.killed = true; } }; started.push(child); return child; };
  return { started, spawnImpl };
}

test('concurrent queues share one caffeinate that stops when the last one finishes', () => {
  const { started, spawnImpl } = fakeSpawn();
  const options = { platform: 'darwin', env: {}, spawnImpl, exists: () => true, pid: 4242 };
  const first = keepAwake(options);
  const second = keepAwake(options);
  assert.equal(started.length, 1);
  assert.deepEqual([started[0].file, ...started[0].args], ['/usr/bin/caffeinate', '-i', '-w', '4242']);
  first(); first();
  assert.equal(started[0].killed, false, 'still held by the second queue; a double release counts once');
  second();
  assert.equal(started[0].killed, true);
});

test('keep-awake is off elsewhere, when disabled, and in the test runner', () => {
  const { started, spawnImpl } = fakeSpawn();
  for (const [platform, env] of [['linux', {}], ['darwin', { THREATLINT_KEEP_AWAKE: '0' }], ['darwin', { NODE_TEST_CONTEXT: 'child' }]]) {
    keepAwake({ platform, env, spawnImpl, exists: () => true })();
  }
  assert.equal(started.length, 0);
});
