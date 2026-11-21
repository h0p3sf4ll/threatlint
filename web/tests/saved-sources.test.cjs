'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const { createSavedSourceActivator } = require('../lib/saved-sources.cjs');

it('reuses active saved source accounts across repeated and concurrent activations, reconnecting after disconnect or rotation', async () => {
  let calls = 0; const connections = [];
  const scm = { list: () => connections.slice(), connect: async input => {
    calls++; const result = { id: `connection-${calls}`, provider: input.provider, account: input.organization || 'personal' };
    connections.push(result); return result;
  } };
  const activate = createSavedSourceActivator(scm);
  const saved = { provider: 'github', organization: 'engineering', token: 'secret-token' };
  const [first, concurrent] = await Promise.all([activate(saved), activate(saved)]);
  assert.equal(first.id, concurrent.id); assert.equal(calls, 1);
  assert.equal((await activate(saved)).id, first.id); assert.equal(calls, 1);
  assert.equal(JSON.stringify(first).includes(saved.token), false);
  connections.splice(0);
  assert.notEqual((await activate(saved)).id, first.id); assert.equal(calls, 2);
  await activate({ ...saved, token: 'rotated-secret' }); assert.equal(calls, 3);
  await activate({ ...saved, organization: 'another-team' }); assert.equal(calls, 4);
});

it('allows a failed source activation to be retried without retaining a failed promise', async () => {
  let attempts = 0;
  const activate = createSavedSourceActivator({ list: () => [], connect: async () => {
    if (++attempts === 1) throw new Error('Rejected by provider');
    return { id: 'recovered' };
  } });
  const saved = { provider: 'github', token: 'fixture-token' };
  await assert.rejects(activate(saved));
  assert.equal((await activate(saved)).id, 'recovered'); assert.equal(attempts, 2);
});
