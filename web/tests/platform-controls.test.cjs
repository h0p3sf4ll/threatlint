'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { participant, buildEnsemble, integer } = require('../public/platform-controls.js');

test('independent providers require explicit consent and provider-specific credentials', () => {
  assert.throws(() => participant('second', { provider: 'openai', model: 'fixture', key: 'private' }), /Authorize/);
  const p = participant('second', { provider: 'openai', model: 'fixture', key: 'private', consent: true });
  assert.deepEqual(p.settings, { provider: 'openai', model: 'fixture', openaiApiKey: 'private' });
  assert.throws(() => participant('second', { provider: '__proto__', model: 'fixture', consent: true }), /supported/);
  assert.throws(() => participant('second', { provider: 'claude', consent: true }), /explicit model/);
});

test('ensemble refuses duplicate providers and never copies a primary key to another participant', () => {
  const primary = { provider: 'openai', model: 'fixture-a', openaiApiKey: 'private-a' };
  const second = participant('second', { provider: 'claude', model: 'fixture-b', key: 'private-b', consent: true });
  const result = buildEnsemble(primary, [second], true);
  assert.equal(result.participants[1].settings.openaiApiKey, undefined);
  assert.equal(result.participants[0].settings.apiKey, undefined);
  assert.equal(result.challengeRounds, 1);
  assert.throws(() => buildEnsemble(primary, [second], false), /Authorize/);
  assert.throws(() => buildEnsemble(primary, [{ ...second, settings: primary }], true), /different providers/);
  assert.throws(() => buildEnsemble(primary, [], true), /two or three/);
});

test('worker and model budgets reject fractional, zero and unbounded values', () => {
  for (const value of [0, -1, 1.5, Infinity, 'x', 65]) assert.throws(() => integer(value, 24, 64));
  assert.equal(integer('4', 1, 4), 4);
  assert.equal(integer(undefined, 24, 64), 24);
});
