'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
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

test('experience preferences wait for identity and remain separate across profiles', async () => {
  const values = new Map([['alice:threatlint.experience', 'advanced']]);
  const pending = [];
  function start(id) {
    const nodes = new Map(['experience-mode', 'ensemble-enabled', 'ensemble-options', 'ensemble-third-enabled', 'ensemble-third'].map(name => [name, Object.assign(new EventTarget(), { value: name === 'experience-mode' ? 'guided' : '', checked: false })]));
    const document = { body: { dataset: {} }, getElementById: name => nodes.get(name), querySelectorAll: () => [] };
    const window = { document, localStorage: { getItem() { throw new Error('Unscoped read'); }, setItem() { throw new Error('Unscoped write'); } },
      ThreatlintProfile: { ready: new Promise(resolve => pending.push(resolve)), storage: {
        getItem: key => values.get(`${id}:${key}`) ?? null,
        setItem: (key, value) => values.set(`${id}:${key}`, value),
      } } };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../public/platform-controls.js'), 'utf8'), { window });
    return { mode: nodes.get('experience-mode'), document };
  }
  const alice = start('alice');
  assert.equal(alice.mode.value, 'guided', 'identity must resolve before saved preferences are read');
  pending.shift()(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(alice.mode.value, 'advanced');
  assert.equal(alice.document.body.dataset.experience, 'advanced');
  const bob = start('bob'); pending.shift()(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(bob.mode.value, 'guided', 'a new profile must not inherit the previous user’s mode');
  bob.mode.value = 'advanced'; bob.mode.dispatchEvent(new Event('change'));
  alice.mode.value = 'guided'; alice.mode.dispatchEvent(new Event('change'));
  assert.equal(values.get('alice:threatlint.experience'), 'guided');
  assert.equal(values.get('bob:threatlint.experience'), 'advanced');
});
