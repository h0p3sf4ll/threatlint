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

const settle = () => new Promise(resolve => setImmediate(resolve));
const response = (preferences, ok = true) => ({ ok, json: async () => ({ preferences }) });
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
function experienceClient({ id = 'alice', records = new Map(), cache = new Map(), ready = Promise.resolve(), fetch } = {}) {
  const nodes = new Map(['experience-mode', 'experience-status', 'ensemble-enabled', 'ensemble-options', 'ensemble-third-enabled', 'ensemble-third']
    .map(name => [name, Object.assign(new EventTarget(), { value: name === 'experience-mode' ? 'guided' : '', checked: false, disabled: false, textContent: '' })]));
  const document = { body: { dataset: {} }, getElementById: name => nodes.get(name), querySelectorAll: () => [] };
  const calls = [];
  const profile = { ready, web: id !== null, user: id === null ? null : { id }, storage: {
    getItem: key => cache.get(`${profile.user?.id || 'desktop'}:${key}`) ?? null,
    setItem: (key, value) => cache.set(`${profile.user?.id || 'desktop'}:${key}`, value),
  }, fetch: async (url, options) => {
    const owner = profile.user?.id || 'desktop';
    calls.push({ owner, url, options });
    if (fetch) return fetch(url, options);
    if (options.method === 'PUT') records.set(owner, JSON.parse(options.body));
    return response(records.get(owner) ?? null);
  } };
  const window = { document, ThreatlintProfile: profile,
    localStorage: { getItem() { throw new Error('Unscoped read'); }, setItem() { throw new Error('Unscoped write'); } },
    fetch() { throw new Error('Unscoped request'); } };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../public/platform-controls.js'), 'utf8'), { window });
  return { profile, calls, cache, document, mode: nodes.get('experience-mode'), status: nodes.get('experience-status'), api: window.ThreatlintPlatformControls };
}

test('experience waits for identity and restores the durable profile value before browser cache', async () => {
  const ready = deferred(), records = new Map([['alice', { experience: 'advanced' }]]);
  const alice = experienceClient({ records, ready: ready.promise, cache: new Map([['alice:threatlint.experience', 'guided']]) });
  assert.equal(alice.calls.length, 0);
  alice.api.setLocked(false);
  assert.equal(alice.mode.disabled, true, 'unlocking a review must not enable an unresolved preference');
  ready.resolve(); await settle();
  assert.equal(alice.mode.value, 'advanced');
  assert.equal(alice.document.body.dataset.experience, 'advanced');
  assert.equal(alice.mode.disabled, false);
  assert.equal(alice.calls.length, 1, 'loading an existing preference must not overwrite it');
  const bob = experienceClient({ id: 'bob', records }); await settle();
  assert.equal(bob.mode.value, 'guided');
  bob.mode.value = 'advanced'; bob.mode.dispatchEvent(new Event('change')); await settle();
  alice.mode.value = 'guided'; alice.mode.dispatchEvent(new Event('change')); await settle();
  assert.deepEqual(records.get('alice'), { experience: 'guided' });
  assert.deepEqual(records.get('bob'), { experience: 'advanced' });
  assert.equal(alice.calls.every(call => call.url === '/api/ui-preferences'), true);
});

test('a fresh desktop origin restores experience without its prior localStorage', async () => {
  const records = new Map(), first = experienceClient({ id: null, records }); await settle();
  first.mode.value = 'advanced'; first.mode.dispatchEvent(new Event('change')); await settle();
  const restarted = experienceClient({ id: null, records }); await settle();
  assert.equal(restarted.mode.value, 'advanced');
  assert.equal(restarted.document.body.dataset.experience, 'advanced');
  assert.equal(restarted.calls.length, 1);
});

test('only a valid scoped legacy experience migrates when the durable store is empty', async () => {
  const records = new Map(), cache = new Map([['alice:threatlint.experience', 'advanced']]);
  const alice = experienceClient({ records, cache }); await settle();
  assert.equal(alice.mode.value, 'advanced');
  assert.deepEqual(records.get('alice'), { experience: 'advanced' });
  assert.deepEqual(alice.calls.map(call => call.options.method), ['GET', 'PUT']);
  assert.deepEqual(JSON.parse(alice.calls[1].options.body), { experience: 'advanced' });
  const bob = experienceClient({ id: 'bob', records, cache: new Map([['bob:threatlint.experience', 'invalid']]) }); await settle();
  assert.equal(bob.mode.value, 'guided');
  assert.equal(bob.calls.length, 1);
});

test('a failed preference read does not overwrite saved data or migrate a browser cache', async () => {
  const client = experienceClient({ cache: new Map([['alice:threatlint.experience', 'advanced']]), fetch: async () => response(null, false) });
  await settle();
  assert.equal(client.mode.disabled, true);
  assert.equal(client.mode.value, 'guided');
  assert.equal(client.calls.length, 1);
  assert.match(client.status.textContent, /could not be loaded/);
});

test('a failed save restores the acknowledged mode and keeps a running review locked', async () => {
  const save = deferred(), client = experienceClient({ fetch: async (_url, options) => options.method === 'GET' ? response({ experience: 'guided' }) : save.promise });
  await settle();
  client.mode.value = 'advanced'; client.mode.dispatchEvent(new Event('change'));
  assert.equal(client.mode.disabled, true);
  client.api.setLocked(true);
  save.resolve(response(null, false)); await settle();
  assert.equal(client.mode.value, 'guided');
  assert.equal(client.document.body.dataset.experience, 'guided');
  assert.equal(client.cache.get('alice:threatlint.experience'), 'guided');
  assert.match(client.status.textContent, /could not be saved/);
  assert.equal(client.mode.disabled, true);
  client.api.setLocked(false); assert.equal(client.mode.disabled, false);
});

test('responses for a former profile cannot restore or cache another profile experience', async () => {
  const load = deferred(), client = experienceClient({ fetch: async () => load.promise });
  await settle(); client.profile.user = { id: 'bob' };
  load.resolve(response({ experience: 'advanced' })); await settle();
  assert.equal(client.mode.value, 'guided');
  assert.equal(client.mode.disabled, true);
  assert.equal(client.cache.size, 0);
  assert.equal(client.calls.length, 1);
});

test('a save response after an identity switch cannot write the new profile browser cache', async () => {
  const save = deferred(), client = experienceClient({ fetch: async (_url, options) => options.method === 'GET' ? response({ experience: 'guided' }) : save.promise });
  await settle();
  client.mode.value = 'advanced'; client.mode.dispatchEvent(new Event('change'));
  client.profile.user = { id: 'bob' }; save.resolve(response({ experience: 'advanced' })); await settle();
  assert.equal(client.cache.has('bob:threatlint.experience'), false);
  assert.equal(client.cache.get('alice:threatlint.experience'), 'guided');
  assert.equal(client.mode.disabled, true);
});
