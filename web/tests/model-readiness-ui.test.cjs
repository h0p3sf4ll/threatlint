'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Node extends EventTarget {
  constructor() {
    super(); this.children = []; this.value = ''; this.textContent = ''; this.dataset = {}; this.disabled = false; this.hidden = false;
    this.classList = { add() {}, remove() {}, toggle() {} };
  }
  append(...values) { this.children.push(...values); }
  replaceChildren(...values) { this.children = values; }
  insertBefore(value) { this.children.push(value); }
  setAttribute(name, value) { this[name] = value; }
  removeAttribute(name) { delete this[name]; }
  querySelector() { return this.control ||= new Node(); }
  querySelectorAll() { return []; }
  reportValidity() { return true; }
  focus() {}
  scrollIntoView() {}
}
class DetailEvent extends Event { constructor(name, init = {}) { super(name); this.detail = init.detail; } }
const settle = () => new Promise(resolve => setImmediate(resolve));
const source = name => fs.readFileSync(path.join(__dirname, '../public', name), 'utf8');

async function fixture(preferences) {
  const nodes = new Map(), entries = new Map([['threatlint.preferences.v2', JSON.stringify(preferences)]]);
  const node = id => { if (!nodes.has(id)) nodes.set(id, new Node()); return nodes.get(id); };
  const document = new EventTarget(); document.readyState = 'loading';
  Object.assign(document, { getElementById: node, querySelector: node, querySelectorAll: () => [], createElement: () => new Node(), createTextNode: text => text });
  const window = new EventTarget(), sent = [], requests = [];
  window.ThreatlintActivityLog = { createActivityLog: () => ({ clear() {} }) };
  window.ThreatlintPlatformControls = { batchControls: () => new Node(), reviewOptions: () => ({}), setLocked() {}, workerControl: () => new Node() };
  const storage = { getItem: key => entries.get(key) || null, setItem: (key, value) => entries.set(key, value) };
  const fetch = async (url, options = {}) => {
    requests.push({ url, ...options });
    return { ok: true, json: async () => options.method === 'PUT' ? { preferences: JSON.parse(options.body) } : [] };
  };
  const context = vm.createContext({ document, window, localStorage: storage, fetch, URL, CustomEvent: DetailEvent,
    setTimeout: () => 0, clearTimeout() {}, location: { hash: '' }, console });
  // Expose the actual state transitions while skipping unrelated boot-time integrations and sockets.
  const bootstrap = '  initialize().catch(error => toast(`Workbench initialization failed: ${error.message}`, true));';
  assert.ok(source('app.js').includes(bootstrap));
  vm.runInContext(source('app.js').replace(bootstrap, '  window.modelFixture = { state, publishContext, saveSettings, startRun };'), context);
  await settle();
  const app = window.modelFixture;
  document.addEventListener('threatlint:request-context', () => app.publishContext());
  vm.runInContext(source('chat.js'), context); vm.runInContext(source('scan-import.js'), context);
  node('view-scanimport').hidden = true;
  document.dispatchEvent(new Event('DOMContentLoaded'));
  Object.assign(app.state, { connected: true, session: { id: 'fixture-session', repoPath: '/fixture/repository' }, ws: { send: value => sent.push(JSON.parse(value)) } });
  node('pipeline-concurrency').value = '1'; node('pipeline-execution-mode').value = 'sequential';
  return { app, node, entries, sent, requests, document };
}

it('makes default remote CLI models ready for review, chat and triage without an authorization bootstrap', async () => {
  for (const provider of ['codex', 'claude-code']) {
    const f = await fixture({ provider, models: { [provider]: '' } });
    f.app.state.config.providers[provider] = true;
    f.app.publishContext();
    assert.equal(f.node('chat-input').disabled, false);
    assert.equal(f.node('scanimport-start').textContent, 'Triage findings');
    await f.app.startRun();
    assert.equal(f.sent.length, 1);
    assert.equal(f.sent[0].action, 'run_pipeline');
    assert.equal(f.sent[0].provider, provider);
    assert.equal(f.sent[0].model, '');
    assert.equal(Object.hasOwn(f.sent[0], 'remoteAuthorizations'), false);
  }
});

it('ignores revoked legacy flags and saves only non-secret model settings while session keys still reach the runner', async () => {
  for (const remoteAuthorizations of [false, []]) {
    const f = await fixture({ provider: 'openai', models: { openai: 'fixture-model' }, remoteAuthorizations });
    f.node('input[name=provider]:checked').value = 'openai';
    f.node('model-id').value = 'fixture-model'; f.node('model-url').value = 'http://localhost:1234/v1';
    f.node('api-key').value = 'synthetic-session-key';
    await f.app.saveSettings({ preventDefault() {} });
    const saved = f.requests.find(request => request.method === 'PUT');
    assert.ok(saved);
    assert.equal(Object.hasOwn(JSON.parse(saved.body), 'remoteAuthorizations'), false);
    assert.doesNotMatch(saved.body, /synthetic-session-key/);
    assert.doesNotMatch(f.entries.get('threatlint.preferences.v2'), /synthetic-session-key|remoteAuthorizations/);
    assert.equal(f.node('chat-input').disabled, false);
    assert.equal(f.node('scanimport-start').textContent, 'Triage findings');
    await f.app.startRun();
    assert.equal(f.sent[0].openaiApiKey, 'synthetic-session-key');
  }
});

it('keeps an unconfigured model unavailable and rejects invalid remote endpoints before saving', async () => {
  const f = await fixture({ provider: 'openai', models: { openai: '' }, remoteAuthorizations: ['openai'] });
  f.app.publishContext();
  assert.equal(f.node('chat-input').disabled, true);
  assert.equal(f.node('scanimport-start').textContent, 'Import without review');
  f.node('input[name=provider]:checked').value = 'openai'; f.node('model-id').value = 'fixture-model';
  f.node('model-url').value = 'http://remote.example.test/v1';
  await f.app.saveSettings({ preventDefault() {} });
  assert.match(f.node('settings-error').textContent, /Remote servers require HTTPS/);
  assert.equal(f.requests.some(request => request.method === 'PUT'), false);
});
