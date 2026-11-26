'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { integer } = require('../public/platform-controls.js');

class Node extends EventTarget {
  constructor(tag = 'div') {
    super(); this.tagName = tag.toUpperCase(); this.children = []; this.parentNode = null; this._text = '';
    this.className = ''; this.dataset = {}; this.style = {}; this.value = ''; this.disabled = false; this.hidden = false;
    this.classList = {
      contains: value => this.className.split(/\s+/).includes(value),
      add: (...values) => { this.className = [...new Set([...this.className.split(/\s+/).filter(Boolean), ...values])].join(' '); },
      remove: (...values) => { this.className = this.className.split(/\s+/).filter(value => !values.includes(value)).join(' '); },
      toggle: (value, force) => { const add = force ?? !this.classList.contains(value); this.classList[add ? 'add' : 'remove'](value); return add; },
    };
  }
  get textContent() { return this._text + this.children.map(child => typeof child === 'string' ? child : child.textContent).join(''); }
  set textContent(value) { this.replaceChildren(); this._text = String(value); }
  append(...values) { for (const value of values) { if (value instanceof Node) { value.remove(); value.parentNode = this; } this.children.push(value); } }
  prepend(value) { if (value instanceof Node) { value.remove(); value.parentNode = this; } this.children.unshift(value); }
  replaceChildren(...values) { for (const child of this.children) if (child instanceof Node) child.parentNode = null; this.children = []; this._text = ''; this.append(...values); }
  remove() { if (this.parentNode) { const children = this.parentNode.children; children.splice(children.indexOf(this), 1); this.parentNode = null; } }
  replaceWith(value) { const parent = this.parentNode; if (!parent) return; const index = parent.children.indexOf(this); this.parentNode = null; value.parentNode = parent; parent.children[index] = value; }
  get firstElementChild() { return this.children.find(child => child instanceof Node); }
  get lastElementChild() { return this.children.findLast(child => child instanceof Node); }
  setAttribute(name, value) { this[name] = String(value); }
  getAttribute(name) { return this[name] ?? null; }
  removeAttribute(name) { delete this[name]; }
  matches(selector) { return selector.startsWith('.') ? this.classList.contains(selector.slice(1)) : selector.startsWith('#') ? this.id === selector.slice(1) : this.tagName === selector.toUpperCase(); }
  querySelectorAll(selector) {
    const [first, ...rest] = selector.split(' '), found = [];
    const visit = node => { for (const child of node.children) if (child instanceof Node) { if (child.matches(first)) found.push(...(rest.length ? child.querySelectorAll(rest.join(' ')) : [child])); visit(child); } };
    visit(this); return found;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  reportValidity() { return true; }
  focus() {}
  scrollIntoView() {}
}
class DetailEvent extends Event { constructor(name, init = {}) { super(name); this.detail = init.detail; } }
const source = name => fs.readFileSync(path.join(__dirname, '../public', name), 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));
const avits = ['AVIT0000001', 'AVIT0000002', 'AVIT0000003', 'AVIT0000004', 'AVIT0000005'];

function client(entries = new Map()) {
  const root = new Node('main'), nodes = new Map();
  const node = id => root.querySelector(`#${id}`) || (() => { if (!nodes.has(id)) nodes.set(id, new Node()); return nodes.get(id); })();
  const document = new EventTarget(); Object.assign(document, { getElementById: node, createElement: tag => new Node(tag), createTextNode: text => String(text), querySelectorAll: () => [], querySelector: node, body: new Node('body') });
  const storage = { getItem: key => entries.get(key) ?? null, setItem: (key, value) => entries.set(key, value) };
  const window = new EventTarget(); window.ThreatlintProfile = { sessionStorage: storage };
  const context = vm.createContext({ document, window, URL, Event, CustomEvent: DetailEvent, sessionStorage: { getItem() { throw new Error('Unscoped session read'); }, setItem() { throw new Error('Unscoped session write'); } }, localStorage: storage,
    setTimeout: action => { action(); return 1; }, clearTimeout() {}, location: { hash: '' }, console });
  vm.runInContext(source('fpreview-run.js'), context);
  const run = window.ThreatlintFpRun.create(root);
  return { root, node, run, entries, context, window, document, storage };
}
const item = (run, avit, stage, fields = {}) => run.handle({ type: 'avit_item', avit, stage, ...fields });

test('shows three active reviews and independently completes or fails findings out of input order', () => {
  const f = client(); f.run.start({ avits, sctasks: [], execution: { maxConcurrency: 3 } });
  item(f.run, avits[0], 'queued');
  assert.match(f.node('fpreview-counts').textContent, /0 \/ 5 · 0 active · 5 queued/);
  for (const avit of avits.slice(0, 3)) item(f.run, avit, 'triage');
  assert.match(f.node('fpreview-counts').textContent, /0 \/ 5 · 3 active · 2 queued/);
  assert.equal(f.node('fpreview-run-status').textContent, '0 of 5 reviewed · 3 active');
  assert.match(f.node('fpreview-run-note').textContent, /Up to 3 reviews at once/);
  item(f.run, avits[2], 'done', { done: true, result: 'noted' });
  item(f.run, avits[1], 'error', { done: true, result: 'error', detail: '<untrusted provider error>' });
  assert.match(f.node('fpreview-counts').textContent, /2 \/ 5 · 1 active · 2 queued.*1 error/);
  assert.equal(f.node(`avit-${avits[0]}`).classList.contains('active'), true);
  assert.equal(f.node(`avit-${avits[2]}`).dataset.result, 'noted');
  assert.equal(f.node(`avit-${avits[1]}`).dataset.result, 'error');
  assert.equal(f.node(`avit-${avits[1]}`).querySelector('.avit-detail').textContent, '<untrusted provider error>');
  item(f.run, avits[3], 'fetching');
  assert.match(f.node('fpreview-progress').getAttribute('aria-valuetext'), /2 of 5 AVITs done, 2 active, 1 queued/);
  assert.equal(f.run.running, true);
});

test('distinguishes an unverified Semgrep triage write from an incomplete rule proposal', () => {
  const f = client(); f.run.start({ avits: avits.slice(0, 3), sctasks: [] });
  const mismatch = 'Semgrep affected IDs/count differ from the requested branch scope. Inspect triage audit /tmp/fixture.json before retrying.';
  const missingFixtures = 'Rule not tuned: The report has no `**Tuned rule fixtures**:` block.';
  const closed = { attached: true, closed: true, tuned: false };
  item(f.run, avits[0], 'error', { done: true, disposition: 'FALSE POSITIVE', detail: mismatch, outcome: closed });
  item(f.run, avits[1], 'rule-not-tuned', { done: true, disposition: 'FALSE POSITIVE', detail: missingFixtures, outcome: { ...closed, semgrep: [`! ${missingFixtures}`] } });
  item(f.run, avits[2], 'error', { done: true, disposition: 'FALSE POSITIVE', detail: 'Rule tuning proof failed before AVIT write-back: The report needs one complete tuned rule and its fixtures' });
  f.run.handle({ type: 'avit_batch_complete' });

  const card = avit => f.node(`avit-${avit}`);
  const outcomes = avit => card(avit).querySelector('.avit-outcome').textContent;
  assert.match(outcomes(avits[0]), /Word report attached.*Closed as false positive.*Review the triage audit and reconcile the affected findings/);
  assert.equal(card(avits[0]).querySelector('.avit-detail').textContent, mismatch);
  assert.doesNotMatch(outcomes(avits[0]), /Correct the proposal|Re-run this AVIT/);
  assert.equal(card(avits[1]).querySelector('.avit-stage').textContent, 'Rule not tuned');
  assert.equal(card(avits[1]).dataset.result, 'closed');
  assert.equal(card(avits[1]).querySelector('.avit-detail').textContent, missingFixtures);
  assert.match(outcomes(avits[1]), /Word report attached.*Closed as false positive/);
  assert.doesNotMatch(outcomes(avits[2]), /attached|Closed as false positive/);
  assert.doesNotMatch(f.root.textContent, /Re-run this AVIT/);
});

test('keeps completed results while cancelling remaining active and queued reviews, including scoped restore/replay', () => {
  const f = client(); f.run.handle({ type: 'fp_run_start', runId: 'fixture-run', avits: avits.slice(0, 3), sctasks: [], execution: { maxConcurrency: 2 } });
  item(f.run, avits[0], 'triage'); item(f.run, avits[1], 'triage');
  item(f.run, avits[0], 'done', { done: true, result: 'closed' });
  for (const avit of avits.slice(1, 3)) item(f.run, avit, 'cancelled', { done: true, result: 'skipped' });
  f.run.handle({ type: 'avit_batch_complete', cancelled: true });
  assert.equal(f.node('fpreview-run-status').textContent, 'Stopped');
  assert.match(f.node('fpreview-counts').textContent, /3 \/ 3.*1 closed.*2 skipped/);
  assert.equal(f.root.querySelectorAll('.active').length, 0);
  assert.equal(f.run.running, false);
  const restored = client(f.entries); assert.equal(restored.run.restore(), true);
  assert.equal(restored.run.runId, 'fixture-run');
  assert.equal(restored.node(`avit-${avits[0]}`).dataset.result, 'closed');
  assert.equal(restored.node(`avit-${avits[1]}`).querySelector('.avit-stage').textContent, 'Cancelled');
  const events = JSON.parse(f.entries.get('threatlint.fpreview.run.v1'));
  restored.run.replay(events.slice(0, 4));
  assert.equal(restored.run.running, true); assert.match(restored.node('fpreview-counts').textContent, /1 \/ 3 · 1 active · 1 queued/);
  assert.match(restored.node('fpreview-run-note').textContent, /Up to 2 reviews at once/);
});

test('retains blocked proof and triage as distinct from errors and successful writes after reload', () => {
  const f = client();
  f.run.start({ avits: avits.slice(0, 2), sctasks: [] });
  item(f.run, avits[0], 'blocked', { done: true, disposition: 'FALSE POSITIVE', detail: 'Rule tuning blocked before AVIT write-back.' });
  item(f.run, avits[1], 'blocked', { done: true, result: 'blocked', disposition: 'FALSE POSITIVE', detail: 'Semgrep triage blocked by a shared fingerprint.', outcome: { closed: true, attached: true } });
  f.run.handle({ type: 'avit_batch_complete' });
  const restored = client(f.entries);
  assert.equal(restored.run.restore(), true);
  assert.match(restored.node('fpreview-counts').textContent, /2 \/ 2.*2 blocked · 0 errors/);
  const unwritten = restored.node(`avit-${avits[0]}`);
  assert.equal(unwritten.querySelector('.avit-stage').textContent, 'Blocked');
  assert.equal(unwritten.querySelector('.avit-outcome').textContent, '');
  assert.match(restored.node(`avit-${avits[1]}`).querySelector('.avit-outcome').textContent, /Word report attached.*Closed as false positive/);
});

test('tracks shared task progress while separate findings finish and uses authoritative batch concurrency', () => {
  const f = client(); f.run.start({ avits: [], sctasks: ['SCTASK0000001'], execution: { maxConcurrency: 3 } });
  f.run.handle({ type: 'sctask_item', sctask: 'SCTASK0000001', stage: 'reviewing', avits: avits.slice(0, 3) });
  f.run.handle({ type: 'avit_batch_start', avits: avits.slice(0, 3), execution: { maxConcurrency: 2 } });
  item(f.run, avits[0], 'triage'); item(f.run, avits[1], 'triage');
  item(f.run, avits[1], 'done', { done: true, result: 'noted' });
  assert.match(f.node('sctask-SCTASK0000001').querySelector('.fp-task-progress').textContent, /1 \/ 3 AVITs reviewed/);
  assert.match(f.node('fpreview-run-note').textContent, /Up to 2 reviews at once/);
  assert.equal(f.node('sctask-SCTASK0000001').querySelectorAll('.chip-active').length, 1);
  assert.equal(f.node('sctask-SCTASK0000001').querySelectorAll('.chip-noted').length, 1);
  assert.equal(f.node('fpreview-avit-cards').children.length, 3, 'batch-start replay moves existing cards rather than duplicating them');
});

async function appClient(value = '3') {
  const f = client();
  f.window.ThreatlintPlatformControls = { integer };
  f.window.ThreatlintActivityLog = { createActivityLog: () => ({ clear() {} }) };
  const sent = [], requests = [];
  f.context.fetch = async url => { requests.push(url); return { ok: true, json: async () => ({ items: [] }) }; };
  const bootstrap = '  initialize().catch(error => toast(`Workbench initialization failed: ${error.message}`, true));';
  assert(source('app.js').includes(bootstrap));
  vm.runInContext(source('app.js').replace(bootstrap, '  window.appFixture = { state, startAvitBatch, handleEvent, fpreviewRunning };'), f.context);
  await settle(); const app = f.window.appFixture;
  Object.assign(app.state, { connected: true, ws: { readyState: 1, send: message => sent.push(JSON.parse(message)) }, snowSaved: { instance: 'https://fixture.service-now.com', clientId: 'fixture-client', hasSecret: true } });
  app.state.preferences.provider = 'codex'; app.state.preferences.snowInstance = 'https://fixture.service-now.com';
  f.node('fpreview-concurrency').value = value; f.node('fpreview-avits').value = avits.slice(0, 3).join(' '); f.node('fpreview-fix-pr').checked = true;
  return { ...f, app, sent, requests };
}

test('launches one durable batch with bounded reviewer concurrency, locks edits, and waits for final completion after stop', async () => {
  for (const value of ['1', '3', '8']) {
    const f = await appClient(value); await f.app.startAvitBatch({ preventDefault() {} });
    assert.equal(f.sent.length, 1); assert.equal(f.sent[0].action, 'run_avit_batch');
    assert.deepEqual(f.sent[0].execution, { maxConcurrency: Number(value) });
    assert.equal(f.node('fpreview-concurrency').disabled, true);
    f.app.handleEvent({ type: 'avit_batch_cancel_ack', accepted: true });
    assert.equal(f.node('fpreview-cancel').disabled, true); assert.equal(f.node('fpreview-cancel').textContent, 'Stopping…');
    assert.match(f.node('toast').textContent, /updates already underway may finish/);
    assert.equal(f.node('fpreview-start').disabled, true, 'cancel acknowledgement must not unlock a draining run');
    f.app.handleEvent({ type: 'avit_batch_complete', cancelled: true });
    assert.equal(f.node('fpreview-concurrency').disabled, false); assert.equal(f.node('fpreview-start').disabled, false);
  }
});

test('rejects invalid concurrency before starting setup requests or a review', async () => {
  for (const value of ['0', '9', '2.5', 'Infinity', 'invalid']) {
    const f = await appClient(value); await f.app.startAvitBatch({ preventDefault() {} });
    assert.equal(f.sent.length, 0); assert.equal(f.requests.length, 0);
    assert.match(f.node('fpreview-error').textContent, /whole number from 1 to 8/);
  }
});

test('restores the actual server concurrency into the locked input on live start and authoritative replay', async () => {
  const f = await appClient('3');
  f.app.handleEvent({ type: 'fp_run_start', avits: avits.slice(0, 3), sctasks: [], execution: { maxConcurrency: 4 } });
  assert.equal(f.node('fpreview-concurrency').value, '4');
  f.app.handleEvent({ type: 'avit_batch_start', avits: avits.slice(0, 3), execution: { maxConcurrency: 2 } });
  assert.equal(f.node('fpreview-concurrency').value, '2');
  f.app.handleEvent({ type: 'avit_batch_replay', runId: 'server-run', active: true, events: [
    { type: 'fp_run_start', avits: avits.slice(0, 3), sctasks: [], execution: { maxConcurrency: 3 } },
    { type: 'avit_batch_start', avits: avits.slice(0, 3), execution: { maxConcurrency: 1 } },
    { type: 'avit_item', avit: avits[0], stage: 'triage' },
  ] });
  assert.equal(f.node('fpreview-concurrency').value, '1');
  assert.equal(f.node('fpreview-concurrency').disabled, true);
});
