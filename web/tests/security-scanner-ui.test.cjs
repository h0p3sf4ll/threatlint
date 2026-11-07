'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Element extends EventTarget {
  constructor(tag = 'div') { super(); this.tagName = tag; this.children = []; this._text = ''; this.value = ''; this.checked = false; this.disabled = false; this.hidden = false; this.dataset = {}; this.classList = { toggle() {} }; }
  get textContent() { return this._text + this.children.map(item => item.textContent).join(''); }
  set textContent(value) { this._text = String(value); this.children = []; }
  set innerHTML(_) { throw new Error('Untrusted HTML must not be rendered'); }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = items; this._text = ''; }
  querySelectorAll(tag) { return this.children.flatMap(item => [...(item.tagName === tag ? [item] : []), ...item.querySelectorAll(tag)]); }
}
class DetailEvent extends Event { constructor(name, input = {}) { super(name); this.detail = input.detail; } }
const settle = () => new Promise(resolve => setImmediate(resolve));
const response = data => ({ ok: true, json: async () => data });
const scan = { id: 'initial', status: 'partial', findings: [{ id: 'debug', title: '<img src=x> debug setting', severity: 'MEDIUM', path: 'settings.py', line: 1, snippet: 'DEBUG = True', fixAvailable: true, ruleId: 'TL-DEBUG-ENABLED' }], engines: [], coverage: { status: 'partial' } };
function fixture(fetch) {
  const html = fs.readFileSync(path.join(__dirname, '../public/index.html'), 'utf8');
  const nodes = new Map([...html.matchAll(/id="([^"]+)"/g)].map(match => [match[1], new Element()]));
  const document = new EventTarget();
  document.getElementById = id => nodes.get(id); document.createElement = tag => new Element(tag);
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../public/security-platform.js'), 'utf8'), { document, fetch, CustomEvent: DetailEvent, setTimeout });
  const session = id => document.dispatchEvent(new DetailEvent('threatlint:context', { detail: { session: { id, repoPath: `/repos/${id}` } } }));
  return { nodes, document, session };
}

test('switching workspace during automatic apply does not relock or overwrite the new workspace', async () => {
  let release;
  const calls = [];
  const app = fixture((url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/apply')) return new Promise(resolve => { release = resolve; });
    if (url.endsWith('/fixes')) return Promise.resolve(response({ id: 'plan' }));
    if (url.includes('?sessionId=')) return Promise.resolve(response([]));
    if (url === '/api/security-scanner/scans') return Promise.resolve(response({ id: 'initial' }));
    return Promise.resolve(response(scan));
  });
  app.session('older'); await settle();
  app.nodes.get('experience-mode').value = 'advanced'; app.nodes.get('security-auto-fix').checked = true;
  app.nodes.get('security-scan-form').dispatchEvent(new Event('submit', { cancelable: true })); await settle();
  assert.equal(typeof release, 'function');
  assert.deepEqual(JSON.parse(calls.find(call => call.url.endsWith('/apply')).options.body), { policy: { autoApply: true, rules: ['TL-DEBUG-ENABLED'] } });
  assert.equal(app.nodes.get('security-auto-fix').checked, false, 'automatic authorization applies to this one scan only');
  app.session('current'); await settle();
  release(response({ scan: { ...scan, id: 'rescanned', findings: [] } })); await settle();
  assert.equal(app.nodes.get('security-scan-start').disabled, false);
  assert.equal(app.nodes.get('security-status').textContent, 'No scan selected in this workspace.');
  assert.equal(app.nodes.get('security-source').textContent, '/repos/current');
  assert.equal(calls.filter(call => call.url.endsWith('/apply')).length, 1);
});

test('scan cancellation waits for terminal evidence and never becomes a clean result', async () => {
  let release, cancelled = false;
  const app = fixture((url) => {
    if (url.endsWith('/cancel')) { cancelled = true; return Promise.resolve(response({ ok: true })); }
    if (url.includes('?sessionId=')) return Promise.resolve(response([]));
    if (url === '/api/security-scanner/scans') return Promise.resolve(response({ id: 'initial' }));
    return new Promise(resolve => { release = resolve; });
  });
  app.session('fixture'); await settle();
  app.nodes.get('security-scan-form').dispatchEvent(new Event('submit', { cancelable: true })); await settle();
  assert.equal(app.nodes.get('security-scan-cancel').hidden, false);
  app.nodes.get('security-scan-cancel').dispatchEvent(new Event('click')); await settle();
  assert.equal(cancelled, true); assert.equal(app.nodes.get('security-scan-start').disabled, true);
  release(response({ status: 'cancelled', error: 'Scan cancelled. No clean result is claimed.' })); await settle();
  assert.equal(app.nodes.get('security-scan-cancel').hidden, true);
  assert.equal(app.nodes.get('security-scan-start').disabled, false);
  assert.match(app.nodes.get('security-status').textContent, /cancelled.*No clean result/);
});
