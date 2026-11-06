'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { it } = require('node:test');

// Small DOM seam tests the actual browser module's state machine without a browser dependency.
class Node extends EventTarget {
  constructor() { super(); this.children = []; this.textContent = ''; this.disabled = false; this.classes = new Set(); this.classList = { add: name => this.classes.add(name) }; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  setAttribute(name, value) { this[name] = value; }
  click() { this.dispatchEvent(new Event('click')); }
}
class DetailEvent extends Event { constructor(name, init = {}) { super(name); this.detail = init.detail; } }
const settle = () => new Promise(resolve => setImmediate(resolve));

function fixture(fetch) {
  const nodes = new Map(['add-design-inputs', 'design-input-files', 'design-input-list', 'design-inputs-note', 'design-inputs-expiry'].map(id => [id, new Node()]));
  const document = new EventTarget();
  document.getElementById = id => nodes.get(id);
  document.createElement = () => new Node();
  const window = {};
  class FileReader {
    readAsDataURL(file) { this.result = `data:text/plain;base64,${Buffer.from(file.content || 'fixture').toString('base64')}`; this.onload(); }
  }
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../public/design-inputs.js'), 'utf8'), { document, window, FileReader, fetch, CustomEvent: DetailEvent });
  document.dispatchEvent(new Event('DOMContentLoaded'));
  const pick = files => { const input = nodes.get('design-input-files'); input.files = files; input.dispatchEvent(new Event('change')); };
  return { document, nodes, pick, api: window.ThreatlintDesignInputs };
}
const summary = name => ({ name, kind: 'Markdown document', chars: 7, truncated: 0, sha256: 'a'.repeat(64) });

it('disables add/remove while extracting and during a review, and publishes busy transitions', async () => {
  let finish;
  const f = fixture(() => new Promise(resolve => { finish = resolve; }));
  const changes = [];
  f.document.addEventListener('threatlint:design-inputs', () => changes.push(f.api.busy()));
  f.pick([{ name: 'architecture.md', size: 7 }]);
  await settle();
  assert.equal(f.api.busy(), true);
  assert.equal(f.nodes.get('add-design-inputs').disabled, true);
  assert.equal(f.nodes.get('design-input-files').disabled, true);
  finish({ ok: true, json: async () => ({ id: 'bundle-1', files: [summary('architecture.md')], expiresAt: Date.now() + 1000 }) });
  await settle();
  assert.deepEqual(changes, [true, false]);
  assert.equal(f.api.id(), 'bundle-1');
  const remove = () => f.nodes.get('design-input-list').children[0].children.at(-1);
  f.api.setLocked(true);
  assert.equal(remove().disabled, true);
  await f.api.clear();
  assert.equal(f.api.id(), 'bundle-1', 'even a programmatic clear cannot alter active review context');
  f.api.setLocked(false);
  assert.equal(remove().disabled, false);
});

it('preserves the previous bundle when extraction fails and deletes it only after a successful replacement', async () => {
  let uploads = 0;
  const deletes = [];
  const f = fixture(async (url, options) => {
    if (options.method === 'DELETE') { deletes.push(url); return { ok: true }; }
    uploads++;
    return uploads === 2 ? { ok: false, json: async () => ({ error: 'Duplicate design input name' }) }
      : { ok: true, json: async () => ({ id: `bundle-${uploads}`, files: [summary('architecture.md')] }) };
  });
  f.pick([{ name: 'architecture.md', size: 7 }]); await settle();
  f.pick([{ name: 'architecture.md', size: 7 }]); await settle();
  assert.equal(f.api.id(), 'bundle-1');
  assert.deepEqual(deletes, []);
  await f.api.clear();
  assert.equal(f.api.id(), null);
  assert.deepEqual(deletes, ['/api/design-inputs/bundle-1']);
});

it('rejects empty and oversized files before encoding or uploading', async () => {
  let requests = 0;
  const f = fixture(async () => { requests++; throw new Error('must not upload'); });
  for (const file of [{ name: 'empty.md', size: 0 }, { name: 'large.md', size: 10 * 1024 * 1024 + 1 }, { name: 'photo.png', size: 5 * 1024 * 1024 + 1 }]) {
    f.pick([file]); await settle();
    assert.equal(f.api.busy(), false);
    assert.equal(f.api.id(), null);
  }
  assert.equal(requests, 0);
});
