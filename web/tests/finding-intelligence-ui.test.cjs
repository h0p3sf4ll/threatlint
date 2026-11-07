'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Element extends EventTarget {
  constructor(tag = 'div') { super(); this.tagName = tag; this.children = []; this._text = ''; this.value = ''; this.hidden = false; this.checked = false; this.disabled = false; }
  get textContent() { return this._text + this.children.map(item => item.textContent).join(''); }
  set textContent(value) { this._text = String(value); this.children = []; }
  set innerHTML(_) { throw new Error('Untrusted HTML must not be rendered'); }
  append(...items) { this.children.push(...items); if (this.tagName === 'select' && !this.value) this.value = this.children[0]?.value || ''; }
  prepend(...items) { this.children.unshift(...items); }
  replaceChildren(...items) { this.children = items; this._text = ''; }
  setAttribute(name, value) { this[name] = value; }
  click() { this.dispatchEvent(new Event('click')); }
  remove() {}
}
class DetailEvent extends Event { constructor(name, input = {}) { super(name); this.detail = input.detail; } }
const settle = () => new Promise(resolve => setImmediate(resolve));
const descend = (root, predicate) => root.children.flatMap(item => [item, ...descend(item, predicate)]).filter(predicate);
function fixture(fetch) {
  const html = fs.readFileSync(path.join(__dirname, '../public/index.html'), 'utf8');
  const nodes = new Map([...html.matchAll(/id="([^"]+)"/g)].map(match => [match[1], new Element()]));
  nodes.get('view-metrics').hidden = true;
  const document = new EventTarget(); document.readyState = 'loading'; document.body = new Element('body');
  document.getElementById = id => nodes.get(id); document.createElement = tag => new Element(tag);
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../public/finding-intelligence.js'), 'utf8'), { document, fetch, CustomEvent: DetailEvent, setTimeout, URL, Blob });
  document.dispatchEvent(new Event('DOMContentLoaded'));
  const session = id => document.dispatchEvent(new DetailEvent('threatlint:context', { detail: { session: id ? { id, repoPath: `/repos/${id}` } : null } }));
  return { nodes, document, session };
}
function overview(title = 'Fixture finding', evidence = []) {
  const finding = { id: 'fi_fixture', title, severity: 'MEDIUM', disposition: 'TRUE POSITIVE', reportedDisposition: 'OPEN',
    provenance: { repo: { id: '/repos/fixture', name: 'fixture' }, branch: 'main', commit: 'abc123', contentDigest: 'digest' }, evidence, reviewHistory: [] };
  return { summary: { findings: 1, open: 1, high: 0, critical: 0, verifiedRemediated: 0, openRiskPoints: 3 }, findings: [finding], revisionFindings: [finding], repositories: [], composites: [], trends: [] };
}
const response = data => ({ ok: true, json: async () => data });

it('discards an old workspace response and renders repository text without HTML sinks', async () => {
  const pending = [];
  const app = fixture((url, options) => new Promise(resolve => pending.push({ url, options, resolve })));
  app.session('older'); app.session('current');
  assert.equal(JSON.parse(pending[0].options.body).sessionId, 'older');
  assert.equal(JSON.parse(pending[1].options.body).sessionId, 'current');
  const hostileText = '<img src=x onerror=alert(1)> reviewed finding';
  pending[1].resolve(response({ overview: overview(hostileText) })); await settle();
  assert.ok(app.nodes.get('intelligence-findings').textContent.includes(hostileText));
  pending[0].resolve(response({ overview: overview('Old workspace finding') })); await settle();
  assert.ok(!app.nodes.get('intelligence-findings').textContent.includes('Old workspace finding'));
  app.session(null);
  assert.equal(app.nodes.get('intelligence-findings').children.length, 0);
});

it('requires an explicit review attestation and submits new evidence tied to the active session', async () => {
  const calls = [];
  const app = fixture(async (url, options) => { calls.push({ url, options }); return response(url.endsWith('/sync') ? { overview: overview() } : url.includes('/reviews') ? {} : overview()); });
  app.session('fixture'); await settle();
  const form = descend(app.nodes.get('intelligence-findings'), item => item.tagName === 'form')[0];
  form.dispatchEvent(new Event('submit', { cancelable: true })); await settle();
  assert.equal(calls.length, 1, 'no review occurs without independent attestation');
  const attest = descend(form, item => item.tagName === 'input' && item.type === 'checkbox')[0]; attest.checked = true;
  const inputFor = label => descend(form, item => item.tagName === 'label' && item._text === label)[0].children[0];
  inputFor('Decision').value = 'TRUE POSITIVE'; inputFor('Evidence purpose').value = 'source';
  inputFor('Evidence path or reference').value = 'src/orders.js'; inputFor('New evidence quote / observed result').value = 'store.read(id)';
  inputFor('How you verified this evidence').value = 'Read the route and all callers.';
  inputFor('Decision basis').value = 'No ownership guard.'; inputFor('Decision rationale and limits').value = 'The direct caller exposes the read.';
  form.dispatchEvent(new Event('submit', { cancelable: true })); await settle();
  const review = calls.find(call => call.url.includes('/reviews'));
  const body = JSON.parse(review.options.body);
  assert.equal(body.sessionId, 'fixture'); assert.equal(body.newEvidence[0].verification, 'verified');
  assert.equal(body.newEvidence[0].verificationMethod, 'Read the route and all callers.');
  assert.deepEqual(body.basis[0].evidenceIds, [0]);
});

it('removes a private coaching result when consent is withdrawn during the preview request', async () => {
  let complete;
  const data = overview('My issue', [{ id: 'ev_intro', path: 'src/orders.js', line: 1, kind: 'introduction', quote: 'Inspected the introducing change.', verification: 'verified' }]);
  const app = fixture((url) => url.endsWith('/sync') ? Promise.resolve(response({ overview: data })) : new Promise(resolve => { complete = resolve; }));
  app.session('fixture'); await settle();
  app.nodes.get('coaching-opt-in').checked = true; app.nodes.get('coaching-sample').value = '10';
  descend(app.nodes.get('coaching-findings'), item => item.tagName === 'input' && item.type === 'checkbox')[0].checked = true;
  app.nodes.get('coaching-form').dispatchEvent(new Event('submit', { cancelable: true }));
  app.nodes.get('coaching-opt-in').checked = false; app.nodes.get('coaching-opt-in').dispatchEvent(new Event('change'));
  complete(response({ score: 30, confidence: 'low', includedIssues: 1, observedChangeCount: 10, excluded: [], formula: 'fixture', improvementSteps: [], limitations: [] })); await settle();
  assert.equal(app.nodes.get('coaching-result').children.length, 0);
  assert.equal(app.nodes.get('coaching-status').textContent, '');
});

it('uses branch-scoped summaries and discards a slower response for a previously selected branch', async () => {
  const pending = [], data = overview('Whole repository finding');
  data.repositories = [{ repo: { name: 'fixture' }, branches: ['main', 'release'].map(branch => ({ branch, open: 1, notReobserved: 0, coverage: { status: 'partial', scope: 'fixture', limitations: [] } })) }];
  const app = fixture(url => url.endsWith('/sync') ? Promise.resolve(response({ overview: data })) : new Promise(resolve => pending.push({ url, resolve })));
  app.session('fixture'); await settle();
  const branch = app.nodes.get('intelligence-branch');
  branch.value = 'main'; branch.dispatchEvent(new Event('change'));
  branch.value = 'release'; branch.dispatchEvent(new Event('change'));
  assert.ok(pending[0].url.includes('branch=main')); assert.ok(pending[1].url.includes('branch=release'));
  const release = overview('Release finding'); release.summary.openRiskPoints = 6;
  pending[1].resolve(response(release)); await settle();
  pending[0].resolve(response(overview('Stale main finding'))); await settle();
  assert.ok(app.nodes.get('intelligence-findings').textContent.includes('Release finding'));
  assert.ok(!app.nodes.get('intelligence-findings').textContent.includes('Stale main finding'));
  assert.ok(app.nodes.get('intelligence-summary').textContent.includes('6Open priority points'));
  assert.ok(app.nodes.get('intelligence-status').textContent.includes('in release'));
});

it('does not restore findings from the previous scope when a branch request fails', async () => {
  const app = fixture(url => url.endsWith('/sync') ? Promise.resolve(response({ overview: overview('Previous branch finding') })) : Promise.resolve({ ok: false, json: async () => ({ error: 'Scope unavailable' }) }));
  app.session('fixture'); await settle();
  const branch = app.nodes.get('intelligence-branch'); branch.value = 'main'; branch.dispatchEvent(new Event('change')); await settle();
  assert.equal(app.nodes.get('intelligence-status').textContent, 'Scope unavailable');
  app.nodes.get('intelligence-disposition').dispatchEvent(new Event('change'));
  assert.equal(app.nodes.get('intelligence-findings').children.length, 0);
  assert.equal(app.nodes.get('chain-submit').disabled, true);
});

it('shows individual coaching factors and exclusions and requires a new preview after consent is renewed', async () => {
  const pending = [], data = overview('My issue', [{ id: 'ev_intro', path: 'src/orders.js', line: 1, kind: 'introduction', quote: 'Inspected the introducing change.', verification: 'verified' }]);
  const app = fixture(url => url.endsWith('/sync') ? Promise.resolve(response({ overview: data })) : new Promise(resolve => pending.push(resolve)));
  app.session('fixture'); await settle();
  const optIn = app.nodes.get('coaching-opt-in'), form = app.nodes.get('coaching-form');
  optIn.checked = true; app.nodes.get('coaching-sample').value = '10';
  const result = { score: 3, confidence: 'low', includedIssues: 1, observedChangeCount: 10, formula: 'fixture formula', improvementSteps: ['Add the ownership guard.'], limitations: [],
    excluded: [{ findingId: 'another', reason: 'No verified introduction evidence' }], details: [{ findingId: 'fi_fixture', severity: 'MEDIUM', severityWeight: 3,
      exposure: 'unknown', exposureFactor: 1, recurrenceFactor: 1, disposition: 'TRUE POSITIVE', remediationFactor: 1, points: 3, evidenceIds: ['ev_intro'], exposureEvidenceIds: [] }] };
  form.dispatchEvent(new Event('submit', { cancelable: true }));
  optIn.checked = false; optIn.dispatchEvent(new Event('change')); optIn.checked = true; optIn.dispatchEvent(new Event('change'));
  pending[0](response(result)); await settle();
  assert.equal(app.nodes.get('coaching-result').textContent, '', 'renewed consent cannot revive an earlier in-flight assessment');
  form.dispatchEvent(new Event('submit', { cancelable: true })); pending[1](response(result)); await settle();
  assert.match(app.nodes.get('coaching-result').textContent, /MEDIUM weight 3 × unknown exposure 1 × recurrence 1/);
  assert.match(app.nodes.get('coaching-result').textContent, /Introduction evidence: ev_intro/);
  assert.match(app.nodes.get('coaching-result').textContent, /Excluded another: No verified introduction evidence/);
  form.dispatchEvent(new Event('change'));
  assert.equal(app.nodes.get('coaching-result').textContent, '', 'changing the sample or evidence clears the stale preview');
});
