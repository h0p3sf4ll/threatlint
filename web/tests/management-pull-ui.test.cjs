'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Node extends EventTarget {
  constructor(tag = 'div') {
    super(); this.tagName = tag.toUpperCase(); this.children = []; this.value = ''; this.dataset = {};
    this.disabled = false; this.hidden = false; this.checked = false; this._text = '';
    this.classList = { add() {}, remove() {}, toggle() {} };
  }
  get textContent() { return this._text + this.children.map(child => typeof child === 'string' ? child : child.textContent).join(''); }
  set textContent(value) { this._text = String(value); this.children = []; }
  append(...values) { this.children.push(...values); }
  replaceChildren(...values) { this._text = ''; this.children = values; }
  setAttribute(name, value) { this[name] = String(value); }
  querySelectorAll(selector) {
    const tags = selector.split(',').map(value => value.trim().toUpperCase());
    return this.children.flatMap(child => typeof child === 'string' ? [] : [...(tags.includes(child.tagName) ? [child] : []), ...child.querySelectorAll(selector)]);
  }
  before() {}
  reset() {}
  showModal() { this.open = true; }
  close() { this.open = false; }
  scrollIntoView() { this.scrolled = true; }
  click() { if (!this.disabled) this.dispatchEvent(new Event('click')); }
}
class DetailEvent extends Event { constructor(name, init = {}) { super(name); this.detail = init.detail; } }
const settle = () => new Promise(resolve => setImmediate(resolve));
const plain = value => JSON.parse(JSON.stringify(value));
const tracker = (id, provider = 'github-issues', extra = {}) => ({ id, name: `${id} source`, kind: 'tracker', provider, available: true, enabled: true, ...extra });
const providers = ['jira', 'azure-boards', 'github-issues', 'servicenow-avit'].map(id => ({ id, label: id, kind: 'tracker', ...(id === 'servicenow-avit' ? { pullOnly: true } : {}) }));

async function fixture({ sources = [tracker('github')], permissions = { manageFindings: true, manageSettings: true, review: true }, onPull, onFetch } = {}) {
  const nodes = new Map(), requests = [], saved = new Map();
  const node = id => { if (!nodes.has(id)) nodes.set(id, new Node()); return nodes.get(id); };
  const old = { id: 'saved-old', connectionId: 'github', provider: 'github-issues', externalId: 'OLD-1', title: 'Previously saved issue', state: 'Open', url: 'https://example.test/old' };
  saved.set(old.id, old);
  const document = new EventTarget();
  Object.assign(document, { getElementById: node, createElement: tag => new Node(tag), querySelectorAll: () => [], querySelector: () => null, body: new Node('body') });
  node('management-pull-state').value = 'all';
  node('management-avit-form').entries = [['scm', 'github'], ['state', '101'], ['riskRating', '1'], ['project', 'not-applicable'], ['repository', 'example/repo']];
  const fetch = async (url, options = {}) => {
    const request = { url, ...options, ...(options.body ? { body: JSON.parse(options.body) } : {}) }; requests.push(request);
    let payload, status = 200;
    const override = await onFetch?.(request);
    if (override) ({ payload, status = 200 } = override);
    else if (url === '/api/management/issue-sources') payload = { sources, providers };
    else if (url === '/api/access') payload = { role: permissions.manageSettings ? 'administrator' : 'viewer', permissions };
    else if (url === '/api/management/findings') payload = { findings: [...saved.values()], connections: sources };
    else if (url === '/api/management/findings/pull') {
      const output = await onPull?.(request.body.sources, { saved, requests });
      if (output) ({ payload, status = 200 } = output);
      else {
        const results = request.body.sources.map(source => {
          const metadata = sources.find(item => item.id === source.connectionId);
          const finding = { id: `${source.connectionId}:${source.cursor || 'first'}`, connectionId: source.connectionId, provider: metadata.provider, externalId: `${source.connectionId}-1`, title: 'Pulled issue', state: 'Open', issueType: source.filters.issueType, url: 'https://example.test/issues/1' };
          saved.set(finding.id, finding);
          return { connectionId: source.connectionId, provider: metadata.provider, imported: 1, nextCursor: null };
        });
        payload = { findings: [...saved.values()], sources: results };
      }
    } else if (url === '/api/management/connections') payload = { connections: sources, providers };
    else throw new Error(`Unexpected fixture endpoint ${url}`);
    return { status, ok: status >= 200 && status < 300, json: async () => payload };
  };
  const window = { ThreatlintProfile: { fetch } };
  const context = vm.createContext({ document, window, fetch, URL, URLSearchParams, CustomEvent: DetailEvent, Event,
    FormData: class { constructor(form) { this.entries = form.entries; } [Symbol.iterator]() { return this.entries[Symbol.iterator](); } },
    location: { replace() {} }, console, setTimeout, clearTimeout });
  const source = fs.readFileSync(path.join(__dirname, '../public/management.js'), 'utf8');
  const bootstrap = '  initializeAvits();\n  await loadAccess();';
  assert.equal(source.split(bootstrap).length, 2, 'only the unrelated initial AVIT form clone is skipped');
  const prefix = source.slice(0, source.indexOf(bootstrap));
  vm.runInContext(`${prefix}  window.managementFixture = { state, issuePull, loadIssueSources, loadFindings, loadAccess, pullIssues, invalidateIssuePull, renderFindings, renderConnections, trackerConnections, openConnection, openTicket, safeLink, syncFindings };\n})();`, context);
  await settle();
  const app = window.managementFixture;
  await app.loadAccess();
  return { app, node, requests, saved, sources, document };
}

it('loads available saved sources, offers only relevant type overrides, and keeps incomplete ServiceNow unselectable', async () => {
  const f = await fixture({ sources: [tracker('jira', 'jira', { issueType: 'Security task' }), tracker('ado', 'azure-boards', { issueType: 'Custom risk' }), tracker('github'), tracker('servicenow-avit', 'servicenow-avit', { available: false, credentialSource: 'servicenow-settings', pullOnly: true, error: 'Configure ServiceNow in Settings.' })] });
  f.node('management-pull-refresh').click(); await settle();
  assert.equal(f.app.issuePull.sources.length, 4);
  assert.equal(f.app.issuePull.controls.filter(control => control.type).length, 2);
  assert.match(f.node('management-pull-sources').textContent, /uses ServiceNow Settings/);
  const snow = f.app.issuePull.controls.find(control => control.source.id === 'servicenow-avit');
  assert.equal(snow.checkbox.disabled, true);
  f.node('management-pull-all').click();
  assert.deepEqual([...f.app.issuePull.selected], ['jira', 'ado', 'github']);
  assert.equal(f.node('management-pull-start').disabled, false);
  assert.equal(f.node('management-pull-snow-note').hidden, true);
  assert.equal(f.node('management-pull-sources').querySelectorAll('input').some(input => input.type === 'password'), false);
});

it('pulls multiple selected sources into the existing inbox with exact user types and independent ServiceNow filters', async () => {
  const f = await fixture({ sources: [tracker('jira', 'jira', { issueType: 'Task' }), tracker('ado', 'azure-boards', { issueType: 'Bug' }), tracker('github'), tracker('servicenow-avit', 'servicenow-avit', { credentialSource: 'servicenow-settings', pullOnly: true })] });
  await f.app.loadIssueSources(); f.node('management-pull-all').click();
  const jira = f.app.issuePull.controls.find(control => control.source.id === 'jira');
  jira.type.value = '  Custom security finding  '; jira.type.dispatchEvent(new Event('input'));
  f.node('management-pull-state').value = 'closed'; f.node('management-pull-state').dispatchEvent(new Event('change'));
  f.node('management-pull-start').click(); await settle(); await settle();
  const pull = f.requests.find(request => request.url.endsWith('/pull'));
  assert.deepEqual(pull.body.sources, [
    { connectionId: 'jira', filters: { state: 'closed', issueType: 'Custom security finding' } },
    { connectionId: 'ado', filters: { state: 'closed', issueType: 'Bug' } },
    { connectionId: 'github', filters: { state: 'closed' } },
    { connectionId: 'servicenow-avit', filters: { scm: 'github', state: '101', riskRating: '1', repository: 'example/repo' } },
  ]);
  assert.equal(f.app.state.findings.length, 5, 'previously saved findings remain alongside pulled issues');
  assert.match(f.node('management-findings').textContent, /Previously saved issue/);
  assert.match(f.node('management-findings').textContent, /Custom security finding/);
  assert.equal(f.node('management-pull-status').textContent, 'Pull finished. Issues are saved in the inbox.');
  assert.equal(f.node('management-pull-start').disabled, false);
  const snowCard = f.node('management-findings').children.find(card => card.textContent.includes('servicenow-avit-1'));
  assert.equal(snowCard.querySelectorAll('button').length, 0, 'pull-only records never offer closure');
});

it('keeps successful rows on partial failure and retries the identical failed pagination cursor', async () => {
  let pageAttempts = 0;
  const f = await fixture({ sources: [tracker('github'), tracker('jira', 'jira', { issueType: 'Risk' })], onPull: async (requests, { saved }) => {
    const results = requests.map(request => {
      if (request.connectionId === 'jira') return { connectionId: 'jira', error: 'The source could not be reached.', imported: 0 };
      if (request.cursor && ++pageAttempts === 1) return { connectionId: 'github', error: 'This page could not be loaded.', imported: 0 };
      saved.set(request.cursor || 'first-page', { id: request.cursor || 'first-page', connectionId: 'github', provider: 'github-issues', externalId: request.cursor ? 'GH-2' : 'GH-1', title: 'Saved source issue', state: 'Open' });
      return { connectionId: 'github', imported: 1, nextCursor: request.cursor ? null : 'opaque.signed/cursor+=1' };
    });
    return { payload: { findings: [...saved.values()], sources: results } };
  } });
  await f.app.loadIssueSources(); f.node('management-pull-all').click(); await f.app.pullIssues();
  assert.equal(f.app.state.findings.length, 2);
  assert.match(f.node('management-pull-status').textContent, /1 source needs attention/);
  assert.match(f.node('management-pull-results').textContent, /Retry source/);
  await f.app.pullIssues({ more: 'github' });
  assert.equal(f.app.state.findings.length, 2);
  await f.app.pullIssues({ retry: 'github' });
  assert.equal(f.app.state.findings.length, 3);
  const pages = f.requests.filter(request => request.url.endsWith('/pull')).slice(1);
  assert.deepEqual(pages[0].body, pages[1].body);
  assert.equal(pages[1].body.sources[0].cursor, 'opaque.signed/cursor+=1');
  assert.deepEqual(pages[1].body.sources[0].filters, { state: 'all' });
  f.node('management-pull-state').value = 'open'; f.node('management-pull-state').dispatchEvent(new Event('change'));
  assert.equal(f.app.issuePull.results.size, 0, 'changing filters removes stale pagination controls');
  await f.app.pullIssues({ more: 'github' });
  assert.equal(f.requests.filter(request => request.url.endsWith('/pull')).length, 3);
});

it('batches at most ten sources and preserves successful inbox rows when a later batch fails', async () => {
  const sources = Array.from({ length: 12 }, (_, index) => tracker(`source-${index}`));
  const f = await fixture({ sources, onPull: async requests => requests[0].connectionId === 'source-10' ? { status: 502, payload: { error: 'These sources could not be reached.' } } : undefined });
  await f.app.loadIssueSources(); f.node('management-pull-all').click(); await f.app.pullIssues();
  assert.deepEqual(f.requests.filter(request => request.url.endsWith('/pull')).map(request => request.body.sources.length), [10, 2]);
  assert.equal(f.app.state.findings.length, 11);
  assert.equal([...f.app.issuePull.results.values()].filter(result => result.error).length, 2);
  assert.match(f.node('management-pull-status').textContent, /successful issues are saved/);
});

it('retains the displayed inbox on a failed refresh and stops further batches after a profile conflict', async () => {
  let failInbox = false;
  const f = await fixture({ sources: [tracker('github')], onFetch: request => failInbox && request.url === '/api/management/findings' ? { status: 502, payload: { error: 'Saved issues could not be refreshed.' } } : undefined });
  await f.app.loadIssueSources(); await f.app.loadFindings(); f.node('management-pull-all').click(); failInbox = true; await f.app.pullIssues();
  assert.equal(f.app.state.findings.length, 1);
  assert.match(f.node('management-findings').textContent, /Previously saved issue/);
  assert.match(f.node('management-pull-status').textContent, /previously shown issues remain visible/);
  const conflict = await fixture({ sources: Array.from({ length: 11 }, (_, index) => tracker(`source-${index}`)), onPull: () => ({ status: 409, payload: { error: 'Reload your account.' } }) });
  await conflict.app.loadIssueSources(); conflict.node('management-pull-all').click(); await conflict.app.pullIssues();
  assert.equal(conflict.requests.filter(request => request.url.endsWith('/pull')).length, 1);
  assert.equal(conflict.requests.some(request => request.url === '/api/management/findings'), false);
  assert.match(conflict.node('management-pull-status').textContent, /account changed/);
});

it('enforces viewer controls and keeps automatic ServiceNow out of legacy ticket and connection actions', async () => {
  const sources = [tracker('github'), tracker('servicenow-avit', 'servicenow-avit', { pullOnly: true, credentialSource: 'servicenow-settings' })];
  const viewer = await fixture({ sources, permissions: { manageFindings: false, manageSettings: false, review: false } });
  await viewer.app.loadIssueSources(); viewer.node('management-pull-all').click(); await viewer.app.pullIssues();
  assert.equal(viewer.app.issuePull.selected.size, 0); assert.equal(viewer.node('management-pull-start').disabled, true);
  assert.equal(viewer.app.issuePull.controls.every(control => control.checkbox.disabled), true);
  assert.equal(viewer.requests.some(request => request.url.endsWith('/pull')), false);
  const f = await fixture({ sources }); await f.app.loadIssueSources(); await f.app.loadFindings();
  assert.deepEqual(plain(f.app.trackerConnections()).map(source => source.id), ['github']);
  f.app.renderConnections(); assert.doesNotMatch(f.node('management-connections').textContent, /servicenow-avit source/);
  f.app.openConnection(sources[1]); await f.app.openTicket('close', { connectionId: 'servicenow-avit', provider: 'servicenow-avit' });
  assert.equal(f.node('management-connection-dialog').open, undefined); assert.equal(f.node('management-ticket-dialog').open, undefined);
  assert.equal(f.app.safeLink('javascript:alert(1)', '<img src=x>').tagName, 'SPAN');
  assert.equal(f.app.safeLink('https://secret@example.test/issues/1', 'Secret').tagName, 'SPAN');
  const safe = f.app.safeLink('https://example.test/issues/1', '<img src=x>'); assert.equal(safe.tagName, 'A'); assert.equal(safe.textContent, '<img src=x>'); assert.equal(safe.children.length, 0);
});

it('guides ServiceNow status refresh back to Pull issues and reports global read-only skips once', async () => {
  const sources = [tracker('github'), tracker('servicenow-avit', 'servicenow-avit', { pullOnly: true, credentialSource: 'servicenow-settings' })];
  const f = await fixture({ sources, onFetch: request => request.url.endsWith('/sync') ? { payload: { findings: [], errors: [], nextCursor: null, skippedReadOnly: 2 } } : undefined });
  await f.app.loadIssueSources(); f.node('management-tracker-filter').value = 'servicenow-avit'; await f.app.syncFindings(f.node('management-sync'));
  assert.equal(f.requests.some(request => request.url.endsWith('/sync')), false); assert.match(f.node('management-sync-status').textContent, /Use Pull issues/);
  f.node('management-tracker-filter').value = ''; await f.app.syncFindings(f.node('management-sync'));
  assert.match(f.node('management-sync-status').textContent, /2 ServiceNow AVIT records are refreshed with Pull issues/);
  assert.equal(f.node('management-findings-error').textContent, '');
});

it('filters saved ServiceNow issues by persisted instance rather than the temporary current-profile alias', async () => {
  const f = await fixture({ sources: [tracker('github'), tracker('servicenow-avit', 'servicenow-avit', { pullOnly: true, credentialSource: 'servicenow-settings' })] });
  await f.app.loadIssueSources();
  const connection = tracker('servicenow-avit-instance', 'servicenow-avit', { name: 'ServiceNow AVIT — example.service-now.com', pullOnly: true });
  f.app.state.connections = [tracker('github'), connection];
  f.app.state.findings = [{ id: 'SN-1', connectionId: connection.id, provider: 'servicenow-avit', title: 'Saved AVIT', externalId: 'AVIT001', state: 'Open' }];
  // Refresh through the actual endpoint so its filter-building path runs too.
  f.saved.set('SN-1', f.app.state.findings[0]);
  f.sources.splice(1, 1, connection);
  await f.app.loadFindings();
  const values = f.node('management-tracker-filter').children.map(option => option.value);
  assert.deepEqual(values, ['', 'github', 'servicenow-avit-instance']);
  f.node('management-tracker-filter').value = connection.id;
  f.node('management-tracker-filter').dispatchEvent(new Event('change'));
  assert.match(f.node('management-findings').textContent, /AVIT001 · Saved AVIT/);
  assert.doesNotMatch(f.node('management-findings').textContent, /Previously saved issue/);
});
