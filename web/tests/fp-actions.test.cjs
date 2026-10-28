'use strict';
// Never read the developer's saved ~/.threatlint config.
process.env.THREATLINT_HOME = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'threatlint-home-'));
// Deterministic Word export: a stub "python" that writes the .docx argument.
const stubDir = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'threatlint-docx-'));
const stub = require('node:path').join(stubDir, process.platform === 'win32' ? 'docx.cmd' : 'docx');
require('node:fs').writeFileSync(stub, process.platform === 'win32' ? '@echo PK-docx> %3\r\n' : '#!/bin/sh\nprintf PK-docx > "$3"\n', { mode: 0o755 });
// Node will not execFile a .cmd (CVE-2024-27980), so Windows converts with the real python-docx instead.
if (process.platform !== 'win32') process.env.THREATLINT_PYTHON = stub;
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { WebSocket } = require('ws');
const { createWorkbench } = require('../server.js');
const { closeAvitAsFalsePositive } = require('../lib/servicenow.cjs');
const { matchFindings, ignoreAsFalsePositive, validateTarget } = require('../lib/semgrep-cloud.cjs');
const { avitFor } = require('../lib/routes/triage.cjs');

const INSTANCE = 'https://example.service-now.com';
const SYS_ID = 'a'.repeat(32);
const json = body => ({ ok: true, status: 200, json: async () => body });
const CREDENTIALS = { instance: INSTANCE, clientId: 'id', clientSecret: 'secret' };
const CHOICES = [
  { name: 'task', element: 'state', value: '3', label: 'Closed Complete' },
  { name: 'sn_vul_app_vulnerable_item', element: 'state', value: '3', label: 'Closed' },
  { name: 'sn_vul_app_vulnerable_item', element: 'substate', value: '6', label: 'False Positive' },
];

function fakeServiceNow(calls, { storedState = '3', inView = true } = {}) {
  return async (url, options = {}) => {
    calls.push({ url, options });
    if (url.endsWith('/oauth_token.do')) return json({ access_token: 'snow-token' });
    if (url.includes('/api/now/table/sys_choice')) return json({ result: CHOICES });
    if (url.includes('/api/now/attachment/file')) return json({ result: { sys_id: 'b'.repeat(32) } });
    if (options.method === 'PATCH') return json({ result: { number: 'AVIT000000000010001', state: storedState, substate: '3' } });
    if (url.includes('/sysrule_view')) return json({ result: [{ condition: 'u_scm_toolISNOTEMPTY' }] });
    if (url.includes('u_scm_toolISNOTEMPTY')) return json({ result: inView ? [{ number: 'AVIT000000000010001' }] : [] });
    if (url.includes('/api/now/table/sn_vul_app_vulnerable_item')) return json({ result: [{ sys_id: { value: SYS_ID, display_value: SYS_ID }, number: { value: 'AVIT000000000010001' }, state: { value: '1' }, u_scm_tool: { display_value: 'ADO' }, u_repository: { display_value: 'web' } }] });
    throw new Error(`unexpected ${url}`);
  };
}

const SEMGREP_FINDINGS = [
  { id: 101, rule_name: 'javascript.express.security.audit.xss.direct-response-write', location: { file_path: 'src/routes/view.js', line: 42 }, ref: 'main', status: 'open' },
  { id: 102, rule_name: 'javascript.express.security.audit.xss.direct-response-write', location: { file_path: 'src/routes/other.js', line: 42 }, ref: 'main', status: 'open' },
  { id: 103, rule_name: 'javascript.lang.security.audit.other-rule', location: { file_path: 'src/routes/view.js', line: 42 }, ref: 'main', status: 'open' },
];
function fakeSemgrep(calls) {
  return async (url, options = {}) => {
    calls.push({ url, options });
    if (url.endsWith('/api/v1/deployments')) return json({ deployments: [{ id: 1, slug: 'acme', name: 'Acme' }] });
    if (url.includes('/findings?')) return json({ findings: SEMGREP_FINDINGS });
    if (url.endsWith('/triage')) { const body = JSON.parse(options.body); return json({ num_triaged: body.issue_ids.length, triaged_issues: body.issue_ids }); }
    throw new Error(`unexpected ${url}`);
  };
}

describe('Closing an AVIT as a false positive', () => {
  it('attaches the report before closing, adds the Threatlint note, and uses the Closed / False Positive choices', async () => {
    const calls = [];
    const result = await closeAvitAsFalsePositive(CREDENTIALS, 'avit000000000010001', { note: 'Closed by Threatlint as a false positive.',
      files: [{ name: 'AVIT000000000010001-threatlint-fp-review.docx', content: Buffer.from('PK-docx'), type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' }] }, { fetchImpl: fakeServiceNow(calls) });
    assert.equal(result.closed, true);
    assert.equal(result.avit, 'AVIT000000000010001');
    const attach = calls.findIndex(call => call.url.includes('/api/now/attachment/file'));
    const patch = calls.findIndex(call => call.options.method === 'PATCH');
    assert.ok(attach > 0 && patch > attach, 'report is attached before the state change');
    assert.match(calls[attach].url, /table_name=sn_vul_app_vulnerable_item/); assert.match(calls[attach].url, /file_name=AVIT000000000010001-threatlint-fp-review\.docx/);
    assert.match(calls[attach].url, new RegExp(`table_sys_id=${SYS_ID}`));
    assert.ok(calls[patch].url.includes(`/api/now/table/sn_vul_app_vulnerable_item/${SYS_ID}`));
    const update = JSON.parse(calls[patch].options.body);
    assert.deepEqual({ state: update.state, substate: update.substate }, { state: '3', substate: '3' });
    assert.match(update.work_notes, /Closed by Threatlint/);
    assert.ok(calls.every(call => call.options.redirect === 'error'));
  });
  it('reports a closure ServiceNow did not apply instead of claiming success', async () => {
    const result = await closeAvitAsFalsePositive(CREDENTIALS, 'AVIT000000000010001', { note: 'n', files: [] }, { fetchImpl: fakeServiceNow([], { storedState: '1' }) });
    assert.equal(result.closed, false); assert.equal(result.state, '1');
  });
  it('closes AVITs outside the AVR CodeSecurity view too (no Semgrep step there)', async () => {
    const result = await closeAvitAsFalsePositive(CREDENTIALS, 'AVIT000000000010001', { note: 'n', files: [{ name: 'f.docx', content: Buffer.from('x'), type: 'application/octet-stream' }] },
      { fetchImpl: fakeServiceNow([], { inView: false }) });
    assert.equal(result.closed, true);
  });
  it('requires exactly one AVIT per finding', () => {
    assert.equal(avitFor({ id: 'FP-001', title: 't', body: '**Original finding**: AVIT000000000010001; rule.x.y' }), 'AVIT000000000010001');
    assert.throws(() => avitFor({ id: 'FP-001', title: 't', body: '**Original finding**: AVIT000000000010001, AVIT000000000010002' }), /several AVITs/);
    assert.throws(() => avitFor({ id: 'FP-001', title: 't', body: 'no reference' }), /does not reference/);
  });
});

describe('Semgrep false-positive tuning', () => {
  it('matches only the same rule, project, and file', async () => {
    const calls = [];
    const target = validateTarget({ rule: 'xss.direct-response-write', repo: 'acme/web', path: './src/routes/view.js', line: 41 });
    const { deployment, matches } = await matchFindings('token', target, { fetchImpl: fakeSemgrep(calls) });
    assert.equal(deployment.slug, 'acme');
    assert.deepEqual(matches.map(match => match.id), [101]);
    assert.match(calls[1].url, /repos=acme%2Fweb/); assert.match(calls[1].url, /status=open/);
    assert.equal(calls[1].options.headers.Authorization, 'Bearer token');
  });
  it('ignores the confirmed IDs as false_positive with a note', async () => {
    const calls = [];
    const result = await ignoreAsFalsePositive('token', 'acme', [101], 'False positive per Threatlint', { fetchImpl: fakeSemgrep(calls) });
    assert.equal(result.triaged, 1);
    assert.deepEqual(JSON.parse(calls[0].options.body), { issue_type: 'sast', issue_ids: [101], new_triage_state: 'ignored', new_triage_reason: 'false_positive', new_note: 'False positive per Threatlint' });
  });
  it('rejects targets that are too broad to tune safely', () => {
    assert.throws(() => validateTarget({ rule: 'x', repo: 'acme/web', path: 'a.js' }), /rule ID/);
    assert.throws(() => validateTarget({ rule: 'a.b.c', repo: 'acme/web', path: '' }), /file path/);
    assert.throws(() => validateTarget({ rule: 'a.b.c', repo: 'acme/web', path: '../etc/passwd' }), /file path/);
  });
});

describe('False-positive action routes', () => {
  const report = ['# FP Review', '', '## TIER 1 — EXECUTIVE SUMMARY', 'Two findings.', '', '## TIER 2 — DETAILED FINDINGS', '',
    '#### [FP-001] — Escaped template output flagged as XSS', '**Original finding**: AVIT000000000010001; xss.direct-response-write; src/routes/view.js:42',
    '**Disposition**: FALSE POSITIVE', '**Severity**: LOW', '**Confidence**: CONFIRMED', '**Evidence**: src/routes/view.js:42 — escaped', 'Blast radius: one rule.', '',
    '#### [FP-002] — Real injection', '**Original finding**: AVIT000000000010002', '**Disposition**: TRUE POSITIVE', '**Severity**: HIGH', '**Confidence**: CONFIRMED',
    '**Evidence**: src/routes/view.js:50', '### Proposed Fix', 'x', '### Regression Tests', 'acceptance', ''].join('\n');
  let instance, base, root, storage, reportId;
  const snowCalls = [], semgrepCalls = [];
  before(async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-triage-repo-'));
    storage = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-triage-store-'));
    const snow = fakeServiceNow(snowCalls), sg = fakeSemgrep(semgrepCalls);
    instance = createWorkbench({ storageDir: storage, runProvider: async args => { args.onEvent({ type: 'text_chunk', text: report }); return report; },
      integrations: { semgrepVersion: async () => '1.99.0', semgrepToken: async () => 'sg-token',
        fetchImpl: (url, options) => (url.startsWith('https://semgrep.dev') ? sg : snow)(url, options) } });
    await new Promise(resolve => instance.server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${instance.server.address().port}`;
    const { sessionId } = await post('/api/session/local', { repoPath: root });
    const socket = new WebSocket(base.replace('http:', 'ws:'), { origin: base });
    await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
    reportId = await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('FP review fixture did not complete')), 15_000);
      socket.on('message', raw => {
        const event = JSON.parse(raw);
        if (event.type === 'agent_complete') { clearTimeout(timeout); resolve(event.report.id); }
        if (event.type === 'error' || event.type === 'agent_error') { clearTimeout(timeout); reject(new Error(event.message)); }
      });
      socket.send(JSON.stringify({ action: 'run_pipeline', sessionId, agentIds: ['appsec-fp-reviewer'], provider: 'lmstudio', model: 'test-fixture', target: 'findings in repo' }));
    });
    socket.close();
  });
  after(async () => { await instance.close(); fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(storage, { recursive: true, force: true }); });
  async function post(route, payload) {
    const response = await fetch(base + route, { method: 'POST', body: JSON.stringify(payload), headers: { 'Content-Type': 'application/json' } });
    const body = await response.json();
    return response.ok ? body : Object.assign(new Error(body.error), { status: response.status });
  }

  it('closes the AVIT with the report attached under an AVIT-prefixed name', async () => {
    const result = await post('/api/servicenow/close-false-positive', { reportId, findingId: 'FP-001', servicenow: CREDENTIALS });
    assert.equal(result.closed, true);
    assert.deepEqual(result.attachments.map(item => item.name), ['AVIT000000000010001-threatlint-fp-review.docx'], 'only the Word report');
    const patch = snowCalls.find(call => call.options.method === 'PATCH');
    assert.equal(JSON.parse(patch.options.body).work_notes, 'Closed by Threatlint as a false positive, see attached report.');
  });
  it('refuses findings that are not FALSE POSITIVE', async () => {
    const error = await post('/api/servicenow/close-false-positive', { reportId, findingId: 'FP-002', servicenow: CREDENTIALS });
    assert.equal(error.status, 400); assert.match(error.message, /TRUE POSITIVE, not FALSE POSITIVE/);
  });
  it('ignores only Semgrep findings inside the narrow match, even if other IDs are sent', async () => {
    const target = { rule: 'xss.direct-response-write', repo: 'acme/web', path: 'src/routes/view.js', line: 42 };
    const preview = await post('/api/semgrep/false-positive/matches', { reportId, findingId: 'FP-001', target });
    assert.deepEqual(preview.matches.map(match => match.id), [101]);
    const result = await post('/api/semgrep/false-positive/ignore', { reportId, findingId: 'FP-001', target: { ...target, deployment: 'acme' }, issueIds: [101, 102, 103] });
    assert.deepEqual(result.issueIds, [101]);
    const triage = JSON.parse(semgrepCalls.findLast(call => call.url.endsWith('/triage')).options.body);
    assert.deepEqual(triage.issue_ids, [101]); assert.match(triage.new_note, /FP-001 \(ServiceNow AVIT000000000010001\)/);
  });
});
