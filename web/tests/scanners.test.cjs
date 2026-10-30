'use strict';
// Never read the developer's saved ~/.threatlint config.
process.env.THREATLINT_HOME = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'threatlint-home-'));
for (const name of ['THREATLINT_DOJO_URL', 'THREATLINT_DOJO_TOKEN', 'THREATLINT_SONAR_URL', 'THREATLINT_SONAR_TOKEN']) delete process.env[name];
// Deterministic Word export: a stub "python" that writes the .docx argument.
const stubDir = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'threatlint-docx-'));
const stub = require('node:path').join(stubDir, process.platform === 'win32' ? 'docx.cmd' : 'docx');
require('node:fs').writeFileSync(stub, process.platform === 'win32' ? '@echo PK-docx> %3\r\n' : '#!/bin/sh\nprintf PK-docx > "$3"\n', { mode: 0o755 });
if (process.platform !== 'win32') process.env.THREATLINT_PYTHON = stub;
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { WebSocket } = require('ws');
const { createWorkbench } = require('../server.js');
const scanners = require('../lib/scanners.cjs');
const scan = require('../lib/scan-import.cjs');
const { filterArgs } = require('../lib/scanner-batch.cjs');
const servicenow = require('../lib/servicenow.cjs');

const DOJO = 'https://dojo.example.test', SONAR = 'https://sonar.example.test';
const FIXTURES = path.join(__dirname, 'fixtures/scan-import');
const fixture = name => fs.readFileSync(path.join(FIXTURES, name));
const reply = (body, status = 200) => ({ ok: status < 400, status, text: async () => (body === undefined ? '' : JSON.stringify(body)) });

/** DefectDojo + SonarQube fake: records method, path, headers and body; never reaches a network. */
function fakeServers(calls, { dojoFalseP = false } = {}) {
  return async (url, options = {}) => {
    const parsed = new URL(url);
    const method = options.method || 'GET';
    calls.push({ method, host: parsed.host, path: parsed.pathname, query: Object.fromEntries(parsed.searchParams), headers: options.headers || {}, body: options.body, redirect: options.redirect });
    if (parsed.host === 'dojo.example.test') {
      if (parsed.pathname === '/api/v2/findings/' && method === 'GET') return reply({ count: 0, results: [] });
      if (/^\/api\/v2\/findings\/9999\/$/.test(parsed.pathname)) return reply({ detail: 'Not found.' }, 404);
      if (/^\/api\/v2\/findings\/\d+\/files\/$/.test(parsed.pathname)) return method === 'GET' ? reply({ files: [] }) : reply({ id: 1 });
      if (/^\/api\/v2\/findings\/\d+\/notes\/$/.test(parsed.pathname)) return reply({ id: 2 });
      if (/^\/api\/v2\/findings\/\d+\/$/.test(parsed.pathname)) return method === 'PATCH' ? reply({ id: 1, ...JSON.parse(options.body) }) : reply({ id: 1, false_p: dojoFalseP, active: true });
    }
    if (parsed.host === 'sonar.example.test') {
      if (parsed.pathname === '/api/authentication/validate') return reply({ valid: options.headers.Authorization === `Basic ${Buffer.from('squ_valid_token_123:').toString('base64')}` });
      if (parsed.pathname === '/api/issues/do_transition') return new URLSearchParams(options.body).get('transition') === 'confirm' ? reply({ errors: [{ msg: 'Transition not allowed' }] }, 400) : reply({ issue: { resolution: 'FALSE-POSITIVE' } });
      if (['/api/issues/add_comment', '/api/hotspots/change_status', '/api/hotspots/add_comment'].includes(parsed.pathname)) return reply(undefined);
    }
    throw new Error(`unexpected ${method} ${url}`);
  };
}
const writes = calls => calls.filter(call => call.method !== 'GET').map(call => `${call.method} ${call.path}`);

describe('Scanner references and connection settings', () => {
  it('parses DefectDojo ids and SonarQube issue/hotspot keys', () => {
    assert.deepEqual(scanners.parseReferences('dojo', '123, DOJO-124 dojo:123'), ['DOJO-123', 'DOJO-124']);
    assert.deepEqual(scanners.parseReferences('sonar', 'AYxExampleKey01 hotspot-AYxExampleKey02'), ['SONAR-AYxExampleKey01', 'SONAR-HOTSPOT-AYxExampleKey02']);
    assert.throws(() => scanners.parseReferences('dojo', 'AVIT0042599'), /Not a DefectDojo finding id/);
    assert.throws(() => scanners.parseReferences('dojo', Array.from({ length: 51 }, (_, i) => String(i + 1))), /at most 50/);
    assert.equal(scanners.mentions('DOJO-1234; rule', 'DOJO-123'), false);
    assert.equal(scanners.mentions('DOJO-123; rule', 'DOJO-123'), true);
  });
  it('accepts only HTTPS base URLs and trims pasted API paths', () => {
    assert.equal(scanners.validateBaseUrl('https://Dojo.example.test/api/v2/findings/', 'dojo'), DOJO);
    assert.equal(scanners.validateBaseUrl('https://example.test/sonarqube/', 'sonar'), 'https://example.test/sonarqube');
    for (const bad of ['http://dojo.example.test', 'https://u:p@dojo.example.test', 'https://dojo.example.test/?a=1', 'not a url']) assert.throws(() => scanners.validateBaseUrl(bad, 'dojo'));
  });
  it('builds validated fetch filters and refuses an unscoped DefectDojo search', () => {
    assert.deepEqual(filterArgs('dojo', { product: '3', active: 'true', severity: ['High', 'Critical'], tags: 'pci, web', limit: 10 }),
      ['--product', '3', '--active', 'true', '--severity', 'High', '--severity', 'Critical', '--tag', 'pci', '--tag', 'web', '--limit', '10']);
    assert.throws(() => filterArgs('dojo', { active: 'true' }), /Narrow the DefectDojo search/);
    assert.throws(() => filterArgs('dojo', { product: '-1' }), /positive id/);
    assert.throws(() => filterArgs('sonar', { project: 'web', branch: '--upload-pack=x' }), /Not a valid branch/);
    assert.deepEqual(filterArgs('sonar', { project: 'web', branch: 'develop', types: ['SECURITY_HOTSPOT'] }), ['--project', 'web', '--branch', 'develop', '--type', 'SECURITY_HOTSPOT', '--limit', '50']);
    assert.deepEqual(filterArgs('sonar', {}), []);
  });
});

describe('Scanner write-back for imported reports', () => {
  const conn = { url: DOJO, token: 'dojo-token' };
  it('DefectDojo: attaches the Word report, notes, then marks a false positive inactive', async () => {
    const calls = [];
    const result = await scanners.resolveDojo(conn, 'DOJO-1201', { disposition: 'FALSE POSITIVE', files: [{ name: 'DOJO-1201-threatlint-fp-review.docx', content: Buffer.from('PK-docx'), type: scanners.DOCX_TYPE }] }, { fetchImpl: fakeServers(calls) });
    assert.deepEqual(writes(calls), ['POST /api/v2/findings/1201/files/', 'POST /api/v2/findings/1201/notes/', 'PATCH /api/v2/findings/1201/']);
    assert.ok(calls.every(call => call.redirect === 'error' && call.headers.Authorization === 'Token dojo-token'));
    const form = calls.find(call => call.method === 'POST' && call.path.endsWith('/files/')).body;
    assert.equal(form.get('title'), 'DOJO-1201-threatlint-fp-review.docx'); assert.equal(form.get('file').name, 'DOJO-1201-threatlint-fp-review.docx');
    assert.equal(JSON.parse(calls.find(call => call.path.endsWith('/notes/')).body).entry, servicenow.CLOSING_COMMENT);
    assert.deepEqual(JSON.parse(calls.find(call => call.method === 'PATCH').body), { false_p: true, active: false, verified: false });
    assert.equal(result.closed, true); assert.equal(result.action, 'closed');
  });
  it('DefectDojo: verifies a true positive (reopening a prior false positive) and only notes an ambiguous one', async () => {
    const calls = [];
    const tp = await scanners.resolveDojo(conn, 'DOJO-1201', { disposition: 'TRUE POSITIVE' }, { fetchImpl: fakeServers(calls, { dojoFalseP: true }) });
    assert.deepEqual(JSON.parse(calls.find(call => call.method === 'PATCH').body), { verified: true, false_p: false, active: true });
    assert.equal(JSON.parse(calls.find(call => call.path.endsWith('/notes/')).body).entry, servicenow.TRUE_POSITIVE_COMMENT); assert.equal(tp.action, 'verified');
    calls.length = 0;
    await scanners.resolveDojo(conn, 'DOJO-1201', { disposition: 'AMBIGUOUS' }, { fetchImpl: fakeServers(calls) });
    assert.deepEqual(writes(calls), ['POST /api/v2/findings/1201/notes/']);
    await assert.rejects(scanners.resolveDojo(conn, 'DOJO-9999', { disposition: 'AMBIGUOUS' }, { fetchImpl: fakeServers([]) }), /DOJO-9999 was not found or is not readable/);
  });
  it('SonarQube: comments with a summary and the report location, then transitions; hotspots become SAFE', async () => {
    const calls = [], sonar = { url: SONAR, token: 'squ' };
    const fp = await scanners.resolveSonar(sonar, 'SONAR-AYxExampleKey01', { disposition: 'FALSE POSITIVE', summary: 'FP-001', where: 'https://wiki.example.test/r/1' }, { fetchImpl: fakeServers(calls) });
    assert.deepEqual(writes(calls), ['POST /api/issues/add_comment', 'POST /api/issues/do_transition']);
    const comment = new URLSearchParams(calls[0].body).get('text');
    assert.match(comment, /^Closed by Threatlint as a false positive\. Summary: FP-001\. Full report: https:\/\/wiki\.example\.test\/r\/1\.$/);
    assert.equal(new URLSearchParams(calls[1].body).get('transition'), 'falsepositive'); assert.equal(fp.closed, true);
    calls.length = 0;
    const tp = await scanners.resolveSonar(sonar, 'SONAR-AYxExampleKey01', { disposition: 'TRUE POSITIVE' }, { fetchImpl: fakeServers(calls) });
    assert.equal(tp.action, 'noted', 'a refused confirm falls back to the comment');
    calls.length = 0;
    await scanners.resolveSonar(sonar, 'SONAR-HOTSPOT-AYxExampleKey02', { disposition: 'FALSE POSITIVE' }, { fetchImpl: fakeServers(calls) });
    const change = new URLSearchParams(calls[0].body);
    assert.deepEqual([calls[0].path, change.get('status'), change.get('resolution')], ['/api/hotspots/change_status', 'REVIEWED', 'SAFE']);
  });
});

describe('DefectDojo and SonarQube JSON imports', () => {
  it('detects and normalises the exports to file:line findings keyed by their references', () => {
    const dojo = scan.parseScanReport(fixture('defectdojo-findings.json'));
    assert.equal(dojo.source, 'defectdojo');
    assert.deepEqual(dojo.findings.map(finding => [finding.originalId, finding.severity, finding.location]),
      [['DOJO-1201', 'HIGH', 'src/app/search.py:42'], ['DOJO-1202', 'MEDIUM', 'src/app/config.py:9'], ['DOJO-1203', 'LOW', 'not recorded']]);
    assert.equal(dojo.findings[0].cwe, 'CWE-89'); assert.equal(dojo.findings[2].rule, 'CVE-2099-0001');
    const sonar = scan.parseScanReport(fixture('sonarqube-issues.json'));
    assert.equal(sonar.source, 'sonarqube'); assert.equal(sonar.target, 'web');
    assert.deepEqual(sonar.findings.map(finding => [finding.originalId, finding.severity, finding.location]), [['SONAR-AYxExampleKey01', 'HIGH', 'src/app/search.py:42'], ['SONAR-AYxExampleKey03', 'LOW', 'src/app/client.py:7']]);
    const hotspots = scan.parseScanReport(fixture('sonarqube-hotspots.json'));
    assert.deepEqual(hotspots.findings.map(finding => [finding.originalId, finding.rule, finding.location]), [['SONAR-HOTSPOT-AYxExampleKey02', 'python:S2068', 'src/app/config.py:9']]);
    assert.throws(() => scan.detect(fixture('sonarqube-issues.json').toString(), 'defectdojo'), /SonarQube report, not DefectDojo/);
  });
  it('reads reference mappings for posting', () => {
    assert.equal(scan.parseReferenceMapping('dojo', 'dojo-12'), 'DOJO-12');
    assert.deepEqual(scan.parseReferenceMapping('sonar', 'FP-001=AYxExampleKey01\nFP-002=HOTSPOT-AYxExampleKey02'), { 'FP-001': 'SONAR-AYxExampleKey01', 'FP-002': 'SONAR-HOTSPOT-AYxExampleKey02' });
    assert.throws(() => scan.parseReferenceMapping('dojo', '12 13'), /Several references need a mapping/);
  });
});

describe('Scanner Workbench routes', () => {
  let instance, base, socket;
  const calls = [], cliCalls = [], events = [];
  const report = (reference, disposition) => `# FP Review\n\n#### [FP-001] — finding\n**Original finding**: ${reference}; rule.x; Semgrep; src/app/search.py:42\n**Disposition**: ${disposition}\n**Severity**: LOW\n**Confidence**: CONFIRMED\n**Evidence**: src/app/search.py:42\n`;
  const threatlintCli = async args => {
    cliCalls.push(args);
    const [toolId, command] = args;
    if (command === 'fetch') {
      const refs = args[2].startsWith('--') ? (toolId === 'dojo' ? ['DOJO-1201', 'DOJO-1202'] : ['SONAR-AYxExampleKey01']) : [args[2]];
      fs.writeFileSync(args[args.indexOf('-o') + 1], refs.map(ref => `## ${ref} — finding\n`).join('\n'));
      return { code: 0, stdout: '✓', stderr: '' };
    }
    if (command === 'checkout') {
      if (args[2] === 'DOJO-1202') return { code: 1, stdout: '', stderr: 'ERROR: DOJO-1202 names no usable repository (Unsupported or missing SCM Tool); pass --repo-url' };
      const dir = args[args.indexOf('--dir') + 1];
      fs.mkdirSync(path.join(dir, '.git'), { recursive: true });
      return { code: 0, stdout: `✓\n${JSON.stringify({ name: 'web', branch: 'main', file_path: 'src/app/search.py' })}\n`, stderr: '' };
    }
    if (command === 'resolve') return { code: 0, stdout: `  ✓ Attached x\n  ✓ Note added\n  ✓ Marked false positive (inactive)\n${JSON.stringify({ reference: args[2], action: 'closed', closed: true })}\n`, stderr: '' };
    throw new Error(`unexpected ${args.join(' ')}`);
  };
  const api = async (route, payload) => {
    const response = await fetch(base + route, { ...(payload !== undefined ? { method: 'POST', body: JSON.stringify(payload) } : {}), headers: { 'Content-Type': 'application/json' } });
    return { status: response.status, body: await response.json() };
  };
  before(async () => {
    instance = createWorkbench({ storageDir: fs.mkdtempSync(path.join(os.tmpdir(), 'tl-scanner-store-')),
      runProvider: async args => { const ref = /(DOJO-\d+|SONAR-[A-Za-z0-9_-]+)\.md/.exec(args.userMessage)?.[1]; return ref ? report(ref, ref === 'DOJO-1202' ? 'AMBIGUOUS' : 'FALSE POSITIVE')
        : `\`\`\`json\n${JSON.stringify({ verdicts: [...new Set(args.userMessage.match(/"id":"FP-\d{3}"/g) || [])].map(item => ({ id: item.slice(6, -1), disposition: 'FALSE POSITIVE', confidence: 'CONFIRMED', rationale: 'stub' })) })}\n\`\`\``; },
      integrations: { fetchImpl: fakeServers(calls), threatlintCli } });
    await new Promise(resolve => instance.server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${instance.server.address().port}`;
    socket = new WebSocket(base.replace('http:', 'ws:'), { origin: base });
    await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
    socket.on('message', raw => events.push(JSON.parse(raw)));
  });
  after(async () => { socket.close(); await instance.close(); });

  it('saves the connection owner-only after checking the token, and never returns it', async () => {
    assert.equal((await api('/api/scanners/sonar/settings', { url: SONAR, token: 'squ_wrong_token_000' })).status, 400, 'a rejected token is not saved');
    const saved = await api('/api/scanners/sonar/settings', { url: `${SONAR}/`, token: 'squ_valid_token_123' });
    assert.equal(saved.status, 200); assert.deepEqual([saved.body.url, saved.body.hasToken], [SONAR, true]);
    assert.doesNotMatch(JSON.stringify((await api('/api/scanners/sonar/settings')).body), /squ_valid/);
    const file = path.join(process.env.THREATLINT_HOME, 'sonarqube.json');
    if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).token, 'squ_valid_token_123');
    assert.equal((await api('/api/scanners/dojo/settings', { url: 'http://dojo.example.test', token: 'x'.repeat(20) })).status, 400);
    assert.equal((await api('/api/scanners/dojo/settings', { url: DOJO, token: 'dojo-token-0123456789' })).body.hasToken, true);
    assert.equal((await api('/api/scanners/other/settings')).status, 400);
  });

  it('reviews findings from a filter, saves each report, and posts nothing until confirmed', async () => {
    events.length = 0; cliCalls.length = 0;
    socket.send(JSON.stringify({ action: 'run_scanner_batch', tool: 'dojo', filter: { product: 3, active: 'true' }, provider: 'lmstudio', model: 'fixture' }));
    while (!events.some(event => event.type === 'scanner_batch_complete' || event.type === 'scanner_batch_error')) await new Promise(resolve => setTimeout(resolve, 20));
    assert.deepEqual(events.find(event => event.type === 'scanner_batch_start').references, ['DOJO-1201', 'DOJO-1202']);
    const final = Object.fromEntries(events.filter(event => event.type === 'scanner_item' && event.done).map(event => [event.reference, event]));
    assert.equal(final['DOJO-1201'].stage, 'reported'); assert.equal(final['DOJO-1201'].disposition, 'FALSE POSITIVE');
    assert.equal(final['DOJO-1202'].stage, 'reported', 'a finding with no repository is still reviewed from its evidence'); assert.equal(final['DOJO-1202'].disposition, 'AMBIGUOUS');
    assert.ok(final['DOJO-1201'].report.docxUrl && final['DOJO-1201'].report.mdUrl, 'the report is kept in Findings');
    assert.deepEqual(cliCalls.filter(args => args[1] === 'resolve'), [], 'no write-back during the run');
    for (const args of cliCalls.filter(item => item[1] === 'checkout')) assert.ok(!fs.existsSync(args[args.indexOf('--dir') + 1]), 'checkouts are deleted');

    const reportId = final['DOJO-1201'].report.id;
    assert.equal((await api('/api/scanners/dojo/resolve', { reportId, reference: 'DOJO-1201' })).status, 400, 'confirmation is required');
    assert.equal((await api('/api/scanners/dojo/resolve', { reportId, reference: 'DOJO-1202', confirm: true })).status, 400, 'the reference must be in that report');
    const posted = await api('/api/scanners/dojo/resolve', { reportId, reference: 'DOJO-1201', confirm: true });
    assert.equal(posted.status, 200); assert.equal(posted.body.outcome.closed, true);
    const [resolve] = cliCalls.filter(args => args[1] === 'resolve');
    assert.deepEqual(resolve.slice(0, 3), ['dojo', 'resolve', 'DOJO-1201']);
    assert.ok(resolve.includes('--yes') && resolve.includes('--skip-semgrep') && fs.existsSync(resolve[resolve.indexOf('--docx') + 1]));
  });

  it('posts an imported DefectDojo export back to DefectDojo, and SonarQube needs a reference for other uploads', async () => {
    const created = await api('/api/scan-import', { filename: 'dojo.json', content: fixture('defectdojo-findings.json').toString('base64'), provider: 'lmstudio', model: 'fixture' });
    assert.equal(created.status, 201);
    await instance.scanImports.idle();
    const job = (await api(`/api/scan-import/${created.body.id}`)).body;
    assert.equal(job.status, 'done'); assert.equal(job.source, 'defectdojo');
    assert.equal((await api(`/api/scan-import/${job.id}/scanner`, { tool: 'dojo' })).status, 400, 'confirmation is required');
    calls.length = 0;
    const posted = await api(`/api/scan-import/${job.id}/scanner`, { tool: 'dojo', confirm: true });
    assert.equal(posted.status, 200, JSON.stringify(posted.body)); assert.equal(posted.body.ok, true);
    assert.deepEqual(posted.body.actions.map(action => action.reference), ['DOJO-1201', 'DOJO-1202', 'DOJO-1203']);
    assert.equal(writes(calls).filter(entry => entry.startsWith('PATCH')).length, 3);
    const sonar = await api(`/api/scan-import/${job.id}/scanner`, { tool: 'sonar', confirm: true });
    assert.equal(sonar.status, 400); assert.match(sonar.body.error, /did not come from SonarQube/);
    calls.length = 0;
    const mapped = await api(`/api/scan-import/${job.id}/scanner`, { tool: 'sonar', confirm: true, references: 'FP-001=AYxExampleKey01' });
    assert.equal(mapped.status, 200, JSON.stringify(mapped.body));
    assert.match(new URLSearchParams(calls[0].body).get('text'), /Full report: Threatlint Workbench report/);
  });
});
