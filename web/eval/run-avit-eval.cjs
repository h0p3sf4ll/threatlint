'use strict';
/**
 * FP-review efficacy evaluation on CodeSecurity AVITs.
 *
 *   node eval/run-avit-eval.cjs [--model claude-opus-5-5] [--out eval/results]
 *
 * Live mode (THREATLINT_SNOW_INSTANCE, THREATLINT_SNOW_CLIENT_ID, THREATLINT_SNOW_CLIENT_SECRET,
 * THREATLINT_EVAL_AVITS, THREATLINT_EVAL_REPO and THREATLINT_EVAL_TRUTH=<json file> set) reads real AVITs.
 * Otherwise the AVITs are built from real Semgrep results on eval/fixture-repo with known ground truth,
 * served by a recording ServiceNow stand-in. The model call is always real (ANTHROPIC_API_KEY).
 * Closing is exercised against recording stand-ins for ServiceNow, Azure DevOps, and GitHub only;
 * nothing is changed in a real tracker.
 */

const fs = require('node:fs');
const path = require('node:path');
const { WebSocket } = require('ws');
const { createWorkbench } = require('../server.js');

const args = Object.fromEntries(process.argv.slice(2).reduce((pairs, value, index, all) => (value.startsWith('--') ? [...pairs, [value.slice(2), all[index + 1]]] : pairs), []));
const MODEL = args.model || 'claude-opus-5-5';
const OUT = path.resolve(args.out || path.join(__dirname, 'results'));
const live = ['THREATLINT_SNOW_INSTANCE', 'THREATLINT_SNOW_CLIENT_ID', 'THREATLINT_SNOW_CLIENT_SECRET', 'THREATLINT_EVAL_AVITS', 'THREATLINT_EVAL_REPO', 'THREATLINT_EVAL_TRUTH'].every(name => process.env[name]);
const INSTANCE = live ? process.env.THREATLINT_SNOW_INSTANCE : 'https://eval.service-now.com';
const REPO = live ? path.resolve(process.env.THREATLINT_EVAL_REPO) : path.join(__dirname, 'fixture-repo');

// Ground truth for the fixture, set by reading the code (see eval/fixture-repo).
const FIXTURE = [
  { number: 'AVIT0090001', rule: 'javascript.lang.security.detect-child-process.detect-child-process', file: 'src/server.js', line: 22, truth: 'FALSE POSITIVE', why: '`format` is checked against a fixed allow-list before exec' },
  { number: 'AVIT0090002', rule: 'javascript.lang.security.detect-child-process.detect-child-process', file: 'src/server.js', line: 27, truth: 'TRUE POSITIVE', why: 'query parameter concatenated into a shell command' },
  { number: 'AVIT0090003', rule: 'javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal', file: 'src/server.js', line: 32, truth: 'FALSE POSITIVE', why: 'resolved path is confined to REPORTS with a separator-aware prefix check' },
  { number: 'AVIT0090004', rule: 'javascript.express.security.audit.xss.direct-response-write.direct-response-write', file: 'src/server.js', line: 34, truth: 'FALSE POSITIVE', why: 'response is a server-generated report file, not reflected input' },
  { number: 'AVIT0090005', rule: 'python.flask.security.injection.raw-html-concat.raw-html-format', file: 'app/views.py', line: 12, truth: 'TRUE POSITIVE', why: 'HTML is escaped, but user input becomes Jinja template source (SSTI)' },
  { number: 'AVIT0090006', rule: 'python.flask.security.injection.subprocess-injection.subprocess-injection', file: 'app/views.py', line: 18, truth: 'TRUE POSITIVE', why: 'query parameter reaches subprocess with shell=True' },
];
const OTHER_VIEW = { number: 'AVIT0090007', source: 'Dynamic Application Security (DAST)', short: 'Missing HSTS header on /login' };

const value = text => ({ value: text, display_value: text });
function avitRow(item) {
  return { sys_id: value(item.number.toLowerCase().replace('avit', '').padStart(32, '0')), number: value(item.number), state: value('Open'),
    source: value('CodeSecurity'), scanner: value('Semgrep'), rule: value(item.rule), source_file: value(item.file), line_number: value(String(item.line)),
    short_description: value(`${item.rule.split('.').pop()} in ${item.file}:${item.line}`), severity: value('3 - Medium') };
}

function recordingServiceNow(log) {
  return async (url, options = {}) => {
    log.push({ service: 'servicenow', method: options.method || 'GET', url: url.replace(/\?.*/, '') });
    const json = body => ({ ok: true, status: 200, json: async () => body });
    if (url.endsWith('/oauth_token.do')) return json({ access_token: 'eval' });
    if (url.includes('/sys_choice')) return json({ result: [{ name: 'sn_vul_app_vulnerable_item', element: 'state', value: '3', label: 'Closed' }, { name: 'sn_vul_app_vulnerable_item', element: 'substate', value: '6', label: 'False Positive' }] });
    if (url.includes('/attachment/file')) return json({ result: { sys_id: 'f'.repeat(32) } });
    if (options.method === 'PATCH') return json({ result: { state: '3', substate: '6' } });
    const query = new URL(url).searchParams.get('sysparm_query') || '';
    const wanted = query.replace(/^number(IN|=)/, '').split(',');
    const rows = [...FIXTURE.map(avitRow), { number: value(OTHER_VIEW.number), source: value(OTHER_VIEW.source), short_description: value(OTHER_VIEW.short), sys_id: value('e'.repeat(32)) }]
      .filter(row => wanted.includes(row.number.value));
    return json({ result: rows });
  };
}

function recordingTrackers(log) {
  return async (url, options = {}) => {
    const json = body => ({ ok: true, status: 200, json: async () => body });
    if (url.startsWith('https://dev.azure.com/')) {
      log.push({ service: 'azure-devops', method: options.method || 'GET', url: url.replace(/\?.*/, '') });
      if (url.includes('/workitems/') && !options.method) return json({ id: 1, fields: { 'System.State': 'Active', 'System.WorkItemType': 'Bug', 'System.Tags': 'CodeSecurity; Semgrep' } });
      if (url.includes('/states')) return json({ value: [{ name: 'Closed', category: 'Completed' }] });
      if (url.includes('/attachments')) return json({ url: 'https://dev.azure.com/eval/_apis/wit/attachments/1' });
      return json({ fields: { 'System.State': 'Closed' } });
    }
    if (url.startsWith('https://api.github.com/')) {
      log.push({ service: 'github', method: options.method || 'GET', url });
      if (url.includes('/code-scanning/alerts/') && !options.method) return json({ state: 'open', html_url: 'https://github.com/eval/fixture/security/code-scanning/1', rule: { id: 'eval' }, tool: { name: 'Semgrep' } });
      if (url.endsWith('/issues')) return json({ number: 9, html_url: 'https://github.com/eval/fixture/issues/9' });
      if (url.includes('/issues/')) return json({ number: 9, html_url: 'https://github.com/eval/fixture/issues/9', state: 'closed' });
      return json({ state: 'dismissed' });
    }
    return recordingServiceNow(log)(url, options);
  };
}

async function main() {
  if (!process.env.ANTHROPIC_API_KEY) throw new Error('ANTHROPIC_API_KEY is required: the evaluation uses the real model');
  fs.mkdirSync(OUT, { recursive: true });
  const storage = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'threatlint-eval-'));
  const calls = [];
  const fetchImpl = live ? undefined : recordingTrackers(calls);
  const instance = createWorkbench({ storageDir: storage, integrations: { fetchImpl, semgrepToken: () => 'eval' } });
  await new Promise(resolve => instance.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${instance.server.address().port}`;
  const post = async (route, body) => { const response = await fetch(base + route, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); return { status: response.status, body: await response.json() }; };
  const numbers = live ? process.env.THREATLINT_EVAL_AVITS.split(/[\s,]+/).filter(Boolean) : [...FIXTURE.map(item => item.number), OTHER_VIEW.number];
  const truth = live ? JSON.parse(fs.readFileSync(process.env.THREATLINT_EVAL_TRUTH, 'utf8')) : Object.fromEntries(FIXTURE.map(item => [item.number, item.truth]));
  const credentials = { instance: INSTANCE, clientId: process.env.THREATLINT_SNOW_CLIENT_ID || 'eval', clientSecret: process.env.THREATLINT_SNOW_CLIENT_SECRET || 'eval' };
  try {
    const { body: session } = await post('/api/session/local', { repoPath: REPO });
    const socket = new WebSocket(base.replace('http:', 'ws:'), { origin: base });
    await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
    const started = Date.now();
    const events = [];
    const report = await new Promise((resolve, reject) => {
      socket.on('message', raw => {
        const event = JSON.parse(raw);
        if (event.type !== 'text_chunk') events.push({ type: event.type, ...(event.type === 'tool_executing' ? { tool: event.tool } : {}), ...(event.type === 'avit_loaded' ? { retrieved: event.retrieved, excluded: event.excluded } : {}) });
        if (event.type === 'tool_executing') process.stdout.write('.');
        if (event.type === 'agent_complete') resolve(event.report);
        if (event.type === 'error' || event.type === 'agent_error') reject(new Error(event.message));
      });
      socket.send(JSON.stringify({ action: 'run_pipeline', sessionId: session.sessionId, agentIds: ['appsec-fp-reviewer'], provider: 'claude', model: MODEL, avits: numbers, servicenow: credentials }));
    });
    socket.close();
    const seconds = Math.round((Date.now() - started) / 1000);
    const full = (await (await fetch(base + report.previewUrl)).json());
    fs.writeFileSync(path.join(OUT, 'fp-review-report.md'), full.markdown);

    // Map each AVIT to the verdict the agent gave it.
    const verdicts = {};
    for (const finding of full.findings) {
      const avits = String(finding.body.match(/Original finding\W*:\s*(.+)/i)?.[1] || finding.title).toUpperCase().match(/AVIT\d{4,12}/g) || [];
      for (const avit of new Set(avits)) verdicts[avit] ||= { finding: finding.id, disposition: finding.disposition || 'UNSPECIFIED', confidence: finding.confidence, title: finding.title };
    }
    const rows = Object.entries(truth).map(([avit, expected]) => ({ avit, expected, ...(verdicts[avit] || { disposition: 'NOT REPORTED' }), correct: verdicts[avit]?.disposition === expected,
      ...(live ? {} : { rule: FIXTURE.find(item => item.number === avit).rule, location: `${FIXTURE.find(item => item.number === avit).file}:${FIXTURE.find(item => item.number === avit).line}`, why: FIXTURE.find(item => item.number === avit).why }) }));
    const count = (expected, got) => rows.filter(row => row.expected === expected && row.disposition === got).length;
    const metrics = {
      total: rows.length, correct: rows.filter(row => row.correct).length,
      fpCorrect: count('FALSE POSITIVE', 'FALSE POSITIVE'), fpTotal: rows.filter(row => row.expected === 'FALSE POSITIVE').length,
      tpCorrect: count('TRUE POSITIVE', 'TRUE POSITIVE'), tpTotal: rows.filter(row => row.expected === 'TRUE POSITIVE').length,
      // The costly error: a real vulnerability marked FALSE POSITIVE and closed.
      unsafeClosures: count('TRUE POSITIVE', 'FALSE POSITIVE'), ambiguous: rows.filter(row => row.disposition === 'AMBIGUOUS').length,
      excludedNonCodeSecurity: events.find(event => event.type === 'avit_loaded')?.excluded || [],
      toolCalls: events.filter(event => event.type === 'tool_executing').length, seconds, model: MODEL, mode: live ? 'live ServiceNow' : 'fixture AVITs (real Semgrep results)',
      formatIssues: full.quality.issues,
    };

    // Closure mechanics on each FALSE POSITIVE verdict (recording stand-ins only, never a real tracker).
    const closures = [];
    if (!live) {
      for (const row of rows.filter(item => item.disposition === 'FALSE POSITIVE')) {
        const before = calls.length;
        const result = await post('/api/trackers/close-false-positive', { reportId: report.id, findingId: row.finding, tracker: 'servicenow', servicenow: credentials });
        closures.push({ avit: row.avit, status: result.status, closed: result.body.closed, attachments: (result.body.attachments || []).map(item => item.name), calls: calls.slice(before).map(call => `${call.method} ${new URL(call.url).pathname}`) });
      }
      const refused = rows.find(item => item.disposition === 'TRUE POSITIVE');
      if (refused) { const result = await post('/api/trackers/close-false-positive', { reportId: report.id, findingId: refused.finding, tracker: 'servicenow', servicenow: credentials }); closures.push({ avit: refused.avit, status: result.status, refused: result.body.error }); }
    }
    const results = { generatedAt: new Date().toISOString(), metrics, rows, closures };
    fs.writeFileSync(path.join(OUT, 'results.json'), `${JSON.stringify(results, null, 2)}\n`);
    console.log(`\n${metrics.correct}/${metrics.total} correct · FP ${metrics.fpCorrect}/${metrics.fpTotal} · TP ${metrics.tpCorrect}/${metrics.tpTotal} · unsafe closures ${metrics.unsafeClosures} · ${seconds}s · results in ${OUT}`);
  } finally { await instance.close(); fs.rmSync(storage, { recursive: true, force: true }); }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
