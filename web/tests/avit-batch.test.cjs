'use strict';
process.env.THREATLINT_HOME = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'threatlint-home-'));
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { WebSocket } = require('ws');
const { createWorkbench } = require('../server.js');
const { redactSecrets, resolveOutcome, parseBatchInput, planBatch, terminalResult, outcomeActions, errorOf, avitRecordUrl } = require('../lib/avit-batch.cjs');
const { convertToWord } = require('./helpers/docx.cjs');

const FP = 'AVIT000000000000001', TP = 'AVIT000000000000002', OUT = 'AVIT000000000000003';
const SLOW = 'AVIT000000000000077';
let gate = { promise: Promise.resolve(), release: () => {} };
const holdSlowFetch = () => { let release; gate = { promise: new Promise(resolve => { release = resolve; }), release: () => release() }; };
let storage;
const SECRET = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
const report = (avit, disposition) => `# FP Review\n\n#### [FP-001] — finding\n**Original finding**: ${avit}; rule.x.y; Semgrep Code; app.yaml:2\n**Disposition**: ${disposition}\n**Severity**: INFO\n**Confidence**: CONFIRMED\n**Evidence**: app.yaml:2 — value ${SECRET}\n**Verified Safe Behavior**: This synthetic fixture value is never used as a provider credential on any deployment path.\nBlast radius: one rule. Acceptance criteria: x. Proposed fix: y.\n`;

it('reports the resolve failure instead of a successful checkout cleanup line', () => {
  const cleanup = '  ✓ Deleted the local checkout /tmp/threatlint-avit-example/repo\n';
  assert.equal(errorOf({ code: 1, stdout: `  ✓ Attached report.docx\n  ! Rule not tuned: Semgrep validation failed\n${cleanup}`, stderr: '' }),
    'Rule not tuned: Semgrep validation failed');
  assert.equal(errorOf({ code: 1, stdout: cleanup, stderr: 'ERROR: ServiceNow denied the update\n' }),
    'ServiceNow denied the update');
  assert.equal(errorOf({ code: 1, stdout: cleanup, stderr: '' }), 'Command failed (exit code 1)');
  assert.equal(errorOf({ code: 1, stdout: `  ✓ Attached report.docx\n${cleanup}`, stderr: '' }), 'Command failed (exit code 1)');
});

it('links the AVIT record using only its own sys_id and otherwise looks up its number', () => {
  const instance = 'https://example.service-now.com', sysId = 'a'.repeat(32), referenceId = 'b'.repeat(32);
  const markdown = `## ${TP}\n\n### AVIT fields\n\n| Field | Value |\n|---|---|\n| sys_id | ${sysId} |\n\n### Referenced records\n\n| sys_id | ${referenceId} |\n`;
  const direct = new URL(avitRecordUrl(instance, TP, markdown));
  assert.equal(direct.origin, instance);
  assert.equal(direct.pathname, '/nav_to.do');
  assert.equal(direct.searchParams.get('uri'), `sn_vul_app_vulnerable_item.do?sys_id=${sysId}`);
  for (const evidence of ['', `### Referenced records\n| sys_id | ${referenceId} |\n`, markdown.replace(`| sys_id | ${sysId} |`, '| state | Closed |')]) {
    const fallback = new URL(avitRecordUrl(instance, TP, evidence));
    assert.equal(fallback.searchParams.get('uri'), `sn_vul_app_vulnerable_item.do?sysparm_query=number=${TP}`);
  }
  assert.equal(avitRecordUrl('', TP), '');
  assert.equal(avitRecordUrl(instance, `${TP}^active=true`), '');
});

it('refuses unsafe ServiceNow record link origins', () => {
  for (const instance of ['javascript:alert(1)', 'http://example.service-now.com', 'https://user:password@example.service-now.com', 'https://untrusted.example']) {
    assert.throws(() => avitRecordUrl(instance, TP));
  }
});

describe('False positive review batch', () => {
  let wb, base;
  const calls = [], modelCalls = [];
  const attachmentNames = new Set();
  let adoMissing = false, omitTuning = false, resolveResult = null, avitMarkdown = null, prScm = '', prResult = null;
  let preparationResults = [], modelReports = [], modelHook = null;
  const preparedReports = [], resolvedReports = [];
  const taskAvits = {};
  before(async () => {
    const threatlintCli = async args => {
      calls.push(args);
      if (args[1] === 'fetch' && args[2] === SLOW) await gate.promise;
      if (args[0] === 'setup') return { code: 0, stdout: JSON.stringify([{ name: 'ServiceNow OAuth client', configured: true }, { name: 'Azure DevOps PAT', configured: !adoMissing, fix: 'threatlint ado login --organization <org>' }, { name: 'Semgrep API token', configured: true }]), stderr: '' };
      if (args[0] === 'sctask' && args[1] === 'avits') {
        if (taskAvits[args[2]] === null) return { code: 1, stdout: '', stderr: `ERROR: ${args[2]} was not found` };
        const avits = taskAvits[args[2]] || [FP, TP];
        return { code: avits.length ? 0 : 1, stdout: `${avits.join('\n')}\n${JSON.stringify({ sctask: args[2], avits })}\n`, stderr: '' };
      }
      if (args[0] === 'sctask' && args[1] === 'close') return { code: 0, stdout: `  ✓ Attached x\n  ✓ Closed ${args[2]}\n`, stderr: '' };
      const [, command, avit] = args;
      if (command === 'fetch') {
        if (avit === OUT) return { code: 1, stdout: '', stderr: `ERROR: None of the requested AVITs are in the AVR CodeSecurity view (${OUT}).` };
        fs.writeFileSync(args[args.indexOf('-o') + 1], avitMarkdown || `## ${avit}\n`); return { code: 0, stdout: '✓', stderr: '' };
      }
      if (command === 'checkout') {
        const dir = args[args.indexOf('--dir') + 1];
        fs.mkdirSync(path.join(dir, '.git'), { recursive: true }); fs.writeFileSync(path.join(dir, 'app.yaml'), `name: svc\nAPI_KEY: "${SECRET}"\n`);
        return { code: 0, stdout: `✓ Checked out\n${JSON.stringify({ kind: 'secrets', name: 'svc', branch: 'main', file_path: 'app.yaml', ...(prScm ? { scm: prScm, organization: 'contoso', project: 'project' } : {}) })}\n`, stderr: '' };
      }
      if (command === 'fix-pr') {
        assert.ok(fs.existsSync(args[args.indexOf('--checkout') + 1]), 'the checkout remains until the PR step completes');
        assert.equal(JSON.parse(fs.readFileSync(args[args.indexOf('--target') + 1], 'utf8')).avit, avit);
        if (prResult instanceof Error) throw prResult;
        return prResult;
      }
      if (command === 'prepare-fix') {
        const md = fs.readFileSync(args[args.indexOf('--report') + 1], 'utf8');
        assert.ok(!md.includes(SECRET), 'evidence preparation receives only a redacted draft');
        assert.ok(md.startsWith('# Finding Review'), 'the draft is normalized before assessment');
        assert.equal(JSON.parse(fs.readFileSync(args[args.indexOf('--target') + 1], 'utf8')).avit, avit);
        preparedReports.push(md);
        const result = preparationResults.shift() || { status: 'ready', issues: [], prompt: '' };
        return Object.hasOwn(result, 'code') ? result : { code: 0, stdout: JSON.stringify(result), stderr: '' };
      }
      if (command === 'resolve') {
        const md = fs.readFileSync(args[args.indexOf('--report') + 1], 'utf8');
        resolvedReports.push(md);
        const attachment = args[args.indexOf('--attachment-name') + 1];
        assert.match(attachment, new RegExp(`^${avit}-threatlint-fp-review-\\d{8}T\\d{12}Z\\.docx$`));
        assert.equal(attachmentNames.has(attachment), false, 'every final report gets a new attachment name on rerun');
        attachmentNames.add(attachment);
        assert.ok(!md.includes(SECRET), 'the secret is redacted before the report is saved or uploaded');
        assert.ok(fs.existsSync(args[args.indexOf('--docx') + 1]));
        if (resolveResult) return resolveResult;
        return /\*\*Disposition\*\*: FALSE POSITIVE/.test(md) ? { code: 0, stdout: '  ✓ Attached x.docx\n  ✓ Closed as false positive\n  ✓ Semgrep ignored 1 finding(s)\n' + (omitTuning ? '' : '  ✓ Published org-private rule synthetic.rule.tuned\n'), stderr: '' }
          : { code: 0, stdout: '  ✓ Attached x.docx\n  ✓ Work note added; AVIT left open\n', stderr: '' };
      }
      throw new Error(`unexpected ${args.join(' ')}`);
    };
    storage = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-store-'));
    wb = createWorkbench({ storageDir: storage,
      runProvider: async args => {
        modelCalls.push(args);
        if (modelHook) await modelHook(args);
        const avit = /servicenow-(AVIT\d+)/.exec(args.userMessage)[1];
        const text = modelReports.shift() || report(avit, avit === FP ? 'FALSE POSITIVE' : 'TRUE POSITIVE');
        if (text instanceof Error) throw text;
        args.onEvent({ type: 'text_chunk', text }); return text;
      },
      integrations: { convertToWord, semgrepVersion: async () => '1.107.0', threatlintCli } });
    await new Promise(resolve => wb.server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${wb.server.address().port}`;
  });
  after(() => wb.close());

  for (const scm of ['azure-devops', 'github']) it(`opens ${scm} proposed fix PRs after successful write-back and keeps failures visible`, async t => {
    prScm = scm;
    t.after(() => { prScm = ''; prResult = null; calls.length = 0; });
    const url = scm === 'azure-devops' ? 'https://dev.azure.com/contoso/project/_git/svc/pullrequest/42' : 'https://git.example.com/contoso/svc/pull/42';
    for (const status of ['created', 'existing', 'skipped', 'error', 'spawn-error', 'disabled']) {
      const start = calls.length;
      prResult = status === 'error' ? { code: 1, stdout: '', stderr: 'ERROR: Provider denied draft PR creation' }
        : { code: 0, stdout: JSON.stringify(status === 'skipped' ? { status, reason: 'No applicable proposed fix' } : { status, url }), stderr: '' };
      if (status === 'spawn-error') prResult = new Error('synthetic spawn failure');
      const socket = new WebSocket(base.replace('http:', 'ws:'), { origin: base });
      await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
      const events = await new Promise(resolve => {
        const seen = [];
        socket.on('message', raw => { const event = JSON.parse(raw); seen.push(event); if (event.type === 'avit_batch_complete' || event.type === 'avit_batch_error') resolve(seen); });
        socket.send(JSON.stringify({ action: 'run_avit_batch', avits: TP, provider: 'lmstudio', model: 'fixture', createFixPr: status !== 'disabled' }));
      });
      socket.close();
      const current = calls.slice(start);
      assert.equal(modelCalls.at(-1).userMessage.includes('**Proposed fix patch**:'), status !== 'disabled');
      const done = events.find(event => event.type === 'avit_item' && event.done);
      assert.ok(done, JSON.stringify(events));
      assert.equal(done.stage, ['error', 'spawn-error'].includes(status) ? 'error' : 'done');
      assert.equal(done.outcome.attached, true);
      if (status === 'disabled') {
        assert.equal(current.some(args => args[1] === 'prepare-fix'), false);
        assert.equal(current.some(args => args[1] === 'fix-pr'), false);
        assert.equal(current.find(args => args[1] === 'resolve').includes('--keep-checkout'), false);
      } else {
        assert.ok(current.find(args => args[1] === 'resolve').includes('--keep-checkout'));
        assert.ok(current.findIndex(args => args[1] === 'resolve') < current.findIndex(args => args[1] === 'fix-pr'));
        if (status === 'error') assert.match(done.detail, /Report attached.*Provider denied/);
        else if (status === 'spawn-error') assert.match(done.detail, /Report attached.*could not complete/);
        else assert.equal(done.outcome.pullRequest.status, status);
        if (['created', 'existing'].includes(status)) assert.ok(events.some(event => event.action === 'pull-request' && event.pullRequest.url === url));
      }
    }
  });

  it('reviews, reports, and resolves each AVIT individually', async () => {
    const socket = new WebSocket(base.replace('http:', 'ws:'), { origin: base });
    await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
    const events = await new Promise(resolve => {
      const seen = [];
      socket.on('message', raw => { const event = JSON.parse(raw); seen.push(event); if (event.type === 'avit_batch_complete' || event.type === 'avit_batch_error') resolve(seen); });
      socket.send(JSON.stringify({ action: 'run_avit_batch', avits: `${FP}\n${TP}, ${OUT}`, provider: 'lmstudio', model: 'fixture' }));
    });
    socket.close();
    const final = Object.fromEntries(events.filter(event => event.type === 'avit_item' && event.done).map(event => [event.avit, event]));
    assert.equal(final[FP].stage, 'done'); assert.equal(final[FP].disposition, 'FALSE POSITIVE'); assert.equal(final[FP].outcome.closed, true);
    assert.equal(final[TP].stage, 'done'); assert.equal(final[TP].outcome.leftOpen, true);
    assert.equal(final[OUT].stage, 'out-of-scope');
    assert.equal(final[FP].report, undefined, 'no local report is offered');
    const reportDirs = calls.filter(args => args[1] === 'resolve').map(args => args[args.indexOf('--report') + 1]);
    assert.equal(new Set(reportDirs).size, 2, 'one report per AVIT');
    for (const file of reportDirs) assert.ok(!fs.existsSync(file), 'reports are not kept locally');
    assert.deepEqual(calls.filter(args => args[1] === 'resolve').map(args => args[2]), [FP, TP], 'one closure per AVIT, in order');
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(storage, 'sessions.json'), 'utf8')), [], 'no report history kept');
    for (const args of calls.filter(item => item[1] === 'checkout')) assert.ok(!fs.existsSync(args[args.indexOf('--dir') + 1]), 'checkouts are deleted');
  });
  it('starts a Daybreak AVIT review through Codex when no OpenAI API key is configured', async t => {
    const previousKey = process.env.OPENAI_API_KEY;
    delete process.env.OPENAI_API_KEY;
    t.after(() => {
      if (previousKey === undefined) delete process.env.OPENAI_API_KEY;
      else process.env.OPENAI_API_KEY = previousKey;
    });
    const authPath = path.join(process.env.CODEX_HOME ? path.resolve(process.env.CODEX_HOME) : path.join(os.homedir(), '.codex'), 'auth.json');
    const readFile = fs.readFileSync;
    // Model the ChatGPT-only sign-in without reading or changing a real login.
    t.mock.method(fs, 'readFileSync', (file, ...args) => file === authPath ? '{"auth_mode":"chatgpt"}' : readFile(file, ...args));
    const firstCall = modelCalls.length;
    const socket = new WebSocket(base.replace('http:', 'ws:'), { origin: base });
    t.after(() => socket.close());
    await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
    const events = await new Promise(resolve => {
      const seen = [];
      socket.on('message', raw => { const event = JSON.parse(raw); seen.push(event); if (event.type === 'avit_batch_complete' || event.type === 'avit_batch_error') resolve(seen); });
      socket.send(JSON.stringify({ action: 'run_avit_batch', avits: TP, provider: 'daybreak', model: 'gpt-6-sol' }));
    });
    assert.ok(events.some(event => event.type === 'avit_batch_start'), JSON.stringify(events));
    assert.equal(events.some(event => event.type === 'avit_batch_error'), false);
    assert.equal(modelCalls.length, firstCall + 1);
    const invocation = modelCalls[firstCall];
    assert.equal(invocation.provider, 'daybreak');
    assert.equal(invocation.transport, 'codex');
    assert.equal(invocation.daybreakBlue, true);
    assert.equal(invocation.model, 'gpt-6-sol');
    assert.equal(invocation.key, null);
    const final = events.find(event => event.type === 'avit_item' && event.avit === TP && event.done);
    assert.equal(final.stage, 'done');
    assert.equal(final.result, 'noted');
  });
  it('expands an SCTASK into its AVITs, reviews each, then closes the task', async () => {
    calls.length = 0;
    const socket = new WebSocket(base.replace('http:', 'ws:'), { origin: base });
    await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
    const events = await new Promise(resolve => {
      const seen = [];
      socket.on('message', raw => { const event = JSON.parse(raw); seen.push(event); if (event.type === 'avit_batch_complete' || event.type === 'avit_batch_error') resolve(seen); });
      socket.send(JSON.stringify({ action: 'run_avit_batch', avits: 'SCTASK14120565', provider: 'lmstudio', model: 'fixture' }));
    });
    socket.close();
    assert.deepEqual(calls.filter(args => args[1] === 'resolve').map(args => args[2]), [FP, TP], 'each AVIT in the task is resolved');
    const order = calls.map(args => args.slice(0, 2).join(' '));
    assert.ok(order.lastIndexOf('avit resolve') < order.indexOf('sctask close'), 'the task is closed after its AVITs');
    const done = events.filter(event => event.type === 'sctask_item' && event.done).pop();
    assert.equal(done.stage, 'done'); assert.match(done.detail, /Closed/);
  });
  const runBatch = async (avits, options = {}) => {
    const socket = new WebSocket(base.replace('http:', 'ws:'), { origin: base });
    await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
    const events = await new Promise(resolve => {
      const seen = [];
      socket.on('message', raw => { const event = JSON.parse(raw); seen.push(event); if (event.type === 'avit_batch_complete' || event.type === 'avit_batch_error') resolve(seen); });
      socket.send(JSON.stringify({ action: 'run_avit_batch', avits, provider: 'lmstudio', model: 'fixture', ...options }));
    });
    socket.close();
    return events;
  };
  const setupRefinement = (t, scm = 'github') => {
    calls.length = 0; preparedReports.length = 0; resolvedReports.length = 0;
    prScm = scm;
    prResult = { code: 0, stdout: JSON.stringify({ status: 'created', url: 'https://git.example.com/contoso/svc/pull/42' }), stderr: '' };
    t.after(() => {
      prScm = ''; prResult = null; preparationResults = []; modelReports = []; modelHook = null;
      calls.length = 0; preparedReports.length = 0; resolvedReports.length = 0;
    });
  };
  const refine = (issue, prompt = `Inspect the caller and registered controls to resolve: ${issue}. Return the full report.`) => ({ status: 'refine', issues: [issue], prompt });
  const uncertain = () => report(TP, 'TRUE POSITIVE') + '**Decision basis**: CONSERVATIVE DEFAULT\n**Blocking Evidence**: Caller control is not yet traced.\n';

  for (const scm of ['azure-devops', 'github']) it(`investigates ${scm} evidence and repairs a proposal before saving, resolving, and publishing once`, async t => {
    setupRefinement(t, scm);
    const firstModel = modelCalls.length;
    preparationResults = [refine('Trace caller control', 'Inspect caller app.yaml:2 and its registered controls.'),
      refine('Patch does not apply', 'Re-read the exact checkout and repair the unified diff context.'), { status: 'ready', issues: [], prompt: '' }];
    modelReports = [uncertain(), report(TP, 'TRUE POSITIVE') + 'Confirmed caller evidence, but draft patch needs repair.\n',
      report(TP, 'TRUE POSITIVE') + '**Exploit path**: Final inspected proof.\n**Proposed fix patch**:\n```diff\nvalidated fixture diff\n```\n'];
    modelHook = () => assert.equal(calls.some(args => args[1] === 'resolve' || args[1] === 'fix-pr'), false, 'all investigation occurs before tracker or PR writes');
    const events = await runBatch(TP);
    const reviews = modelCalls.slice(firstModel);
    assert.equal(reviews.length, 3);
    assert.match(reviews[0].userMessage, /TRUE POSITIVE when the inspected evidence establishes the vulnerability/);
    assert.match(reviews[1].userMessage, /Inspect caller app.yaml:2 and its registered controls/);
    assert.match(reviews[2].userMessage, /repair the unified diff context/);
    assert.ok(reviews.every(args => args.repoPath === reviews[0].repoPath && args.purpose === 'review' && args.agentId === 'appsec-fp-reviewer'));
    assert.equal(preparedReports.length, 3);
    assert.match(preparedReports[0], /CONSERVATIVE DEFAULT/);
    assert.equal(resolvedReports.length, 1);
    assert.match(resolvedReports[0], /Final inspected proof/);
    assert.doesNotMatch(resolvedReports[0], /CONSERVATIVE DEFAULT/);
    const commands = calls.filter(args => ['prepare-fix', 'resolve', 'fix-pr'].includes(args[1])).map(args => args[1]);
    assert.deepEqual(commands, ['prepare-fix', 'prepare-fix', 'prepare-fix', 'resolve', 'fix-pr']);
    assert.equal(events.filter(event => event.attempt).length, 2);
    const final = events.find(event => event.avit === TP && event.done);
    assert.equal(final.stage, 'done'); assert.equal(final.outcome.pullRequest.status, 'created');
    assert.ok(!fs.existsSync(reviews[0].repoPath), 'temporary source and intermediate reports are deleted');
  });

  it('retains honest evidence gaps after bounded investigation and reports blocked remediation without publishing', async t => {
    setupRefinement(t);
    const firstModel = modelCalls.length;
    preparationResults = [refine('Deployment configuration is unavailable'), refine('Deployment configuration is unavailable'), refine('Deployment configuration is unavailable')];
    modelReports = [uncertain(), uncertain(), uncertain()];
    const events = await runBatch(TP);
    const final = events.find(event => event.avit === TP && event.done);
    assert.equal(modelCalls.length - firstModel, 3);
    assert.equal(resolvedReports.length, 1);
    assert.match(resolvedReports[0], /CONSERVATIVE DEFAULT/);
    assert.equal(final.stage, 'error'); assert.equal(final.outcome.attached, true);
    assert.deepEqual(final.outcome.pullRequest, { status: 'blocked', reason: 'Deployment configuration is unavailable' });
    assert.match(final.detail, /evidence investigation.*Deployment configuration is unavailable/);
    assert.equal(calls.some(args => args[1] === 'fix-pr'), false);
    assert.equal(calls.find(args => args[1] === 'resolve').includes('--keep-checkout'), false);
  });

  it('allows evidence investigation to prove a false positive and follows the normal closure and tuning path', async t => {
    setupRefinement(t);
    preparationResults = [refine('Inspect the actual control'), { status: 'skipped', issues: [], prompt: '', reason: 'False positives need no source-fix PR' }];
    modelReports = [uncertain(), report(TP, 'FALSE POSITIVE')];
    const events = await runBatch(TP);
    const final = events.find(event => event.avit === TP && event.done);
    assert.equal(final.stage, 'done'); assert.equal(final.disposition, 'FALSE POSITIVE');
    assert.equal(final.outcome.closed, true); assert.equal(final.outcome.tuned, true);
    assert.match(resolvedReports[0], /Disposition\*\*: FALSE POSITIVE/);
    assert.equal(calls.some(args => args[1] === 'fix-pr'), false);
  });

  for (const failure of ['assessment', 'model']) it(`stops before tracker writes if ${failure} fails during evidence investigation`, async t => {
    setupRefinement(t);
    if (failure === 'assessment') preparationResults = [{ code: 1, stdout: '', stderr: 'ERROR: Synthetic assessment failure' }];
    else { preparationResults = [refine('Inspect caller')]; modelReports = [uncertain(), new Error('Synthetic follow-up model failure')]; }
    const events = await runBatch(TP);
    const final = events.find(event => event.avit === TP && event.done);
    assert.equal(final.stage, 'error'); assert.match(final.detail, /Synthetic/);
    assert.equal(calls.some(args => ['resolve', 'fix-pr'].includes(args[1])), false);
    const checkout = calls.find(args => args[1] === 'checkout');
    assert.ok(!fs.existsSync(checkout[checkout.indexOf('--dir') + 1]));
  });

  it('cancels a follow-up investigation before saving or writing tracker state', async t => {
    setupRefinement(t);
    preparationResults = [refine('Inspect caller')];
    modelReports = [uncertain(), report(TP, 'TRUE POSITIVE')];
    let reviews = 0;
    modelHook = async () => {
      if (++reviews !== 2) return;
      const stop = await open();
      stop.send(JSON.stringify({ action: 'avit_batch_cancel' }));
      await waitFor(stop, event => event.type === 'avit_batch_cancel_ack');
      stop.close();
    };
    const events = await runBatch(TP);
    assert.equal(events.find(event => event.avit === TP && event.done).stage, 'cancelled');
    assert.equal(calls.some(args => ['resolve', 'fix-pr'].includes(args[1])), false);
    assert.equal(events.at(-1).cancelled, true);
  });

  it('reports an already closed AVIT as informational with a direct ServiceNow record link', async () => {
    const information = 'AVIT is already closed in ServiceNow; work note added and report attached.';
    const sysId = 'c'.repeat(32);
    resolveResult = { code: 0, stdout: `  ✓ Attached x.docx\n  INFO: ${information}\n`, stderr: '' };
    avitMarkdown = `## ${TP}\n\n### AVIT fields\n\n| sys_id | ${sysId} |\n\n### Referenced records\n\n| sys_id | ${'d'.repeat(32)} |\n`;
    try {
      const events = await runBatch(TP, { servicenow: { instance: 'https://example.service-now.com' } });
      const final = events.find(event => event.avit === TP && event.done);
      assert.equal(final.stage, 'info'); assert.equal(final.result, 'noted');
      assert.equal(final.detail, information);
      assert.equal(final.outcome.information, information);
      assert.equal(final.outcome.attached, true);
      assert.equal(final.outcome.leftOpen, false);
      assert.equal(final.outcome.closed, false, 'the review did not close the record');
      assert.equal(new URL(final.url).searchParams.get('uri'), `sn_vul_app_vulnerable_item.do?sys_id=${sysId}`);
      const fetching = events.find(event => event.avit === TP && event.stage === 'fetching');
      assert.equal(new URL(fetching.url).searchParams.get('uri'), `sn_vul_app_vulnerable_item.do?sysparm_query=number=${TP}`);
      assert.ok(!events.some(event => event.avit === TP && (event.stage === 'error' || /left open/i.test(event.detail || ''))));
    } finally { resolveResult = null; avitMarkdown = null; }
  });
  it('retains actual resolve failures even when stdout also contains an informational notice', async () => {
    resolveResult = { code: 1, stdout: '  ✓ Attached x.docx\n  INFO: AVIT is already closed in ServiceNow; work note added and report attached.\n',
      stderr: 'ERROR: ServiceNow denied the update\n' };
    try {
      const events = await runBatch(TP);
      const final = events.find(event => event.avit === TP && event.done);
      assert.equal(final.stage, 'error'); assert.equal(final.result, 'error');
      assert.equal(final.detail, 'ServiceNow denied the update');
      assert.equal(final.outcome.leftOpen, false);
    } finally { resolveResult = null; }
  });
  it('expands several SCTASKs, deduplicates their AVITs, closes each after its own AVITs, and survives a failing task', async () => {
    calls.length = 0;
    const A = 'SCTASK1000001', B = 'SCTASK1000002', BAD = 'SCTASK1000003';
    Object.assign(taskAvits, { [A]: [FP], [B]: [FP, TP], [BAD]: null });
    const events = await runBatch(`${A}, ${BAD}; ${B}\n${TP}`);
    const order = calls.filter(args => args[0] === 'sctask' || args[1] === 'resolve').map(args => `${args[1]} ${args[2]}`);
    assert.deepEqual(order, [`avits ${A}`, `avits ${BAD}`, `avits ${B}`, `resolve ${FP}`, `close ${A}`, `resolve ${TP}`, `close ${B}`],
      'every task is read, each AVIT is reviewed once, and each task is closed right after its own AVITs');
    const start = events.find(event => event.type === 'avit_batch_start');
    assert.deepEqual(start.avits, [FP, TP]); assert.deepEqual(start.sctasks, [A, B]); assert.equal(start.truncated, null);
    const final = Object.fromEntries(events.filter(event => event.type === 'sctask_item' && event.done).map(event => [event.sctask, event]));
    assert.equal(final[BAD].stage, 'error'); assert.match(final[BAD].detail, /not found/); assert.equal(final[BAD].result, 'error');
    assert.equal(final[A].result, 'closed'); assert.equal(final[B].result, 'closed');
    assert.deepEqual(events.find(event => event.sctask === B && event.avits).shared, [FP], 'the AVIT shared with an earlier task is reported as reviewed once');
    assert.ok(events.every(event => typeof event.at === 'string' && !Number.isNaN(Date.parse(event.at))), 'every event is timestamped');
    const fp = events.filter(event => event.avit === FP && !event.tool).map(event => event.action || event.stage);
    assert.deepEqual(fp, ['fetching', 'checkout', 'triage', 'reported', 'resolving', 'attached', 'closed', 'semgrep-ignored', 'tuned', 'done'], 'each step and ServiceNow action is its own event');
    assert.equal(events.filter(event => event.type === 'avit_item' && event.done).find(event => event.avit === TP).result, 'noted');
    for (const key of Object.keys(taskAvits)) delete taskAvits[key];
  });
  it('reports partial completion when an eligible FP closes without tuning', async () => {
    omitTuning = true;
    try {
      const events = await runBatch(FP);
      const result = events.find(event => event.avit === FP && event.done);
      assert.equal(result.stage, 'error'); assert.equal(result.result, 'error');
      assert.equal(result.outcome.closed, true); assert.equal(result.outcome.tuned, false);
      assert.match(result.detail, /rule tuning did not complete/);
      assert.match(result.detail, /tracker may already have changed/);
    } finally { omitTuning = false; }
  });
  it('reviews every AVIT with no batch limit', async () => {
    calls.length = 0;
    const many = Array.from({ length: 52 }, (_, index) => `AVIT${String(9000000 + index)}`);
    taskAvits.SCTASK2000001 = many;
    const events = await runBatch(`${FP} SCTASK2000001`);
    const start = events.find(event => event.type === 'avit_batch_start');
    assert.equal(start.avits.length, 53); assert.equal(start.truncated, null);
    assert.ok(!events.some(event => event.type === 'avit_item' && event.stage === 'skipped'), 'nothing is skipped for size');
    assert.equal(calls.filter(args => args[1] === 'fetch').length, 53, 'all 53 are reviewed');
    assert.doesNotMatch(events.find(event => event.sctask && event.avits).detail, /limit/);
    delete taskAvits.SCTASK2000001;
  });

  const open = async () => {
    const socket = new WebSocket(base.replace('http:', 'ws:'), { origin: base });
    socket.seen = [];
    socket.on('message', raw => socket.seen.push(JSON.parse(raw)));
    await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
    return socket;
  };
  const waitFor = (socket, test) => new Promise(resolve => {
    const found = socket.seen.find(test); if (found) { resolve(found); return; }
    const listener = raw => { const event = JSON.parse(raw); if (test(event)) { socket.off('message', listener); resolve(event); } };
    socket.on('message', listener);
  });

  it('keeps a run going when its page closes and replays it to the next page', async () => {
    holdSlowFetch();
    const first = await open();
    first.send(JSON.stringify({ action: 'run_avit_batch', avits: `${SLOW} ${FP}`, modelLabel: 'Fixture model', provider: 'lmstudio', model: 'fixture', servicenow: { clientSecret: 'never-replayed-secret' } }));
    const announced = await waitFor(first, event => event.type === 'fp_run_start');
    assert.deepEqual(announced.avits, [SLOW, FP]); assert.equal(announced.model, 'Fixture model');
    await waitFor(first, event => event.avit === SLOW && event.stage === 'fetching');
    first.close();  // the user leaves the page mid-review
    await new Promise(resolve => setTimeout(resolve, 50));

    const second = await open();
    second.send(JSON.stringify({ action: 'avit_batch_attach' }));
    const replay = await waitFor(second, event => event.type === 'avit_batch_replay');
    assert.equal(replay.active, true, 'the run is still going after its page closed');
    assert.equal(replay.runId, announced.runId);
    assert.equal(replay.events[0].type, 'fp_run_start');
    assert.ok(replay.events.some(event => event.avit === SLOW && event.stage === 'fetching'), 'history before the page closed is replayed');
    assert.ok(!JSON.stringify(replay).includes('never-replayed-secret'), 'credentials from the start message are never recorded');
    gate.release();
    const complete = await waitFor(second, event => event.type === 'avit_batch_complete');
    assert.equal(complete.cancelled, false, 'closing the page did not cancel the run');
    assert.ok(second.seen.some(event => event.avit === FP && event.done), 'live events continue on the returning page');

    second.send(JSON.stringify({ action: 'avit_batch_attach' }));
    const later = await waitFor(second, event => event.type === 'avit_batch_replay' && !event.active);
    assert.equal(later.events.at(-1).type, 'avit_batch_complete', 'a finished run stays available to show its outcome');
    second.close();
  });

  it('allows one active run, and any page can stop it', async () => {
    holdSlowFetch();
    const a = await open(), b = await open();
    a.send(JSON.stringify({ action: 'run_avit_batch', avits: `${SLOW} ${FP}`, provider: 'lmstudio', model: 'fixture' }));
    await waitFor(a, event => event.avit === SLOW && event.stage === 'fetching');
    b.send(JSON.stringify({ action: 'run_avit_batch', avits: TP, provider: 'lmstudio', model: 'fixture' }));
    const busy = await waitFor(b, event => event.type === 'avit_batch_error');
    assert.equal(busy.code, 'run_active');
    b.send(JSON.stringify({ action: 'avit_batch_cancel' }));
    assert.equal((await waitFor(b, event => event.type === 'avit_batch_cancel_ack')).accepted, true);
    gate.release();
    const complete = await waitFor(a, event => event.type === 'avit_batch_complete');
    assert.equal(complete.cancelled, true);
    assert.ok(a.seen.some(event => event.avit === FP && event.stage === 'cancelled'), 'the remaining AVITs are reported cancelled');
    a.close(); b.close();
  });
  it('parses mixed AVIT/SCTASK/ISST lists and plans a deduplicated batch', () => {
    const parsed = parseBatchInput(' sctask1000001, AVIT0000001;AVIT0000002\n\nSCTASK1000002\tavit0000001 SCTASK1000001 isst0012345 ');
    assert.deepEqual(parsed.sctasks, ['SCTASK1000001', 'SCTASK1000002']);
    assert.deepEqual(parsed.issts, ['ISST0012345']);
    assert.deepEqual(parsed.avits, ['AVIT0000001', 'AVIT0000002']);
    assert.deepEqual(parsed.order, ['SCTASK1000001', 'AVIT0000001', 'AVIT0000002', 'SCTASK1000002', 'ISST0012345']);
    assert.throws(() => parseBatchInput('AVIT0000001, INC0001234'), /Not an AVIT, SCTASK, or ISST number: INC0001234/);
    assert.throws(() => parseBatchInput(' ,; '), /at least one/);
    // An ISST expands like a task: its AVITs join the plan in place and deduplicate against the rest.
    const withIsst = planBatch(['ISST0012345', 'AVIT0000001'], { ISST0012345: ['AVIT0000001', 'AVIT0000005'] }, 5);
    assert.deepEqual(withIsst.all, ['AVIT0000001', 'AVIT0000005']);
    assert.deepEqual(withIsst.shared, {});
    const plan = planBatch(parsed.order, { SCTASK1000001: ['AVIT0000009', 'AVIT0000001'], SCTASK1000002: ['AVIT0000002', 'AVIT0000008'] }, 3);
    assert.deepEqual(plan.all, ['AVIT0000009', 'AVIT0000001', 'AVIT0000002', 'AVIT0000008']);
    assert.deepEqual(plan.shared, { SCTASK1000002: ['AVIT0000002'] });
    assert.deepEqual(plan.kept, ['AVIT0000009', 'AVIT0000001', 'AVIT0000002']); assert.deepEqual(plan.skipped, ['AVIT0000008']);
    assert.equal(terminalResult('done', { outcome: { closed: true } }), 'closed');
    assert.equal(terminalResult('done', { outcome: { leftOpen: true } }), 'noted');
    assert.equal(terminalResult('out-of-scope'), 'skipped'); assert.equal(terminalResult('error'), 'error');
    assert.deepEqual(outcomeActions({ attached: true, closed: true, semgrep: ['✓ Published org-private rule x.tuned'] }, 'FALSE POSITIVE').map(item => item.kind), ['attached', 'closed', 'tuned']);
  });
  it('refuses to start until every required credential is configured', async () => {
    adoMissing = true;
    const socket = new WebSocket(base.replace('http:', 'ws:'), { origin: base });
    await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
    const event = await new Promise(resolve => {
      socket.on('message', raw => { const value = JSON.parse(raw); if (value.type === 'avit_batch_error' || value.type === 'avit_batch_start') resolve(value); });
      socket.send(JSON.stringify({ action: 'run_avit_batch', avits: FP, provider: 'lmstudio', model: 'fixture' }));
    });
    socket.close(); adoMissing = false;
    assert.equal(event.type, 'avit_batch_error'); assert.match(event.message, /Azure DevOps PAT \(threatlint ado login/);
  });
  it('redacts credential-like values from the flagged file and parses resolve output', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-red-'));
    fs.writeFileSync(path.join(dir, 'f.yaml'), `KEY: ${SECRET}\npath: some/dir/with-digits-123456789\n`);
    const { markdown, count } = redactSecrets(`value ${SECRET} and some/dir/with-digits-123456789`, dir, 'f.yaml');
    assert.equal(count, 1); assert.ok(!markdown.includes(SECRET)); assert.ok(markdown.includes('some/dir/with-digits-123456789'));
    assert.deepEqual(resolveOutcome('  ✓ Attached a\n  ! ServiceNow kept state 3 / \n').closed, 'state not applied');
  });
});
