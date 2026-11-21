'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createSecurityScanner } = require('../lib/security-scanner.cjs');

const tick = () => new Promise(resolve => setImmediate(resolve));
function fixture(t, options = {}) {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'security-scanner-test-'));
  t.after(() => fs.rmSync(repo, { recursive: true, force: true }));
  const store = { sessions: new Map([['session', { id: 'session', repoPath: repo }], ['alias', { id: 'alias', repoPath: repo }]]) };
  const calls = [];
  const scan = { status: 'partial', binding: { repository: fs.realpathSync(repo), branch: 'main', commit: 'a'.repeat(40), contentDigest: 'b'.repeat(64) },
    findings: [{ id: 'finding', severity: 'MEDIUM', fixAvailable: true }], coverage: { status: 'partial' }, engines: [] };
  const plan = { status: 'proposed', binding: scan.binding, path: 'settings.py', ruleId: 'TL-DEBUG-ENABLED', findingId: 'finding', before: 'DEBUG = True', after: 'DEBUG = False' };
  const cli = async (args, input) => {
    calls.push({ args, ...input });
    return { code: 0, stdout: JSON.stringify(args[1] === 'scan' ? scan : args[1] === 'propose' ? plan : { status: 'applied', scan }), stderr: '' };
  };
  const scanner = createSecurityScanner({ store, integrations: { securityScannerCli: options.cli || cli }, ...options });
  t.after(() => scanner.close());
  return { scanner, calls, scan, plan, store };
}

test('session binding, explicit engine selection, and completion ingestion', async t => {
  const finished = [];
  const { scanner } = fixture(t, { onScanComplete: (scan, session) => finished.push([scan, session]) });
  assert.throws(() => scanner.start({ sessionId: 'missing' }), /Session not found/);
  assert.throws(() => scanner.start({ sessionId: 'session', engines: ['arbitrary'] }), /supported/);
  const { id } = scanner.start({ sessionId: 'session' });
  assert.throws(() => scanner.start({ sessionId: 'alias' }), /active scan/);
  await tick();
  assert.equal(scanner.get(id).status, 'partial');
  assert.equal(finished.length, 1);
  assert.equal(scanner.list('session').length, 1);
  assert.equal(scanner.list('missing').length, 0);
  const result = scanner.get(id); result.status = 'modified';
  assert.equal(scanner.get(id).status, 'partial');
});

test('server-owned proposal prevents arbitrary client edits and applies only after confirmation', async t => {
  const { scanner, calls } = fixture(t);
  const { id } = scanner.start({ sessionId: 'session' });
  await tick();
  const plan = await scanner.propose(id, { findingId: 'finding' });
  await assert.rejects(scanner.apply(plan.id, {}), /confirm/);
  const result = await scanner.apply(plan.id, { confirm: true, after: 'malicious client replacement' });
  assert.equal(result.status, 'applied');
  const applied = calls.find(call => call.args[1] === 'apply');
  assert.equal(JSON.parse(applied.input).plan.after, 'DEBUG = False');
  assert.ok(applied.signal);
  await assert.rejects(scanner.apply(plan.id, { confirm: true }), /already been applied/);
});

test('session repo changes and active reviews reject fix execution', async t => {
  let busy = false;
  const { scanner, store } = fixture(t, { isSessionBusy: () => busy });
  const { id } = scanner.start({ sessionId: 'session' });
  await tick();
  busy = true;
  await assert.rejects(scanner.propose(id, { findingId: 'finding' }), /active scan/);
  busy = false;
  store.sessions.get('session').repoPath = os.tmpdir();
  await assert.rejects(scanner.propose(id, { findingId: 'finding' }), /repository changed/);
});

test('shutdown aborts and drains a native scanner before resolving', async t => {
  let release, observedSignal;
  const { scanner } = fixture(t, { cli: (_args, { signal }) => new Promise(resolve => { observedSignal = signal; release = resolve; }) });
  const { id } = scanner.start({ sessionId: 'session' });
  let closed = false;
  const closing = scanner.close().then(() => { closed = true; });
  await tick();
  assert.equal(observedSignal.aborted, true);
  assert.equal(closed, false);
  release({ code: 1, stderr: '', stdout: '' });
  await closing;
  assert.equal(scanner.get(id).status, 'cancelled');
  assert.throws(() => scanner.start({ sessionId: 'session' }), /closing/);
});

test('shutdown drains apply and never asserts rollback when interrupted', async t => {
  const { scanner, scan, plan } = fixture(t);
  await scanner.close();
  let release, observedSignal;
  const source = createSecurityScanner({ store: { sessions: new Map([['session', { id: 'session', repoPath: scan.binding.repository }]]) }, integrations: {
    securityScannerCli: (args, { signal }) => args[1] === 'apply' ? new Promise(resolve => { observedSignal = signal; release = resolve; })
      : Promise.resolve({ code: 0, stdout: JSON.stringify(args[1] === 'scan' ? scan : plan) }),
  } });
  const { id } = source.start({ sessionId: 'session' }); await tick();
  const proposed = await source.propose(id, { findingId: 'finding' });
  const applying = source.apply(proposed.id, { confirm: true });
  const rejected = assert.rejects(applying, /No completed validation/);
  let closed = false;
  const closing = source.close().then(() => { closed = true; });
  await tick();
  assert.equal(observedSignal.aborted, true); assert.equal(closed, false);
  release({ code: 1, stderr: '', stdout: '' });
  await Promise.all([closing, rejected]);
});

test('automatic policy must explicitly name the proposed supported rule', async t => {
  const { scanner, plan, calls } = fixture(t);
  plan.ruleId = 'TL-PY-YAML';
  plan.before = 'value = yaml.load(data)'; plan.after = 'value = yaml.safe_load(data)';
  const { id } = scanner.start({ sessionId: 'session' }); await tick();
  const proposed = await scanner.propose(id, { findingId: 'finding' });
  await assert.rejects(scanner.apply(proposed.id, { policy: { autoApply: true, rules: ['TL-DEBUG-ENABLED'] } }), /confirm/);
  await assert.rejects(scanner.apply(proposed.id, { policy: { autoApply: true, rules: ['TL-PY-YAML', 'arbitrary'] } }), /confirm/);
  assert.equal(calls.filter(call => call.args[1] === 'apply').length, 0);
  const result = await scanner.apply(proposed.id, { policy: { autoApply: true, rules: ['TL-PY-YAML'] } });
  assert.equal(result.status, 'applied');
  assert.deepEqual(JSON.parse(calls.find(call => call.args[1] === 'apply').input).policy, { autoApply: true, rules: ['TL-PY-YAML'] });
});

test('unsupported local application remains a reviewable proposal and never invokes mutation', async t => {
  const { scanner, plan, calls } = fixture(t);
  plan.canApply = false;
  plan.applyUnavailableReason = 'Safe directory-relative replacement is unavailable; apply the reviewed diff manually. No files were changed.';
  const { id } = scanner.start({ sessionId: 'session' }); await tick();
  const proposed = await scanner.propose(id, { findingId: 'finding' });
  assert.equal(proposed.after, 'DEBUG = False');
  assert.equal(proposed.canApply, false);
  await assert.rejects(scanner.apply(proposed.id, { confirm: true }), /apply the reviewed diff manually.*No files were changed/);
  await assert.rejects(scanner.apply(proposed.id, { policy: { autoApply: true, rules: ['TL-DEBUG-ENABLED'] } }), /apply the reviewed diff manually/);
  assert.equal(calls.filter(call => call.args[1] === 'apply').length, 0);
});
