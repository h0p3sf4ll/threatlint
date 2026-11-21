'use strict';

/** Session-scoped scans and server-owned fix plans. The client never supplies source edits. */
const crypto = require('node:crypto');
const fs = require('node:fs');
const { HttpError } = require('./http.cjs');
const { runCli } = require('./avit-batch.cjs');

const LIMIT = 25;
const FIX_RULES = new Set(['TL-DEBUG-ENABLED', 'TL-PY-YAML', 'TL-TLS-VERIFY-OFF']);
const copy = value => structuredClone(value);

function createSecurityScanner({ store, integrations = {}, onScanComplete = () => {}, isSessionBusy = () => false }) {
  const scans = new Map();
  const plans = new Map();
  const active = new Set();
  const controllers = new Map();
  const pending = new Set();
  let closed = false;
  const cli = integrations.securityScannerCli || integrations.threatlintCli || runCli;
  const sessionFor = id => store.sessions.get(id) || (() => { throw new HttpError('Session not found', 404); })();
  const repoFor = session => fs.realpathSync(session.repoPath);
  const checkIdle = session => {
    if (closed) throw new HttpError('Security scanner is closing', 503);
    if (active.has(repoFor(session)) || isSessionBusy(session.id)) throw new HttpError('This repository has an active scan, fix, or review; wait for it to finish', 409);
  };
  const scanFor = id => scans.get(id) || (() => { throw new HttpError('Scan not found', 404); })();
  async function invoke(args, input, signal) {
    const result = await cli(['security-scanner', ...args], { input: input === undefined ? undefined : JSON.stringify(input), signal });
    if (result.code !== 0) {
      let detail = 'Security scanner failed; no clean result is claimed';
      try { detail = JSON.parse(result.stderr).error || detail; } catch { /* stderr may contain source or credentials */ }
      throw new HttpError(detail);
    }
    try { return JSON.parse(result.stdout); } catch { throw new HttpError('Security scanner returned invalid output'); }
  }
  const engineArgs = engines => engines.flatMap(engine => ['--engine', engine]);
  function track(promise) { pending.add(promise); promise.then(() => pending.delete(promise), () => pending.delete(promise)); return promise; }
  function trim() {
    while (scans.size > LIMIT) {
      const oldest = [...scans.values()].find(item => item.status !== 'running');
      if (!oldest) break;
      scans.delete(oldest.id);
      for (const [id, plan] of plans) if (plan.scanId === oldest.id) plans.delete(id);
    }
  }
  async function completed(scan, session) {
    try { await onScanComplete(copy(scan), session); }
    catch { scan.ingestionStatus = 'failed'; scan.ingestionError = 'Scan finished but findings history could not be updated'; }
  }
  function start(body = {}) {
    const session = sessionFor(body.sessionId);
    checkIdle(session);
    const engines = body.engines ?? [];
    if (!Array.isArray(engines) || engines.length > 2 || engines.some(engine => !['semgrep', 'trivy'].includes(engine))) throw new HttpError('Choose supported scanner engines');
    if ([...scans.values()].filter(item => item.status === 'running').length >= 3) throw new HttpError('Three scans are already running', 429);
    const id = crypto.randomUUID();
    const controller = new AbortController();
    const repo = repoFor(session);
    const scan = { id, sessionId: session.id, status: 'running', startedAt: Date.now(), findings: [], engines: [], requestedEngines: [...new Set(engines)], coverage: { status: 'unknown' } };
    scans.set(id, scan); controllers.set(id, controller); active.add(repo); trim();
    void track((async () => {
      try {
        Object.assign(scan, await invoke(['scan', '--repo', repo, ...engineArgs(scan.requestedEngines)], undefined, controller.signal));
        await completed(scan, session);
      } catch (error) { scan.status = controller.signal.aborted ? 'cancelled' : 'failed'; scan.error = error.message; }
      finally { scan.finishedAt = Date.now(); controllers.delete(id); active.delete(repo); }
    })());
    return { id };
  }
  async function propose(id, body = {}) {
    const scan = scanFor(id);
    const session = sessionFor(scan.sessionId);
    checkIdle(session);
    if (!['completed', 'partial'].includes(scan.status)) throw new HttpError('Wait for a completed scan before proposing a fix');
    const repo = repoFor(session);
    if (scan.binding?.repository !== repo) throw new HttpError('The session repository changed; scan again', 409);
    active.add(repo);
    const controller = new AbortController();
    const operationId = crypto.randomUUID();
    controllers.set(operationId, controller);
    try {
      const plan = await invoke(['propose'], { scan, findingId: body.findingId }, controller.signal);
      const planId = crypto.randomUUID();
      plans.set(planId, { plan, scanId: id, sessionId: session.id, createdAt: Date.now() });
      while (plans.size > 100) plans.delete(plans.keys().next().value);
      return { ...copy(plan), id: planId, scanId: id, sessionId: session.id };
    } finally { active.delete(repo); controllers.delete(operationId); }
  }
  async function apply(id, body = {}) {
    const record = plans.get(id);
    if (!record) throw new HttpError('Fix proposal not found', 404);
    if (record.applied) throw new HttpError('This fix has already been applied', 409);
    if (record.plan.canApply === false) throw new HttpError(record.plan.applyUnavailableReason || 'Local application is unavailable; apply the reviewed diff manually and scan again. No files were changed.');
    const session = sessionFor(record.sessionId);
    checkIdle(session);
    const repo = repoFor(session);
    if (record.plan.binding.repository !== repo) throw new HttpError('The session repository changed; scan again', 409);
    // Auto-apply opt-in is explicit, narrow, and recorded. No global enablement or implied permission.
    const policy = body.policy;
    const auto = policy?.autoApply === true && Array.isArray(policy.rules) && policy.rules.length > 0
      && policy.rules.every(rule => FIX_RULES.has(rule)) && policy.rules.includes(record.plan.ruleId);
    if (body.confirm !== true && !auto) throw new HttpError('Review and confirm the proposed edit before applying');
    active.add(repo);
    const controller = new AbortController();
    const operationId = crypto.randomUUID();
    controllers.set(operationId, controller);
    try {
      const previous = scanFor(record.scanId);
      const result = await invoke(['apply', ...(body.confirm === true ? ['--confirm'] : []), ...engineArgs(previous.requestedEngines || [])], { plan: record.plan, policy: auto ? policy : undefined }, controller.signal);
      const scanId = crypto.randomUUID();
      const scan = { ...result.scan, id: scanId, sessionId: session.id, startedAt: Date.now(), finishedAt: Date.now(), requestedEngines: previous.requestedEngines || [], parentScanId: previous.id };
      scans.set(scanId, scan); record.applied = true; trim();
      await completed(scan, session);
      return { ...result, scan: copy(scan), scanId };
    } catch (error) {
      if (controller.signal.aborted) throw new HttpError('Fix interrupted; inspect repository content and rescan before retrying. No completed validation is claimed.');
      throw error;
    } finally { active.delete(repo); controllers.delete(operationId); }
  }
  return { start, propose: (...args) => track(propose(...args)), apply: (...args) => track(apply(...args)),
    get: id => copy(scanFor(id)),
    list: sessionId => [...scans.values()].filter(scan => !sessionId || scan.sessionId === sessionId).reverse().map(copy),
    isBusy: sessionId => { const session = store.sessions.get(sessionId); return !!session && active.has(repoFor(session)); },
    cancel(id) { scanFor(id); controllers.get(id)?.abort(); return { ok: true }; },
    async close() { closed = true; for (const controller of controllers.values()) controller.abort(); await Promise.allSettled([...pending]); },
  };
}

module.exports = { createSecurityScanner };
