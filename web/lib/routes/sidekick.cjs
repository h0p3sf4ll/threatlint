'use strict';

/**
 * Sidekick: portfolio reporting and bulk operations, driven through `threatlint sidekick …` so the CLI and
 * the Workbench behave identically. Quick reads are plain requests; long work (vReports, Find Projects,
 * powered loadouts, AVIT closure and reversal, bulk triage) runs as a job whose JSON-line progress the
 * page polls. One job of each kind runs at a time; a job can be cancelled.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { handle, HttpError } = require('../http.cjs');

const NAME = /^[\w .@+-]{3,80}$/;
const ID = /^[0-9a-f]{32}$/;
const REPO = /^[A-Za-z0-9._\- ]{1,200}$/;
const ORG = /^[A-Za-z0-9][A-Za-z0-9-]{0,49}$/;
const JOB_KINDS = new Set(['report', 'find', 'powered', 'avit-close', 'avit-reverse', 'triage']);
const MAX_JOBS_KEPT = 30;

function registerSidekickRoutes(app, { integrations = {} } = {}) {
  const avitBatch = require('../avit-batch.cjs');
  const run = integrations.sidekickCli || ((args, input) => cli(args, input));
  const jobs = new Map();

  /** Run `threatlint sidekick <args>`; resolve {code, json, error}. */
  function cli(args, input, onLine) {
    const pythonpath = [avitBatch.pythonPath(), process.env.PYTHONPATH].filter(Boolean).join(path.delimiter);
    return new Promise((resolve, reject) => {
      const child = spawn(avitBatch.python(), ['-c', 'from threatlint.cli import main; main()', 'sidekick', ...args],
        { env: { ...process.env, PYTHONPATH: pythonpath, PYTHONIOENCODING: 'utf-8' }, windowsHide: true });
      let stdout = '', stderr = '', pending = '';
      child.stdout.on('data', chunk => { stdout += chunk; });
      child.stderr.on('data', chunk => {
        stderr += chunk; pending += chunk;
        const lines = pending.split(/\r?\n/); pending = lines.pop();
        for (const line of lines) { try { onLine?.(JSON.parse(line)); } catch { /* plain log line */ } }
      });
      child.on('error', error => reject(error.code === 'ENOENT' ? new HttpError('Python was not found. Set THREATLINT_PYTHON.', 503) : error));
      child.on('close', code => {
        let json = null; try { json = JSON.parse(stdout.trim().split(/\r?\n/).pop() || 'null'); } catch { /* not JSON */ }
        const error = (stderr.trim().split(/\r?\n/).reverse().find(line => line.startsWith('ERROR:')) || '').replace(/^ERROR:\s*/, '');
        resolve({ code, json, error, child });
      });
      if (input !== undefined) child.stdin.end(input); else child.stdin.end();
      if (onLine) onLine({ type: 'started' }, child);
    });
  }

  async function call(args, input) {
    const result = await run(args, input);
    if (result.code !== 0) throw new HttpError(result.error || 'Sidekick command failed', 400);
    return result.json;
  }

  function startJob(kind, args, input) {
    if ([...jobs.values()].some(job => job.kind === kind && job.state === 'running')) throw new HttpError(`A ${kind} job is already running`, 409);
    const id = crypto.randomUUID();
    // Cancelling writes this file; the CLI polls it, so cancel works the same on Windows and macOS.
    const cancelFile = path.join(require('node:os').tmpdir(), `threatlint-sidekick-cancel-${id}`);
    const job = { id, kind, state: 'running', progress: null, log: [], result: null, error: null, startedAt: Date.now(), child: null, cancelFile };
    jobs.set(id, job);
    const onLine = (event, child) => {
      if (child) { job.child = child; return; }
      if (event.type === 'progress') job.progress = event;
      else if (event.type === 'log') { job.log.push(event.message); if (job.log.length > 200) job.log.shift(); }
    };
    const jobArgs = [...args, '--cancel-file', cancelFile];
    const runner = integrations.sidekickCli ? integrations.sidekickCli(jobArgs, input, onLine) : cli(jobArgs, input, onLine);
    Promise.resolve(runner).then(result => {
      job.state = result.code === 0 ? 'done' : job.state === 'cancelling' ? 'cancelled' : 'error';
      job.result = result.json; job.error = result.code === 0 ? null : result.error || 'Sidekick command failed';
      fs.rmSync(cancelFile, { force: true });
    }, error => { job.state = 'error'; job.error = error.message; fs.rmSync(cancelFile, { force: true }); });
    while (jobs.size > MAX_JOBS_KEPT) jobs.delete(jobs.keys().next().value);
    return { jobId: id };
  }

  const text = (value, max = 500) => (typeof value === 'string' ? value.trim().slice(0, max) : '');
  const int = (value, min, max, fallback) => { const n = Number.parseInt(value, 10); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback; };
  const need = (value, pattern, what) => { if (!pattern.test(value)) throw new HttpError(`Invalid ${what}`); return value; };

  // ── Reads ────────────────────────────────────────────────────────────────
  app.get('/api/sidekick/orgs', handle(() => call(['orgs'])));
  app.get('/api/sidekick/loadouts', handle(() => call(['loadouts'])));
  app.get('/api/sidekick/runs', handle(req => call(['runs', ...(req.query.loadout ? ['--loadout', text(req.query.loadout, 80)] : []),
    '--limit', String(int(req.query.limit, 1, 200, 20)), '--offset', String(int(req.query.offset, 0, 1e6, 0))])));
  app.get('/api/sidekick/runs/:id/rows', handle(req => call(['rows', need(req.params.id, ID, 'run'), '--project', text(req.query.project, 200),
    '--repository', text(req.query.repository, 200), '--limit', String(int(req.query.limit, 1, 1000, 100)), '--offset', String(int(req.query.offset, 0, 1e7, 0))])));
  app.get('/api/sidekick/runs/:id/workbook', handle(async (req, res) => {
    const runs = await call(['runs', '--limit', '200']);
    const found = (runs.runs || []).find(item => item.id === need(req.params.id, ID, 'run'));
    if (!found || !found.workbook || !fs.existsSync(found.workbook)) throw new HttpError('Workbook not found', 404);
    res.download(found.workbook, path.basename(found.workbook));
  }, { fallback: true }));
  app.get('/api/sidekick/trends', handle(req => call(['trends', need(text(req.query.loadout, 80), NAME, 'loadout'), '--months', String(int(req.query.months, 0, 120, 12))])));
  app.get('/api/sidekick/actions', handle(req => call(['actions', ...(req.query.id ? ['--id', need(String(req.query.id), ID, 'action')] : []), '--limit', String(int(req.query.limit, 1, 1000, 200))])));
  app.get('/api/sidekick/owner', handle(req => {
    if (req.query.email) return call(['owner', '--email', need(text(req.query.email, 200), /^[^\s@^]+@[^\s@^]+$/, 'email'), ...(req.query.refresh ? ['--refresh'] : [])]);
    return call(['owner', '--repository', need(text(req.query.repository, 200), REPO, 'repository'), '--project', need(text(req.query.project, 200), REPO, 'project'),
      ...(req.query.organization ? ['--organization', need(text(req.query.organization, 50), ORG, 'organization')] : [])]);
  }));

  // ── Changes ──────────────────────────────────────────────────────────────
  app.post('/api/sidekick/loadouts', handle(req => {
    const lines = Array.isArray(req.body?.entries) ? req.body.entries.map(e => [e.repo, e.project, e.organization].filter(Boolean).join(', ')).join('\n') : text(req.body?.text, 200_000);
    return call(['loadout-save', need(text(req.body?.name, 80), NAME, 'loadout name'), ...(req.body?.renameFrom ? ['--rename-from', text(req.body.renameFrom, 80)] : []),
      ...(req.body?.organization ? ['--organization', need(text(req.body.organization, 50), ORG, 'organization')] : [])], lines);
  }));
  app.delete('/api/sidekick/loadouts/:name', handle(req => call(['loadout-delete', need(String(req.params.name), NAME, 'loadout name')])));
  app.delete('/api/sidekick/runs/:id', handle(req => call(['run-delete', need(req.params.id, ID, 'run')])));
  app.post('/api/sidekick/branches', handle(req => call(['branches', need(text(req.body?.repository, 200), REPO, 'repository'), '--project', need(text(req.body?.project, 200), REPO, 'project'),
    ...(req.body?.organization ? ['--organization', need(text(req.body.organization, 50), ORG, 'organization')] : []), '--stale-days', String(int(req.body?.staleDays, 1, 365, 90))])));
  app.post('/api/sidekick/import', handle(async req => {
    const content = typeof req.body?.content === 'string' ? Buffer.from(req.body.content, 'base64') : null;
    if (!content || content.length < 100 || content.slice(0, 2).toString() !== 'PK') throw new HttpError('Upload an .xlsx workbook');
    const temp = path.join(require('node:os').tmpdir(), `threatlint-import-${crypto.randomUUID()}.xlsx`);
    fs.writeFileSync(temp, content, { mode: 0o600 });
    try {
      return await call(['import', temp, '--loadout', need(text(req.body?.loadout, 80), NAME, 'loadout'), ...(req.body?.date ? ['--date', need(text(req.body.date, 10), /^\d{4}-\d{2}-\d{2}$/, 'date')] : [])]);
    } finally { fs.rmSync(temp, { force: true }); }
  }));
  app.post('/api/sidekick/owner-cache/clear', handle(() => call(['owner-cache-clear'])));
  app.post('/api/sidekick/actions/purge', handle(req => call(['actions-purge', String(int(req.body?.days, 1, 3650, 90)), ...(req.body?.includeReversible ? ['--include-reversible'] : [])])));
  app.post('/api/sidekick/avit/search', handle(req => call(['avit-search', '--limit', String(int(req.body?.limit, 1, 500, 100)), '--offset', String(int(req.body?.offset, 0, 1e7, 0))],
    JSON.stringify(Array.isArray(req.body?.conditions) ? req.body.conditions.slice(0, 30) : []))));

  // ── Jobs ─────────────────────────────────────────────────────────────────
  app.post('/api/sidekick/jobs', handle(req => {
    const kind = String(req.body?.kind || '');
    if (!JOB_KINDS.has(kind)) throw new HttpError('Unknown job');
    const b = req.body || {};
    if (kind === 'report') return startJob(kind, ['report', need(text(b.loadout, 80), NAME, 'loadout'), '--stale-days', String(int(b.staleDays, 1, 365, 90)), '--workers', String(int(b.workers, 1, 32, 10)),
      ...(b.onlyFailedFrom ? ['--only-failed-from', need(String(b.onlyFailedFrom), ID, 'run')] : [])]);
    if (kind === 'find') return startJob(kind, ['find'], (Array.isArray(b.names) ? b.names : String(b.names || '').split(/\r?\n/)).map(n => String(n).trim()).filter(Boolean).slice(0, 5000).join('\n'));
    if (kind === 'powered') return startJob(kind, ['powered', need(String(b.id || ''), /^[a-z0-9-]{3,40}$/, 'powered loadout')]);
    if (kind === 'avit-close') {
      const reason = need(text(b.reason, 1000), /\S/, 'reason');
      const spec = Array.isArray(b.records) ? { records: b.records.slice(0, 5000).map(r => ({ sys_id: need(String(r.sysId || r.sys_id || ''), ID, 'record'), state: String(r.state ?? ''), active: String(r.active ?? 'true') })) }
        : { conditions: Array.isArray(b.conditions) ? b.conditions.slice(0, 30) : [] };
      return startJob(kind, ['avit-close', '--reason', reason, '--yes'], JSON.stringify(spec));
    }
    if (kind === 'avit-reverse') return startJob(kind, ['avit-reverse', need(String(b.actionId || ''), ID, 'action'), '--reason', need(text(b.reason, 1000), /\S/, 'reason'), '--yes']);
    return startJob(kind, ['triage', '--project', need(text(b.project, 200), /^[\w ./@-]{1,200}$/, 'project'), '--mode', b.mode === 'secrets' ? 'secrets' : 'sast',
      ...(b.mode === 'secrets' ? ['--secret-type', need(text(b.secretType, 200), /\S/, 'secret type')] : ['--rule', need(text(b.rule, 300), /^[\w.:-]+$/, 'rule')]),
      '--note', need(text(b.note, 1000), /\S/, 'note'), '--workers', String(int(b.workers, 1, 16, 4)), '--yes']);
  }));
  app.get('/api/sidekick/jobs/:id', handle(req => {
    const job = jobs.get(String(req.params.id));
    if (!job) throw new HttpError('Job not found', 404);
    return { id: job.id, kind: job.kind, state: job.state, progress: job.progress, log: job.log.slice(-20), result: job.result, error: job.error };
  }));
  app.post('/api/sidekick/jobs/:id/cancel', handle(req => {
    const job = jobs.get(String(req.params.id));
    if (!job) throw new HttpError('Job not found', 404);
    if (job.state === 'running') { job.state = 'cancelling'; fs.writeFileSync(job.cancelFile, 'cancel'); }
    return { state: job.state };
  }));
}

module.exports = { registerSidekickRoutes };
