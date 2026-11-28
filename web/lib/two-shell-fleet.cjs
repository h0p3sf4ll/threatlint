'use strict';

/**
 * detect-xshell fleet scans: run the Python `threatlint detect-xshell fleet` command across a chosen subset, or all,
 * of the repositories and branches that connected GitHub / Azure DevOps credentials can read.
 *
 * - Selection is validated here against live source connections; nothing the client sends reaches argv unchecked.
 * - Tokens come from the sources facade (which refreshes saved GitHub App / Azure DevOps credentials first) and go
 *   to the child ONLY through THREATLINT_XSHELL_CREDENTIALS in its environment. They are never written to the
 *   targets file, argv, job state, errors, HTTP or MCP responses.
 * - The Python CLI reads repository trees and lockfiles through the provider APIs; nothing is cloned.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { HttpError } = require('./http.cjs');
const { superviseChild } = require('./child-lifecycle.cjs');

const SCHEMA = 'threatlint.detect-xshell/v1';
// Output written by a CLI built before the detect-xshell rename is still accepted.
const SCHEMAS = new Set([SCHEMA, 'threatlint.detect-2shell/v1']);
const RETAINED = 25;
const CONCURRENT = 2;
const MAX_CONNECTIONS = 16;
const MAX_REPOSITORIES = 1000;
const MAX_BRANCH_PATTERNS = 20;
const MAX_RECENT_EVENTS = 200;
const MAX_OUTPUT_BYTES = 64 * 1024 * 1024;
const TIMEOUT_MS = 3 * 60 * 60_000;
const STATUSES = new Set(['vulnerable', 'clean', 'not-applicable', 'error']);
const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const REPOSITORY_SEGMENT = /^[A-Za-z0-9_.][A-Za-z0-9 _.()-]{0,99}$/;
const BRANCH_PATTERN = /^[A-Za-z0-9._/*+-]{1,200}$/;
const copy = value => structuredClone(value);

function integer(value, fallback, min, max, label) {
  if (value === undefined || value === null || value === '') return fallback;
  if (!Number.isInteger(value) || value < min || value > max) throw new HttpError(`${label} must be a whole number from ${min} to ${max}`);
  return value;
}

function normalizeRepositories(value, connection) {
  if (value === undefined || value === 'all') return 'all';
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_REPOSITORIES) throw new HttpError(`Choose "all" or 1 to ${MAX_REPOSITORIES} repositories for each source`);
  const names = new Set();
  for (const raw of value) {
    if (typeof raw !== 'string') throw new HttpError('Repository names must be text');
    let parts = raw.trim().split('/');
    if (parts.length === 3 && connection.provider === 'azure-devops') {
      // The Workbench lists Azure DevOps repositories as organization/project/repository.
      if (parts[0].toLowerCase() !== String(connection.account || '').toLowerCase()) throw new HttpError('An Azure DevOps repository belongs to a different organization than its source');
      parts = parts.slice(1);
    }
    if (parts.length !== 2 || !parts.every(part => REPOSITORY_SEGMENT.test(part) && part.trim() === part && !part.includes('..'))) {
      throw new HttpError(connection.provider === 'github' ? 'Name GitHub repositories as owner/name' : 'Name Azure DevOps repositories as project/repository');
    }
    names.add(parts.join('/'));
  }
  return [...names].sort();
}

function normalizeBranches(value) {
  if (value === undefined || value === 'default') return 'default';
  if (value === 'all') return 'all';
  const list = typeof value === 'string' ? value.split(',') : value;
  if (!Array.isArray(list)) throw new HttpError('Choose the default branch, all branches, or a list of branch names');
  const patterns = [...new Set(list.map(item => (typeof item === 'string' ? item.trim() : item)).filter(item => item !== ''))];
  if (!patterns.length || patterns.length > MAX_BRANCH_PATTERNS) throw new HttpError(`Name 1 to ${MAX_BRANCH_PATTERNS} branches or wildcard patterns`);
  for (const pattern of patterns) {
    if (typeof pattern !== 'string' || !BRANCH_PATTERN.test(pattern) || pattern.includes('..') || pattern.includes('//')
        || pattern.startsWith('/') || pattern.startsWith('-') || pattern.endsWith('/') || pattern.endsWith('.lock')) {
      throw new HttpError('Branch names may use letters, numbers, . _ - / and * wildcards');
    }
  }
  return patterns;
}

/** Remove every token (and common encodings of it) from text that may reach a user. */
function redactor(tokens) {
  const secrets = tokens.flatMap(token => [token, encodeURIComponent(token), Buffer.from(`:${token}`).toString('base64'),
    Buffer.from(`x-access-token:${token}`).toString('base64')]).filter(secret => secret && secret.length >= 8);
  return text => {
    let value = String(text ?? '');
    for (const secret of secrets) value = value.split(secret).join('[REDACTED]');
    return value.replace(/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g, '[REDACTED]');
  };
}

function topSeverity(findings = []) {
  return findings.reduce((best, finding) => ((SEVERITY_RANK[finding.severity] ?? -1) > (SEVERITY_RANK[best] ?? -1) ? finding.severity : best), '');
}

/** The default runner: Python CLI with stderr streamed line by line for progress. */
function spawnCli(args, { env, signal, onStderrLine, command, spawnImpl = spawn }) {
  if (signal?.aborted) return Promise.reject(Object.assign(new Error('Run cancelled'), { name: 'AbortError' }));
  const batch = require('./avit-batch.cjs');
  const [executable, ...prefix] = command || [batch.python(), '-c', 'from threatlint.cli import main; main()'];
  const pythonpath = [batch.pythonPath(), process.env.PYTHONPATH].filter(Boolean).join(path.delimiter);
  return new Promise((resolve, reject) => {
    const child = spawnImpl(executable, [...prefix, ...args], {
      env: { ...process.env, PYTHONPATH: pythonpath, PYTHONIOENCODING: 'utf-8', ...env }, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '', buffered = '', tail = '';
    superviseChild(child, { signal, timeoutMs: TIMEOUT_MS, timeoutMessage: 'The detect-xshell fleet scan exceeded its three-hour limit',
      startMessage: 'Python could not start. Check THREATLINT_PYTHON.', resolve, reject,
      onClose: (code, finish) => { if (buffered) onStderrLine(buffered); finish(null, { code, stdout, stderr: tail }); } });
    child.stdout.on('data', chunk => { if (stdout.length < 1_000_000) stdout += chunk; });
    child.stderr.on('data', chunk => {
      buffered += chunk;
      const lines = buffered.split(/\r?\n/);
      buffered = lines.pop();
      if (buffered.length > 1_000_000) buffered = '';
      for (const line of lines) { onStderrLine(line); if (line.trim()) tail = line; }
    });
  });
}

/** Markdown in the two-tier report shape that gate_report.py and to_sarif.py parse. */
function markdownReport(job) {
  const result = job.result || { summary: {}, results: [] };
  const summary = result.summary || {};
  const findings = [];
  for (const target of result.results || []) for (const finding of target.findings || []) findings.push({ target, finding });
  findings.sort((a, b) => (SEVERITY_RANK[b.finding.severity] ?? -1) - (SEVERITY_RANK[a.finding.severity] ?? -1));
  const noFix = findings.filter(item => item.finding.fixAvailable === false).length;
  const level = findings.length ? topSeverity(findings.map(item => item.finding)) || 'HIGH' : (summary.errors ? 'UNKNOWN' : 'CLEAN');
  const where = target => [target.provider, target.organization, target.project, target.repository].filter(Boolean).join(' / ');
  const cell = value => String(value ?? '').replaceAll('|', '\\|').replaceAll('\n', ' ');
  const lines = [
    '# *-Shell Exposure Scan (fleet)', '',
    `**Date**: ${new Date(job.finishedAt || Date.now()).toISOString().slice(0, 10)}`,
    `**Scope**: ${summary.targets ?? 0} repository branches across ${job.selection.length} source connection(s)`,
    '**Reviewed by**: detect-xshell (Threatlint Workbench)', '', '---', '',
    '## TIER 1 — EXECUTIVE SUMMARY', '', '### *-Shell Risk Level', '', `**${level}**`, '',
    findings.length ? `${summary.vulnerable ?? 0} branch(es) resolve a version affected by the *-2Shell (React2Shell, Next.js, PHP2Shell, WP2Shell, Node2Shell) or *-4Shell (Log4Shell, Spring4Shell, Text4Shell, Java4Shell) advisories${summary.families ? ` (*-2Shell: ${summary.families['2Shell'] ?? 0} finding(s), *-4Shell: ${summary.families['4Shell'] ?? 0})` : ''}.`
      : summary.errors ? 'No affected versions were found in the branches that could be read, but some branches could not be scanned; this is not a clean result.'
        : 'No *-2Shell or *-4Shell affected versions were found in the scanned branches.', '',
    '| Targets | Scanned | Vulnerable | Clean | Not applicable | Errors | Critical | High | Medium |',
    '|---|---|---|---|---|---|---|---|---|',
    `| ${summary.targets ?? 0} | ${summary.scanned ?? 0} | ${summary.vulnerable ?? 0} | ${summary.clean ?? 0} | ${summary.notApplicable ?? 0} | ${summary.errors ?? 0} | ${summary.critical ?? 0} | ${summary.high ?? 0} | ${summary.medium ?? 0} |`, '',
    '### Recommended Immediate Action', '',
    findings.length ? `Upgrade each affected package or runtime (\`next\` / \`react-server-dom-*\`, \`log4j-core\`, Spring Framework or Boot, \`commons-text\`, PHP, WordPress core, Node.js / Brotli, the JDK) to the patched release on its line; where the line has no fix (${noFix} finding(s)), move to a supported line. Redeploy, hunt logs for \`\${jndi:\` and \`class.module\` payloads, and rotate secrets for any affected app that was internet-facing and unpatched.`
      : 'Keep this scan scheduled; re-run it when lockfiles, Maven/Gradle builds, vendored jars or runtime pins (Dockerfiles, .nvmrc, .tool-versions) change.', '', '---', '',
    '## TIER 2 — TECHNICAL SCAN RESULTS', '', '### Findings', '',
  ];
  let index = 0;
  for (const { target, finding } of findings) {
    index += 1;
    const id = `TS-${String(index).padStart(3, '0')}`;
    lines.push(`#### [${id}] — ${cell(finding.title || finding.advisory || 'Affected framework version')}`, '',
      `**Severity**: ${finding.severity || 'HIGH'}`, `**Confidence**: ${finding.confidence || 'PLAUSIBLE'}`, '',
      '| Field | Detail |', '|-------|--------|',
      `| Family | ${finding.family ? `*-${cell(finding.family)}` : '—'} |`,
      `| Repository | ${cell(where(target))} |`,
      `| Branch | ${cell(target.branch)}${target.commit ? ` @ ${cell(String(target.commit).slice(0, 12))}` : ''} |`,
      `| Package | ${cell(finding.package)}@${cell(finding.version)} → ${finding.fixAvailable === false ? `**No fix on this line**: ${cell(finding.fixedIn || 'move to a supported line')}` : cell(finding.fixedIn || 'move to a supported line')} |`,
      `| Fix available | ${finding.fixAvailable === false ? 'No — impacted, move to a supported release line' : 'Yes'} |`,
      `| Location | \`${cell(finding.file || 'package.json')}:${Number.isInteger(finding.line) ? finding.line : 1}\` |`,
      `| CVEs | ${cell((finding.cves || []).join(', '))} |`,
      `| Exposure | ${cell(finding.exposure)} |`,
      `| Remediation | ${cell(finding.remediation)} |`, '');
  }
  if (!findings.length) lines.push('No findings.', '');
  const errors = (result.results || []).filter(target => target.status === 'error');
  if (errors.length) {
    lines.push('### Coverage gaps', '', '| Repository | Branch | Reason |', '|---|---|---|');
    for (const target of errors.slice(0, 500)) lines.push(`| ${cell(where(target))} | ${cell(target.branch)} | ${cell(target.error || 'Could not be scanned')} |`);
    lines.push('');
  }
  lines.push('### Residual Risk', '', 'detect-xshell reads declared and resolved dependency versions (npm lockfiles, Maven, Gradle, vendored jars) and pinned runtime versions (Dockerfile FROM tags, .nvmrc, .tool-versions, setup-* versions, WordPress core). It does not prove a deployed build matches the branch, and it does not probe live hosts. Version-only findings stay PLAUSIBLE until exposure is confirmed (App Router / Server Functions, WAR on a servlet container, StringSubstitutor interpolation, Brotli decompression of untrusted data, AVX-512 VBMI CPUs for Java4Shell).', '');
  return lines.join('\n');
}

function createTwoShellFleet({ sources, integrations = {} } = {}) {
  const jobs = new Map();
  const controllers = new Map();
  const pending = new Set();
  let closed = false;
  const runner = integrations.twoShellCli || ((args, options) => spawnCli(args, { ...options, command: integrations.twoShellCommand, spawnImpl: integrations.twoShellSpawn }));
  const jobFor = id => jobs.get(id) || (() => { throw new HttpError('Scan not found', 404); })();
  const running = () => [...jobs.values()].filter(job => job.status === 'running').length;

  function trim() {
    while (jobs.size > RETAINED) {
      const oldest = [...jobs.values()].find(job => job.status !== 'running');
      if (!oldest) break;
      jobs.delete(oldest.id);
    }
  }

  async function plan(body) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new HttpError('Send a scan selection');
    if (!sources || typeof sources.list !== 'function') throw new HttpError('Source connections are unavailable', 503);
    const requested = body.connections;
    if (!Array.isArray(requested) || requested.length === 0) throw new HttpError('Choose at least one connected source');
    if (requested.length > MAX_CONNECTIONS) throw new HttpError(`Choose at most ${MAX_CONNECTIONS} sources`);
    const live = new Map((await sources.list()).filter(item => item.connected !== false).map(item => [item.id, item]));
    const seen = new Set();
    const selection = requested.map(item => {
      if (!item || typeof item !== 'object') throw new HttpError('Each source selection needs a connectionId');
      const connection = live.get(item.connectionId);
      if (typeof item.connectionId !== 'string' || !connection) throw new HttpError('A selected source is not connected. Refresh Connected accounts and try again.');
      if (seen.has(item.connectionId)) throw new HttpError('Each source can be selected once');
      seen.add(item.connectionId);
      if (!['github', 'azure-devops'].includes(connection.provider)) throw new HttpError('detect-xshell supports GitHub and Azure DevOps sources');
      return { connectionId: connection.id, provider: connection.provider, label: connection.label || `${connection.provider} · ${connection.account}`,
        account: connection.account, repositories: normalizeRepositories(item.repositories, connection), branches: normalizeBranches(item.branches) };
    });
    return {
      selection,
      workers: integer(body.workers, 4, 1, 8, 'Workers'),
      maxRepositories: integer(body.maxRepositories, 500, 1, 10_000, 'Maximum repositories'),
      maxBranchesPerRepository: integer(body.maxBranchesPerRepository, 50, 1, 500, 'Maximum branches per repository'),
    };
  }

  function onProgress(job, redact, line) {
    const text = line.trim();
    if (!text.startsWith('{')) return; // Free-form stderr may contain source content; never retain it.
    let event;
    try { event = JSON.parse(text); } catch { return; }
    if (event?.event === 'plan' && Number.isInteger(event.total) && event.total >= 0) job.progress.total = event.total;
    else if (event?.event === 'target' && STATUSES.has(event.status)) {
      const key = { vulnerable: 'vulnerable', clean: 'clean', 'not-applicable': 'notApplicable', error: 'errors' }[event.status];
      job.progress.done += 1; job.progress[key] += 1;
      if (Number.isInteger(event.total) && event.total > job.progress.total) job.progress.total = event.total;
      job.recent.push({ provider: redact(event.provider).slice(0, 40), repository: redact(event.repository).slice(0, 300),
        branch: redact(event.branch).slice(0, 255), status: event.status });
      if (job.recent.length > MAX_RECENT_EVENTS) job.recent.splice(0, job.recent.length - MAX_RECENT_EVENTS);
    } else if (event?.event === 'error' && typeof event.error === 'string') job.lastError = redact(event.error).slice(0, 300);
  }

  function readResult(file, redact) {
    let stat;
    try { stat = fs.statSync(file); } catch { throw new HttpError('detect-xshell finished without writing results'); }
    if (!stat.isFile() || stat.size > MAX_OUTPUT_BYTES) throw new HttpError('detect-xshell results are missing or too large');
    let result;
    try { result = JSON.parse(redact(fs.readFileSync(file, 'utf8'))); } catch { throw new HttpError('detect-xshell returned invalid results'); }
    if (!SCHEMAS.has(result?.schema) || !Array.isArray(result.results) || !result.summary || typeof result.summary !== 'object') throw new HttpError('detect-xshell returned results in an unexpected format');
    return result;
  }

  async function execute(job, settings, controller) {
    let directory;
    const tokens = [];
    let redact = redactor(tokens);
    try {
      const connections = [];
      for (const item of settings.selection) {
        const credential = await sources.credentialFor(item.connectionId);
        if (!credential?.token || credential.provider !== item.provider) throw new HttpError('A selected source credential could not be refreshed. Refresh Connected accounts and try again.', 503);
        tokens.push(credential.token);
        connections.push({ id: item.connectionId, provider: credential.provider, token: credential.token,
          ...(credential.organization ? { organization: credential.organization } : item.provider === 'azure-devops' ? { organization: item.account } : {}),
          ...(credential.kind ? { kind: credential.kind } : {}), ...(credential.apiBase ? { apiBase: credential.apiBase } : {}) });
      }
      redact = redactor(tokens);
      if (controller.signal.aborted) throw Object.assign(new Error('Run cancelled'), { name: 'AbortError' });
      directory = fs.mkdtempSync(path.join(integrations.tmpdir || os.tmpdir(), 'threatlint-xshell-'));
      const targetsFile = path.join(directory, 'targets.json');
      const outputFile = path.join(directory, 'results.json');
      fs.writeFileSync(targetsFile, JSON.stringify({
        connections: settings.selection.map(item => ({ connection: item.connectionId, repositories: item.repositories, branches: item.branches })),
        maxRepositories: settings.maxRepositories, maxBranchesPerRepository: settings.maxBranchesPerRepository,
      }), { mode: 0o600 });
      const outcome = await runner(['detect-xshell', 'fleet', '--targets-file', targetsFile, '--format', 'json', '--output', outputFile, '--progress', '--workers', String(settings.workers)], {
        env: { THREATLINT_XSHELL_CREDENTIALS: JSON.stringify({ connections }) }, signal: controller.signal,
        onStderrLine: line => onProgress(job, redact, line),
      });
      if (outcome.code !== 0) {
        let detail = job.lastError || '';
        try { detail = JSON.parse(String(outcome.stderr || '').trim()).error || detail; } catch { /* free-form stderr is never shown */ }
        throw new HttpError(detail ? `detect-xshell failed: ${redact(detail).slice(0, 300)}` : 'detect-xshell failed; no clean result is claimed');
      }
      job.result = readResult(outputFile, redact);
      job.summary = job.result.summary;
      job.status = 'completed';
    } catch (error) {
      job.status = controller.signal.aborted ? 'cancelled' : 'failed';
      job.error = controller.signal.aborted ? 'Scan cancelled; partial results are not reported as clean' : redact(error?.status ? error.message : 'detect-xshell could not complete; no clean result is claimed').slice(0, 400);
    } finally {
      tokens.length = 0;
      job.finishedAt = Date.now();
      controllers.delete(job.id);
      if (directory) fs.rmSync(directory, { recursive: true, force: true });
    }
  }

  async function start(body) {
    if (closed) throw new HttpError('detect-xshell is closing', 503);
    const settings = await plan(body);
    if (running() >= CONCURRENT) throw new HttpError(`${CONCURRENT} detect-xshell scans are already running; wait for one to finish`, 429);
    const id = crypto.randomUUID();
    const controller = new AbortController();
    const job = { id, status: 'running', startedAt: Date.now(), finishedAt: null, workers: settings.workers,
      selection: settings.selection.map(({ connectionId, provider, label, repositories, branches }) => ({ connectionId, provider, label,
        repositories: repositories === 'all' ? 'all' : repositories, branches })),
      progress: { total: 0, done: 0, vulnerable: 0, clean: 0, notApplicable: 0, errors: 0 }, recent: [], summary: null, result: null, error: null, lastError: null };
    jobs.set(id, job); controllers.set(id, controller); trim();
    const work = execute(job, settings, controller);
    pending.add(work); work.finally(() => pending.delete(work));
    return { id, status: job.status };
  }

  function view(job, { results = false } = {}) {
    const { result, lastError, ...rest } = job;
    return copy({ ...rest, ...(results && result ? { result } : {}),
      topSeverity: result ? topSeverity((result.results || []).flatMap(target => target.findings || [])) : '' });
  }

  return {
    start,
    list: () => [...jobs.values()].reverse().map(job => view(job)),
    get: (id, options = {}) => view(jobFor(id), { results: options.results !== false }),
    report(id, format = 'json') {
      const job = jobFor(id);
      if (job.status !== 'completed') throw new HttpError('The report is available when the scan completes', 409);
      if (format === 'markdown') return { contentType: 'text/markdown; charset=utf-8', filename: `detect-xshell-${id}.md`, body: markdownReport(job) };
      if (format === 'json') return { contentType: 'application/json; charset=utf-8', filename: `detect-xshell-${id}.json`, body: JSON.stringify(job.result, null, 2) };
      throw new HttpError('Choose json or markdown');
    },
    cancel(id) { const job = jobFor(id); controllers.get(id)?.abort(); return { ok: true, status: job.status }; },
    get active() { return running() > 0; },
    async close() { closed = true; for (const controller of controllers.values()) controller.abort(); await Promise.allSettled([...pending]); },
  };
}

module.exports = { createTwoShellFleet, markdownReport, normalizeBranches, normalizeRepositories, spawnCli, SCHEMA };
