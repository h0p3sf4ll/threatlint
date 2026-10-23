'use strict';

/**
 * False-positive review of ServiceNow AVITs from the Workbench, one AVIT at a time. For each AVIT:
 *   1. `threatlint avit fetch`    – the AVIT (CodeSecurity, or another tool/view: no Semgrep step)
 *   2. `threatlint avit checkout` – its repository and branch, from the AVIT fields
 *   3. the Findings triage agent, with the selected model, against that checkout
 *   4. the report, written as Markdown and Word (secrets found in the flagged files are redacted first)
 *   5. `threatlint avit resolve`  – attach the Word report; close a false positive and tune Semgrep;
 *                                   leave a true positive open with a work note; deletes the checkout
 * ServiceNow, Git, and Semgrep work goes through the Python CLI so the Workbench and `/fp-review` behave
 * identically. Each AVIT gets its own report and its own closure; one AVIT failing does not stop the rest.
 * The report is not kept locally: it is attached to the AVIT, then its files and history entry are deleted.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { AGENTS } = require('./agents.cjs');
const { runModel, providerRequest, buildUserMessage } = require('./pipeline.cjs');
const servicenow = require('./servicenow.cjs');
const { HttpError } = require('./http.cjs');

const AGENT_ID = 'appsec-fp-reviewer';
const MAX_BATCH = 50;
const CLI_TIMEOUT_MS = 20 * 60_000;

/** The Python package: bundled in the desktop app's resources, or the repository's src/ in development. */
function pythonPath() {
  const bundled = process.resourcesPath && path.join(process.resourcesPath, 'python');
  if (bundled && fs.existsSync(path.join(bundled, 'threatlint', 'cli.py'))) return bundled;
  return path.resolve(__dirname, '../../src');
}

// Word export and the OS keychain need python-docx and keyring; prefer an interpreter on PATH that has both.
let chosenPython;
function python() {
  if (process.env.THREATLINT_PYTHON) return process.env.THREATLINT_PYTHON;
  if (chosenPython) return chosenPython;
  const { spawnSync } = require('node:child_process');
  const names = process.platform === 'win32' ? ['python', 'py'] : ['python3', 'python'];
  const candidates = String(process.env.PATH || '').split(path.delimiter).flatMap(dir => names.map(name => path.join(dir, process.platform === 'win32' ? `${name}.exe` : name))).filter(file => fs.existsSync(file));
  const score = file => { const probe = spawnSync(file, ['-c', 'import importlib.util as u;print(int(bool(u.find_spec("docx")))+int(bool(u.find_spec("keyring"))))'], { encoding: 'utf8', timeout: 10_000, windowsHide: true }); return Number(probe.stdout?.trim()) || 0; };
  chosenPython = candidates.map(file => [file, score(file)]).sort((a, b) => b[1] - a[1])[0]?.[0] || names[0];
  return chosenPython;
}

function runCli(args, { env = {}, signal } = {}) {
  const python = module.exports.python();
  const pythonpath = [pythonPath(), process.env.PYTHONPATH].filter(Boolean).join(path.delimiter);
  return new Promise((resolve, reject) => {
    const child = spawn(python, ['-c', 'from threatlint.cli import main; main()', ...args],
      { env: { ...process.env, PYTHONPATH: pythonpath, PYTHONIOENCODING: 'utf-8', ...env }, windowsHide: true, signal });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => child.kill(), CLI_TIMEOUT_MS);
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('error', error => { clearTimeout(timer); reject(error.code === 'ENOENT' ? new HttpError(`Python was not found (${python}). Set THREATLINT_PYTHON.`, 503) : error); });
    child.on('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}

const lastLine = text => String(text).trim().split(/\r?\n/).filter(Boolean).pop() || '';
const errorOf = result => (lastLine(result.stderr) || lastLine(result.stdout)).replace(/^ERROR:\s*/, '');

/**
 * Replace any long, credential-like value from the flagged file (and its directory) that appears in the
 * report. The agent is told never to print secrets; this is the enforcement.
 */
function redactSecrets(markdown, repo, filePath) {
  const target = filePath ? path.join(repo, filePath) : '';
  const files = new Set();
  if (target && fs.existsSync(target)) {
    files.add(target);
    for (const name of fs.readdirSync(path.dirname(target))) {
      const file = path.join(path.dirname(target), name);
      try { if (fs.statSync(file).isFile() && fs.statSync(file).size < 1024 * 1024) files.add(file); } catch { /* skip */ }
    }
  }
  const values = new Set();
  for (const file of files) {
    for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
      const match = /^\s*#?\s*["']?[\w.-]+["']?\s*[:=]\s*["']?([^"'\s#,]{16,})["']?/.exec(line);
      if (match && /\d/.test(match[1]) && /[A-Za-z]/.test(match[1]) && !match[1].includes('/')) values.add(match[1]);
    }
  }
  let redacted = markdown, count = 0;
  for (const value of values) {
    if (redacted.includes(value)) { redacted = redacted.split(value).join('[REDACTED]'); count++; }
  }
  return { markdown: redacted, count };
}

/** What `threatlint avit resolve` reported, from its output lines. */
function resolveOutcome(output) {
  const text = String(output);
  return {
    attached: /✓ Attached|is already attached/.test(text),
    closed: /✓ Closed as false positive/.test(text) ? true : /ServiceNow kept state/.test(text) ? 'state not applied' : false,
    leftOpen: /AVIT left open/.test(text),
    semgrep: (text.match(/^\s*[✓!] (?:Semgrep|Rule|Tuned|Published|.*already runs the tuned rule|.*enabled \().*$/gm) || []).map(line => line.trim()),
  };
}

function createAvitBatch({ store, reports, override, integrations = {} }) {
  const cli = integrations.threatlintCli || runCli;
  const semgrepVersion = integrations.semgrepVersion || servicenow.semgrepVersion;

  function validate(message) {
    const numbers = servicenow.parseAvitNumbers(message.avits);
    if (numbers.length > MAX_BATCH) throw new HttpError(`Review at most ${MAX_BATCH} AVITs at a time`);
    return { numbers, settings: providerRequest(message) };
  }

  /** Session-only ServiceNow values from the page; anything blank comes from the saved Threatlint config. */
  function cliEnv(message) {
    const snow = message.servicenow && typeof message.servicenow === 'object' ? message.servicenow : {};
    const env = {};
    if (snow.instance) env.THREATLINT_SNOW_INSTANCE = servicenow.validateInstanceUrl(snow.instance);
    if (snow.clientId && snow.clientSecret) { env.THREATLINT_SNOW_CLIENT_ID = String(snow.clientId); env.THREATLINT_SNOW_CLIENT_SECRET = String(snow.clientSecret); }
    return env;
  }

  async function reviewOne(avit, { settings, message, semgrep, env, profile, signal, send }) {
    const step = (stage, detail = '', extra = {}) => send({ type: 'avit_item', avit, stage, detail, ...extra });
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-avit-'));
    let created = null, sessionId = null;
    const repo = path.join(work, 'repo');
    try {
      step('fetching', 'Reading the AVIT from ServiceNow');
      const fetched = await cli(['avit', 'fetch', avit, ...profile, '-o', path.join(work, 'avit.md')], { env, signal });
      if (fetched.code !== 0) {
        const reason = errorOf(fetched);
        return step(/CodeSecurity view/.test(reason) ? 'out-of-scope' : 'error', reason, { done: true });
      }
      step('checkout', 'Cloning the AVIT repository and branch');
      const checkout = await cli(['avit', 'checkout', avit, ...profile, '--dir', repo], { env, signal });
      // AVITs from other tools often name no repository; review them from the AVIT evidence alone.
      const noRepository = checkout.code !== 0 && /names no repository/.test(`${checkout.stdout}${checkout.stderr}`);
      if (checkout.code !== 0 && !noRepository) return step('error', errorOf(checkout), { done: true });
      if (noRepository) fs.mkdirSync(repo, { recursive: true });
      let target = {};
      try { target = JSON.parse(lastLine(checkout.stdout)); } catch { /* the review still runs; context is in avit.md */ }
      if (noRepository) step('triage', 'No repository on this AVIT; validating from its own evidence');
      else step('triage', `${target.kind?.toUpperCase() || 'Finding'} in ${target.name || 'repository'} · ${target.branch || 'default branch'} · ${target.file_path || ''}`, { target });

      sessionId = store.create(repo, true, work);
      const session = store.sessions.get(sessionId);
      session.provenance = { provider: target.scm || null, repository: target.organization && target.name ? `${target.project || target.organization}/${target.name}` : target.name || null, branch: target.branch || null, webUrl: target.web_url || null, avit };
      const attachment = { name: `servicenow-${avit}.md`, content: fs.readFileSync(path.join(work, 'avit.md'), 'utf8') };
      const guidance = [
        `Use finding ID FP-001 and write the Original finding line exactly as: **Original finding**: ${avit}; <rule or vulnerability>; <scanner>; <path:line>.`,
        'Never write any secret, key, token, password, or connection-string value; refer to it by path:line, key name, and characterization, and use [REDACTED] in excerpts.',
        'For a SAST or Secrets FALSE POSITIVE, include the narrowest tuned rule (the original rule plus a pattern-not or sanitizer, id suffixed `.tuned`) in one ```yaml block directly after a line reading exactly `**Tuned rule**:`, optionally followed by `**Tuned rule fixtures**:` with a fenced block of `ruleid:`/`ok:` fixtures.',
      ].join('\n');
      const output = await runModel({ settings, systemPrompt: AGENTS[AGENT_ID].systemPrompt, repoPath: repo, signal, override, purpose: 'review', agentId: AGENT_ID,
        userMessage: buildUserMessage(repo, `${message.target || ''}\n${guidance}`.trim(), [], attachment, { avits: [avit], semgrep }),
        onEvent: event => { if (event.type === 'tool_executing') send({ type: 'avit_item', avit, stage: 'triage', tool: event.tool }); } });
      if (signal.aborted) throw new Error('Cancelled');
      const { markdown, count } = redactSecrets(output, repo, target.file_path);
      const report = await reports.save(AGENT_ID, markdown, sessionId);
      const finding = report.findings.find(item => (item.body.match(/Original finding\W*:\s*(.+)/i)?.[1] || '').toUpperCase().includes(avit)) || report.findings[0];
      const disposition = finding?.disposition || 'UNSPECIFIED';
      created = report;
      step('reported', count ? `Report written (${count} credential value${count > 1 ? 's' : ''} redacted)` : 'Report written', { disposition });
      if (!report.docxPath) return step('error', 'The Word report could not be generated (install python-docx for THREATLINT_PYTHON); nothing was attached or closed', { disposition, done: true });

      step('resolving', disposition === 'FALSE POSITIVE' ? 'Attaching the report, closing the AVIT, and tuning Semgrep' : disposition === 'TRUE POSITIVE' ? 'Attaching the report and adding the true-positive work note' : 'No change for this disposition');
      // Not cancellable: once ServiceNow writes start, they finish so an AVIT is never left half-updated.
      const resolved = await cli(['avit', 'resolve', avit, '--report', report.mdPath, '--docx', report.docxPath, '--checkout', repo, '--yes', ...profile], { env });
      const outcome = resolveOutcome(`${resolved.stdout}\n${resolved.stderr}`);
      return step(resolved.code === 0 ? 'done' : 'error', resolved.code === 0 ? 'Report attached to the AVIT in ServiceNow (not kept locally)' : errorOf(resolved), { disposition, outcome, done: true });
    } catch (error) {
      return step(signal.aborted ? 'cancelled' : 'error', signal.aborted ? 'Cancelled' : error.message, { done: true });
    } finally {
      // The checkout is a copy of another team's source and may hold live secrets. The report is kept only in ServiceNow.
      if (created) reports.remove(created);
      if (sessionId) { store.sessions.delete(sessionId); store.save(); }
      fs.rmSync(work, { recursive: true, force: true, maxRetries: 3 });
    }
  }

  async function run(message, send, controller) {
    const { numbers, settings } = validate(message);
    const semgrep = await semgrepVersion();
    if (!semgrep) throw Object.assign(new HttpError(servicenow.SEMGREP_INSTALL, 412), { code: 'semgrep_missing' });
    const env = cliEnv(message);
    const profile = typeof message.awsProfile === 'string' && /^[\w.@+-]{1,128}$/.test(message.awsProfile) ? ['--aws-profile', message.awsProfile] : [];
    send({ type: 'avit_batch_start', avits: numbers });
    for (const avit of numbers) {
      if (controller.signal.aborted) { send({ type: 'avit_item', avit, stage: 'cancelled', detail: 'Cancelled', done: true }); continue; }
      await reviewOne(avit, { settings, message, semgrep, env, profile, signal: controller.signal, send });
    }
    send({ type: 'avit_batch_complete', cancelled: controller.signal.aborted });
  }

  return { run };
}

module.exports = { createAvitBatch, redactSecrets, resolveOutcome, runCli, pythonPath, python };
