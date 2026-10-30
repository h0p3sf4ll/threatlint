'use strict';

/**
 * DefectDojo / SonarQube review from the Workbench, one finding at a time:
 *   1. `threatlint dojo|sonar fetch`     – the findings, by reference or by filter
 *   2. `threatlint dojo|sonar checkout`  – the repository and branch the finding names (skipped when it names none)
 *   3. the Findings triage agent, with the selected model, against that checkout
 *   4. the report, saved to Findings as Markdown and Word (secret values from the flagged files are redacted first)
 * Nothing is written back during the run. Posting is a separate, explicit call per finding
 * (POST /api/scanners/:tool/resolve with {confirm: true}) that runs `threatlint dojo|sonar resolve --yes`.
 * The checkout is deleted as soon as the report is written.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { AGENTS } = require('./agents.cjs');
const { runModel, providerRequest, buildUserMessage } = require('./pipeline.cjs');
const { HttpError } = require('./http.cjs');
const scanners = require('./scanners.cjs');
const { runCli, redactSecrets } = require('./avit-batch.cjs');

const AGENT_ID = 'appsec-fp-reviewer';
const MAX_SEARCH = 200;
const lastLine = text => String(text).trim().split(/\r?\n/).filter(Boolean).pop() || '';
const errorOf = result => (lastLine(result.stderr) || lastLine(result.stdout)).replace(/^ERROR:\s*/, '');
const REFERENCE_HEADING = /^## ((?:DOJO-\d+)|(?:SONAR-(?:HOTSPOT-)?[A-Za-z0-9_-]{6,64}))\b/gm;

const DOJO_SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const SONAR_TYPES = ['VULNERABILITY', 'BUG', 'CODE_SMELL', 'SECURITY_HOTSPOT'];
const SONAR_SEVERITIES = ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO'];
const SONAR_STATUSES = ['OPEN', 'CONFIRMED', 'REOPENED', 'RESOLVED', 'CLOSED', 'ACCEPTED', 'TO_REVIEW', 'REVIEWED'];

const list = value => (Array.isArray(value) ? value : String(value ?? '').split(/[\s,]+/)).map(item => String(item).trim()).filter(Boolean);
function positiveInt(value, name) {
  if (value === undefined || value === null || value === '') return null;
  if (!/^\d{1,12}$/.test(String(value)) || Number(value) < 1) throw new HttpError(`${name} must be a positive id`);
  return String(Number(value));
}
function choices(values, allowed, name) {
  const bad = values.filter(value => !allowed.includes(value));
  if (bad.length) throw new HttpError(`${name} must be one of ${allowed.join(', ')}`);
  return values;
}

/** `fetch` arguments for a filter object; every value is validated so nothing reaches argv unchecked. */
function filterArgs(toolId, filter) {
  if (!filter || typeof filter !== 'object' || Array.isArray(filter)) return [];
  const args = [];
  const limit = filter.limit === undefined || filter.limit === '' ? 50 : Number(filter.limit);
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_SEARCH) throw new HttpError(`limit must be 1 to ${MAX_SEARCH}`);
  if (scanners.tool(toolId).id === 'dojo') {
    for (const [key, flag] of [['product', '--product'], ['engagement', '--engagement'], ['test', '--test']]) { const id = positiveInt(filter[key], key); if (id) args.push(flag, id); }
    for (const key of ['active', 'verified']) if (filter[key] !== undefined && filter[key] !== '') { if (!['true', 'false'].includes(String(filter[key]))) throw new HttpError(`${key} must be true or false`); args.push(`--${key}`, String(filter[key])); }
    for (const severity of choices(list(filter.severity), DOJO_SEVERITIES, 'severity')) args.push('--severity', severity);
    for (const tag of list(filter.tags)) { if (!/^[\w.:-]{1,100}$/.test(tag)) throw new HttpError('Tags may contain letters, digits, and . _ : - only'); args.push('--tag', tag); }
    if (!args.length) return [];
    if (!args.some(item => ['--product', '--engagement', '--test', '--tag'].includes(item))) throw new HttpError('Narrow the DefectDojo search with a product, engagement, test, or tag');
  } else {
    const project = String(filter.project || '').trim();
    if (!project) return [];
    if (!/^[\w.:-]{1,400}$/.test(project)) throw new HttpError('Not a SonarQube project key');
    args.push('--project', project);
    for (const [key, flag] of [['branch', '--branch'], ['pullRequest', '--pull-request'], ['organization', '--organization']]) {
      const value = String(filter[key] || '').trim();
      if (!value) continue;
      if (!/^[\w./@-]{1,250}$/.test(value) || value.startsWith('-')) throw new HttpError(`Not a valid ${key}`);
      args.push(flag, value);
    }
    for (const type of choices(list(filter.types), SONAR_TYPES, 'types')) args.push('--type', type);
    for (const severity of choices(list(filter.severities), SONAR_SEVERITIES, 'severities')) args.push('--severity', severity);
    for (const status of choices(list(filter.statuses), SONAR_STATUSES, 'statuses')) args.push('--status', status);
  }
  return [...args, '--limit', String(limit)];
}

function createScannerBatch({ store, reports, override, integrations = {} }) {
  const cli = integrations.threatlintCli || runCli;

  /** The session that holds scanner-review reports (the checkouts themselves are deleted). */
  function reviewSession(toolId) {
    const label = `${scanners.tool(toolId).label} reviews`;
    const existing = [...store.sessions.values()].find(session => session.provenance?.kind === 'scanner-review' && session.provenance?.tool === toolId && fs.existsSync(session.repoPath));
    if (existing) return existing.id;
    const directory = store.directory ? path.join(store.directory, `${scanners.tool(toolId).name}-reviews`) : fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-scanner-reviews-'));
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const id = store.create(directory);
    store.sessions.get(id).provenance = { kind: 'scanner-review', tool: toolId, repository: label };
    store.save();
    return id;
  }

  async function reviewOne(toolId, reference, { settings, message, signal, send, profile }) {
    const spec = scanners.tool(toolId);
    const step = (stage, detail = '', extra = {}) => send({ type: 'scanner_item', tool: toolId, reference, stage, detail, ...extra });
    const work = fs.mkdtempSync(path.join(os.tmpdir(), `threatlint-${spec.name}-`));
    const repo = path.join(work, 'repo');
    let sessionId = null;
    try {
      step('fetching', `Reading the finding from ${spec.label}`);
      const fetched = await cli([toolId, 'fetch', reference, ...profile, '-o', path.join(work, 'finding.md')], { signal });
      if (fetched.code !== 0) return step('error', errorOf(fetched), { done: true });
      step('checkout', 'Cloning the repository and branch the finding names');
      const checkout = await cli([toolId, 'checkout', reference, ...profile, '--dir', repo], { signal });
      const noRepository = checkout.code !== 0 && /names no usable repository/.test(`${checkout.stdout}${checkout.stderr}`);
      if (checkout.code !== 0 && !noRepository) return step('error', errorOf(checkout), { done: true });
      if (noRepository) fs.mkdirSync(repo, { recursive: true });
      let target = {};
      try { target = JSON.parse(lastLine(checkout.stdout)); } catch { /* context is in finding.md */ }
      step('triage', noRepository ? 'No repository on this finding; validating from its own evidence' : `${target.name || 'repository'} · ${target.branch || 'default branch'} · ${target.file_path || ''}`, { target });

      sessionId = store.create(repo, true, work);
      const attachment = { name: `${spec.name}-${reference}.md`, content: fs.readFileSync(path.join(work, 'finding.md'), 'utf8') };
      const guidance = [`Use finding ID FP-001 and write the Original finding line exactly as: **Original finding**: ${reference}; <rule>; <tool>; <path:line>.`,
        'Never write any secret, key, token, password, or connection-string value; refer to it by path:line and key name, and use [REDACTED] in excerpts.'].join('\n');
      const output = await runModel({ settings, systemPrompt: AGENTS[AGENT_ID].systemPrompt, repoPath: repo, signal, override, purpose: 'review', agentId: AGENT_ID,
        userMessage: buildUserMessage(repo, `${message.target || ''}\n${guidance}`.trim(), [], attachment),
        onEvent: event => { if (event.type === 'tool_executing') step('triage', '', { agentTool: event.tool }); } });
      if (signal.aborted) throw new Error('Cancelled');
      const { markdown, count } = redactSecrets(output, repo, target.file_path);
      const report = await reports.save(AGENT_ID, markdown, reviewSession(toolId), { title: `${spec.label} ${reference} triage`, source: { kind: 'scanner-review', tool: toolId, reference } });
      const finding = report.findings.find(item => scanners.mentions(item.body.match(/Original finding\W*:\s*(.+)/i)?.[1] || '', reference)) || null;
      const disposition = finding?.disposition || 'UNSPECIFIED';
      return step('reported', `${count ? `Report saved to Findings (${count} credential value${count > 1 ? 's' : ''} redacted)` : 'Report saved to Findings'}. Nothing was posted to ${spec.label}.`,
        { disposition, findingId: finding?.id || null, report: reports.metadata(report), done: true });
    } catch (error) {
      return step(signal.aborted ? 'cancelled' : 'error', signal.aborted ? 'Cancelled' : error.message, { done: true });
    } finally {
      // The checkout is a copy of another team's source and may hold live secrets.
      if (sessionId) { store.sessions.delete(sessionId); store.save(); }
      fs.rmSync(work, { recursive: true, force: true, maxRetries: 3 });
    }
  }

  async function run(message, send, controller) {
    const toolId = scanners.tool(message.tool).id;
    const spec = scanners.tool(toolId);
    const settings = providerRequest(message);
    scanners.connection(toolId);
    const profile = typeof message.awsProfile === 'string' && /^[\w.@+-]{1,128}$/.test(message.awsProfile) ? ['--aws-profile', message.awsProfile] : [];
    const explicit = String(message.references || '').trim() ? scanners.parseReferences(toolId, message.references) : [];
    const filter = filterArgs(toolId, message.filter);
    let found = [];
    if (filter.length) {
      const work = fs.mkdtempSync(path.join(os.tmpdir(), `threatlint-${spec.name}-search-`));
      try {
        const searched = await cli([toolId, 'fetch', ...filter, ...profile, '-o', path.join(work, 'findings.md')], { signal: controller.signal });
        if (searched.code !== 0) throw new HttpError(errorOf(searched) || `The ${spec.label} search failed`, 502);
        found = [...fs.readFileSync(path.join(work, 'findings.md'), 'utf8').matchAll(REFERENCE_HEADING)].map(match => match[1]);
      } finally { fs.rmSync(work, { recursive: true, force: true }); }
    }
    const all = [...new Set([...explicit, ...found])];
    if (!all.length) throw new HttpError(filter.length ? `The ${spec.label} search returned no findings` : `Enter ${spec.label} references or a filter`);
    if (all.length > scanners.MAX_REFERENCES) throw new HttpError(`Review at most ${scanners.MAX_REFERENCES} ${spec.label} findings at a time; narrow the filter or lower the limit`);
    send({ type: 'scanner_batch_start', tool: toolId, references: all });
    for (const reference of all) {
      if (controller.signal.aborted) { send({ type: 'scanner_item', tool: toolId, reference, stage: 'cancelled', detail: 'Cancelled', done: true }); continue; }
      await reviewOne(toolId, reference, { settings, message, signal: controller.signal, send, profile });
    }
    send({ type: 'scanner_batch_complete', tool: toolId, cancelled: controller.signal.aborted });
  }

  /** The explicit second step: `threatlint dojo|sonar resolve --yes` for one reviewed finding, only with {confirm: true}. */
  async function resolve(toolId, body = {}) {
    const spec = scanners.tool(toolId);
    if (body.confirm !== true) throw new HttpError(`Posting to ${spec.label} needs confirmation: send {"confirm": true} after the user confirms`);
    const [reference] = scanners.parseReferences(spec.id, body.reference);
    const located = typeof body.reportId === 'string' ? reports.find(body.reportId) : null;
    if (!located) throw new HttpError('Report not found', 404);
    const { report } = located;
    if (report.agentId !== AGENT_ID) throw new HttpError('Only Findings triage reports can be posted');
    const finding = reports.read(report).findings.find(item => scanners.mentions(item.body.match(/Original finding\W*:\s*(.+)/i)?.[1] || '', reference));
    if (!finding) throw new HttpError(`The report has no finding whose Original finding is ${reference}`);
    if (!['TRUE POSITIVE', 'FALSE POSITIVE', 'AMBIGUOUS'].includes(finding.disposition)) throw new HttpError(`${finding.id} has no TRUE POSITIVE / FALSE POSITIVE / AMBIGUOUS disposition`);
    if (spec.attachments && (!report.docxPath || !fs.existsSync(report.docxPath))) throw new HttpError('The Word report is unavailable; install python-docx so the report can be attached', 409);
    const args = [spec.id, 'resolve', reference, '--report', report.mdPath, '--yes'];
    if (report.docxPath && fs.existsSync(report.docxPath)) args.push('--docx', report.docxPath);
    if (spec.id === 'dojo' && body.semgrep !== true) args.push('--skip-semgrep');
    if (spec.id === 'sonar' && body.reportUrl) {
      let url;
      try { url = new URL(String(body.reportUrl)); } catch { throw new HttpError('The report location must be an https:// URL'); }
      if (url.protocol !== 'https:' || url.username || url.password) throw new HttpError('The report location must be an https:// URL');
      args.push('--report-url', url.href);
    }
    const result = await cli(args, {});
    const output = `${result.stdout}\n${result.stderr}`;
    if (result.code !== 0) throw new HttpError(errorOf(result) || `${spec.label} resolve failed`, 502);
    let outcome = {};
    try { outcome = JSON.parse(lastLine(result.stdout)); } catch { /* lines below still describe it */ }
    return { ok: true, reference, disposition: finding.disposition, outcome, lines: (output.match(/^\s*[✓!] .*$/gm) || []).map(line => line.trim()) };
  }

  return { run, resolve };
}

module.exports = { createScannerBatch, filterArgs };
