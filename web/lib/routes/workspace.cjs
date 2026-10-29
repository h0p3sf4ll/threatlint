'use strict';

/** Catalog, workspaces (local folders and HTTPS clones), reports, and the local model list. */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { AGENTS, SKILLS, publicAgent } = require('../agents.cjs');
const { parseReport } = require('../reports.cjs');
const { validateBaseUrl } = require('../providers.cjs');
const { handle, HttpError } = require('../http.cjs');
const servicenow = require('../servicenow.cjs');
const catalog = require('../model-catalog.cjs');
const threatlintConfig = require('../threatlint-config.cjs');

const execFileAsync = promisify(execFile);
const CLONE_TIMEOUT_MS = 300_000;
const MODEL_LIST_TIMEOUT_MS = 5000;
const EXAMPLES = path.join(__dirname, '../../examples');
const expandHome = value => value.replace(/^~(?=\/|$)/, os.homedir());

function registerWorkspaceRoutes(app, { store, reports, build, integrations = {} }) {
  const credentialSources = integrations.credentialSources || catalog.credentialSources;
  const { sessions } = store;
  const sessionFor = id => sessions.get(id) || (() => { throw new HttpError('Session not found', 404); })();

  app.get('/api/config', handle(async () => ({ desktop: !!process.versions.electron, persistent: !!store.directory, build,
    providers: await credentialSources(),
    semgrep: await (integrations.semgrepVersion || servicenow.semgrepVersion)(), semgrepAgents: [...servicenow.SEMGREP_AGENTS],
    servicenow: { ...servicenow.access(), instance: process.env.THREATLINT_SNOW_INSTANCE || '' } })));
  // Uses the local user's own AWS CLI session (from SSO); values return only to this loopback UI and are not stored.
  app.post('/api/servicenow/parameter-store', handle(req => (integrations.readParameterStore || servicenow.readParameterStore)({ profile: req.body?.profile || undefined })));
  // Saved ServiceNow connection (shared with the CLI). GET never returns the secret.
  app.get('/api/servicenow/settings', handle(() => threatlintConfig.publicServiceNow()));
  app.post('/api/servicenow/settings', handle(req => {
    const body = req.body || {};
    const saved = threatlintConfig.readServiceNow();
    const instance = body.instance ? servicenow.validateInstanceUrl(body.instance) : '';
    const clientId = typeof body.clientId === 'string' ? body.clientId.trim() : '';
    // An omitted secret keeps the saved one, so the masked field can be left untouched.
    const clientSecret = typeof body.clientSecret === 'string' && body.clientSecret.trim() ? body.clientSecret.trim() : saved.clientSecret;
    if (clientId.length > 500 || clientSecret.length > 2000) throw new HttpError('ServiceNow client ID or secret is too long');
    if ((clientId || clientSecret) && !(instance && clientId && clientSecret)) throw new HttpError('ServiceNow needs the instance URL, client ID, and client secret together');
    if (!instance && !clientId) { threatlintConfig.clearServiceNow(); return threatlintConfig.publicServiceNow(); }
    threatlintConfig.writeServiceNow({ instance, clientId, clientSecret });
    return threatlintConfig.publicServiceNow();
  }));
  // Semgrep API token for rule tuning and triage. GET never returns the token.
  // Also reports a token the CLI saved in the OS credential store (`threatlint semgrep login`), by source only.
  app.get('/api/semgrep/settings', handle(async () => {
    const saved = threatlintConfig.publicSemgrep();
    if (saved.hasToken && !saved.inKeyring) return saved;
    try {
      const result = await (integrations.threatlintCli || require('../avit-batch.cjs').runCli)(['semgrep', 'status']);
      const source = /^Semgrep token: (.+)$/m.exec(result.stdout)?.[1] || null;
      return { ...saved, cliSource: source };
    } catch { return saved; }
  }));
  app.post('/api/semgrep/settings', handle(async req => {
    const token = typeof req.body?.token === 'string' ? req.body.token.trim() : '';
    const current = threatlintConfig.readSemgrep();
    if (!token) return threatlintConfig.publicSemgrep();
    if (!/^[A-Za-z0-9._~+/=-]{20,200}$/.test(token)) throw new HttpError('That does not look like a Semgrep API token');
    const api = `${(process.env.THREATLINT_SEMGREP_API || 'https://semgrep.dev').replace(/\/$/, '')}/api/v1/deployments`;
    let response;
    try { response = await (integrations.fetchImpl || fetch)(api, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(15_000) }); }
    catch (error) { throw new HttpError(`Semgrep could not be reached: ${error.cause?.message || error.message}`, 502); }
    if (!response.ok) throw new HttpError(`Semgrep rejected the token (HTTP ${response.status})`, 400);
    const deployments = (await response.json()).deployments || [];
    threatlintConfig.writeSemgrep({ token, deployment: deployments.length === 1 ? deployments[0].slug : current.deployment });
    return threatlintConfig.publicSemgrep();
  }));
  // Azure DevOps PAT, shared with `threatlint ado login` (OS credential store when available). Never returned.
  const cli = (...args) => (integrations.threatlintCli || require('../avit-batch.cjs').runCli)(...args);
  const adoStatus = async () => {
    const result = await cli(['ado', 'status']);
    // One line per organization with a saved PAT (sources only, never the PAT).
    const sources = [...result.stdout.matchAll(/^Azure DevOps PAT: (.+)$/gm)].map(match => match[1]);
    const organizations = sources.map(line => /^(.*) · ([A-Za-z0-9-]+)$/.exec(line)).filter(Boolean).map(([, source, name]) => ({ name, source }));
    return { hasPat: sources.length > 0, source: sources.join('; ') || null, organizations };
  };
  app.delete('/api/ado/settings/:organization', handle(async req => {
    const organization = String(req.params.organization || '');
    if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,49}$/.test(organization)) throw new HttpError('Invalid Azure DevOps organization');
    await cli(['ado', 'logout', '--organization', organization]);
    return adoStatus();
  }));
  app.get('/api/ado/settings', handle(adoStatus));
  app.post('/api/ado/settings', handle(async req => {
    const organization = typeof req.body?.organization === 'string' ? req.body.organization.trim() : '';
    const pat = typeof req.body?.pat === 'string' ? req.body.pat.trim() : '';
    if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,49}$/.test(organization)) throw new HttpError('Enter the Azure DevOps organization name (e.g. contoso), not a URL');
    if (!/^[A-Za-z0-9._~+/=-]{20,200}$/.test(pat)) throw new HttpError('That does not look like an Azure DevOps PAT');
    const result = await cli(['ado', 'login', '--organization', organization, '--pat-stdin'], { input: pat });
    if (result.code !== 0) throw new HttpError((result.stderr.trim().split(/\r?\n/).pop() || 'Azure DevOps rejected the PAT').replace(/^ERROR:\s*/, ''), 400);
    return adoStatus();
  }));
  // Required credentials for AVIT review, by source only (`threatlint setup --check`).
  app.get('/api/setup/status', handle(async () => ({ items: await require('../avit-batch.cjs').setupStatus(integrations.threatlintCli) })));
  app.get('/api/agents', (_req, res) => res.json(Object.values(AGENTS).map(publicAgent)));
  app.get('/api/skills', (_req, res) => res.json(Object.values(SKILLS)));
  app.get('/api/examples/fp-review', (_req, res) => res.json({ ...parseReport(fs.readFileSync(path.join(EXAMPLES, 'fp-review.md'), 'utf8'), 'appsec-fp-reviewer'), example: true }));
  app.get('/api/examples/runtime', (_req, res) => res.json(JSON.parse(fs.readFileSync(path.join(EXAMPLES, 'runtime-scan.json'), 'utf8'))));

  // Models the configured (or session) credential can use, for the settings dropdown. POST keeps a typed key out of URLs and logs.
  app.post('/api/models', handle(async req => {
    const provider = String(req.body?.provider || '');
    if (!['claude', 'openai', 'copilot'].includes(provider)) throw new HttpError('Unknown model provider');
    const credential = await (integrations.resolveKey || catalog.resolveKey)(provider, req.body?.key);
    return { source: credential.source, models: await catalog.listModels(provider, credential, { fetchImpl: integrations.fetchImpl }) };
  }));
  app.get('/api/lmstudio/models', handle(async req => {
    const baseUrl = validateBaseUrl(typeof req.query.baseUrl === 'string' ? req.query.baseUrl : undefined);
    let data;
    try {
      const response = await fetch(`${baseUrl}/models`, { signal: AbortSignal.timeout(MODEL_LIST_TIMEOUT_MS), redirect: 'error' });
      if (!response.ok) throw new Error(`Model server returned HTTP ${response.status}`);
      data = await response.json();
    } catch (error) { throw new HttpError(`Cannot load model list: ${error.message}`, 503); }
    return { models: (data.data || []).map(model => model.id).filter(id => typeof id === 'string') };
  }));

  app.get('/api/fs/browse', handle(req => {
    let requested;
    try { requested = fs.realpathSync(expandHome(typeof req.query.path === 'string' ? req.query.path : os.homedir())); } catch (error) { throw new HttpError(`Cannot browse directory: ${error.message}`); }
    if (!fs.statSync(requested).isDirectory()) throw new HttpError('Not a directory');
    const entries = fs.readdirSync(requested, { withFileTypes: true }).filter(entry => entry.isDirectory())
      .map(entry => ({ name: entry.name, isRepo: fs.existsSync(path.join(requested, entry.name, '.git')) }))
      .sort((a, b) => Number(b.isRepo) - Number(a.isRepo) || a.name.localeCompare(b.name));
    return { path: requested, parent: path.dirname(requested) === requested ? null : path.dirname(requested), entries };
  }));

  app.get('/api/sessions', (_req, res) => res.json([...sessions.values()].map(session => ({ id: session.id, repoPath: session.repoPath,
    reportCount: session.reports.length, createdAt: session.createdAt, updatedAt: session.updatedAt })).sort((a, b) => b.updatedAt - a.updatedAt)));

  // The repository path is chosen by the local user on purpose: this loopback runner reviews their own folders.
  app.post('/api/session/local', handle(req => {
    if (typeof req.body?.repoPath !== 'string' || !req.body.repoPath.trim()) throw new HttpError('repoPath required');
    let repoPath;
    try { repoPath = fs.realpathSync(path.resolve(expandHome(req.body.repoPath))); } catch { throw new HttpError('That folder does not exist'); }
    if (!fs.statSync(repoPath).isDirectory()) throw new HttpError('Choose a repository directory, not a file');
    const existing = [...sessions.values()].find(session => session.repoPath === repoPath && !session.isTempRepo);
    return { sessionId: existing?.id || store.create(repoPath), repoPath };
  }));

  app.post('/api/session/clone', handle(async req => {
    let url;
    try { url = new URL(req.body?.url); } catch { throw new HttpError('Use an HTTPS repository URL without embedded credentials'); }
    if (url.protocol !== 'https:' || url.username || url.password) throw new HttpError('Use an HTTPS repository URL without embedded credentials');
    const branch = req.body.branch;
    if (branch && (typeof branch !== 'string' || branch.startsWith('-') || !/^[\w./-]{1,200}$/.test(branch))) throw new HttpError('Invalid branch name');
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-'));
    const repoPath = path.join(tempDir, 'repo');
    try {
      await execFileAsync('git', ['-c', 'core.hooksPath=', 'clone', '--depth=20', ...(branch ? ['--branch', branch] : []), '--', url.toString(), repoPath], {
        timeout: CLONE_TIMEOUT_MS, maxBuffer: 1024 * 1024, env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: '', SSH_ASKPASS: '' }, windowsHide: true });
    } catch {
      fs.rmSync(tempDir, { recursive: true, force: true });
      throw new HttpError('Clone failed. Verify the HTTPS URL, network access, and existing Git credentials.');
    }
    return { sessionId: store.create(repoPath, true, tempDir), repoPath };
  }));

  app.get('/api/session/:id', handle(req => {
    const session = sessionFor(req.params.id);
    return { id: session.id, repoPath: session.repoPath, reportCount: session.reports.length, provenance: session.provenance || null };
  }));
  app.get('/api/session/:id/reports', handle(req => sessionFor(req.params.id).reports.map(reports.metadata).reverse()));

  app.get('/api/report/:sessionId/:agentId/:ts/:fmt', (req, res) => {
    const { sessionId, agentId, ts, fmt } = req.params;
    const report = sessions.get(sessionId)?.reports.find(item => item.agentId === agentId && String(item.timestamp) === ts);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    if (fmt === 'json') {
      try { return res.json({ ...reports.read(report), ...reports.metadata(report) }); }
      catch { return res.status(404).json({ error: 'The report file is no longer available' }); }
    }
    const filePath = { md: report.mdPath, docx: report.docxPath }[fmt];
    if (!filePath || !fs.existsSync(filePath)) return res.status(404).json({ error: 'Report format unavailable' });
    const name = report.title ? report.title.normalize('NFKD').replace(/[^\w.-]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '').slice(0, 120) : '';
    return res.download(filePath, `${name || `threatlint-${agentId}-${ts}`}.${fmt}`);
  });
}

module.exports = { registerWorkspaceRoutes };
