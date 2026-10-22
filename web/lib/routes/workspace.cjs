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
    servicenow: { ...servicenow.ACCESS, instance: process.env.THREATLINT_SNOW_INSTANCE || '' } })));
  // Uses the local user's own AWS CLI session (from SSO); values return only to this loopback UI and are not stored.
  app.post('/api/servicenow/parameter-store', handle(req => (integrations.readParameterStore || servicenow.readParameterStore)({ profile: req.body?.profile || undefined })));
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
    return res.download(filePath, `threatlint-${agentId}-${ts}.${fmt}`);
  });
}

module.exports = { registerWorkspaceRoutes };
