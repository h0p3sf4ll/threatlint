'use strict';

/** Catalog, workspaces (local folders and HTTPS clones), reports, and the local model list. */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { AGENTS, SKILLS, publicAgent } = require('../agents.cjs');
const { parseReport } = require('../reports.cjs');
const { onePageFinding, primaryFinding } = require('../report-one-page.cjs');
const { listConfiguredModels } = require('../model-discovery.cjs');
const { handle, HttpError } = require('../http.cjs');
const servicenow = require('../servicenow.cjs');
const catalog = require('../model-catalog.cjs');
const threatlintConfig = require('../threatlint-config.cjs');
const { modelPolicy } = require('../model-policy.cjs');
const { publicAdoStatus } = require('../ado-settings.cjs');
const { createWorkspaces } = require('../workspaces.cjs');

const EXAMPLES = path.join(__dirname, '../../examples');
const expandHome = value => value.replace(/^~(?=\/|$)/, os.homedir());

function registerWorkspaceRoutes(app, { store, reports, build, integrations = {} }) {
  const credentialSources = integrations.credentialSources || catalog.credentialSources;
  const { sessions } = store;
  const workspaces = createWorkspaces({ store, integrations });
  const sessionFor = id => sessions.get(id) || (() => { throw new HttpError('Session not found', 404); })();

  app.get('/api/config', handle(async () => ({ desktop: !!process.versions.electron, persistent: !!store.directory, build,
    providers: await credentialSources(), modelPolicy: modelPolicy(),
    semgrep: await (integrations.semgrepVersion || servicenow.semgrepVersion)(), semgrepAgents: [...servicenow.SEMGREP_AGENTS],
    servicenow: { ...servicenow.access(), instance: process.env.THREATLINT_SNOW_INSTANCE || '' } })));
  app.get('/api/semgrep/engine', handle(() => (integrations.semgrepEngineStatus || require('../semgrep-engine.cjs').status)()));
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
  // Azure DevOps credential-source metadata, shared with the CLI. PATs are never returned.
  const cli = (...args) => (integrations.threatlintCli || require('../avit-batch.cjs').runCli)(...args);
  const adoStatus = async () => {
    const result = await cli(['ado', 'status', '--json']);
    if (result.code !== 0) throw new HttpError('Azure DevOps credential settings could not be read.', 503);
    return publicAdoStatus(result.stdout);
  };
  app.delete('/api/ado/settings/:organization', handle(async req => {
    const organization = String(req.params.organization || '');
    if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,49}$/.test(organization)) throw new HttpError('Invalid Azure DevOps organization');
    await cli(['ado', 'logout', '--organization', organization]);
    return adoStatus();
  }));
  app.get('/api/ado/settings', handle(adoStatus));
  app.post('/api/ado/service-account', handle(async req => {
    const body = req.body || {};
    const parameter = typeof body.parameter === 'string' ? body.parameter.trim() : '';
    const organizations = Array.isArray(body.organizations) ? [...new Set(body.organizations)] : [];
    const profile = typeof body.profile === 'string' ? body.profile.trim() : '';
    const region = typeof body.region === 'string' ? body.region.trim() : '';
    if (!parameter || parameter.length > 2048 || !/^(?:[A-Za-z0-9_./][A-Za-z0-9_./-]*|arn:aws(?:-[a-z]+)*:ssm:[a-z0-9-]+:\d{12}:parameter\/[A-Za-z0-9_./-]+)$/.test(parameter)) throw new HttpError('Enter the AWS Parameter Store name or ARN for the service-account PAT.');
    if (!organizations.length || organizations.length > 100 || organizations.some(name => typeof name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9-]{0,49}$/.test(name))) throw new HttpError('Enter one or more Azure DevOps organization names, not URLs.');
    if (profile && !/^[\w.@+][\w.@+-]{0,127}$/.test(profile)) throw new HttpError('Enter a valid AWS profile name.');
    if (region && !/^[a-z][a-z0-9]*(?:-[a-z0-9]+)+-\d+$/.test(region)) throw new HttpError('Enter a valid AWS region.');
    const args = ['ado', 'service-account', '--parameter', parameter, ...organizations.flatMap(name => ['--organization', name]),
      ...(profile ? ['--aws-profile', profile] : []), ...(region ? ['--region', region] : [])];
    const result = await cli(args);
    if (result.code !== 0) throw new HttpError((result.stderr.trim().split(/\r?\n/).pop() || 'Service-account configuration failed.').replace(/^ERROR:\s*/, ''), 400);
    return adoStatus();
  }));
  app.post('/api/ado/settings', handle(async req => {
    if ((await adoStatus()).serviceAccount.parameter) throw new HttpError('AWS Parameter Store is the configured Azure DevOps credential source. Update the service-account settings instead of saving a personal PAT.');
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
  app.post('/api/models', handle(req => listConfiguredModels(req.body, integrations)));
  app.get('/api/lmstudio/models', handle(req => listConfiguredModels({ provider: 'lmstudio',
    baseUrl: typeof req.query.baseUrl === 'string' ? req.query.baseUrl : undefined }, integrations)));

  app.get('/api/fs/browse', handle(req => {
    let requested;
    try { requested = fs.realpathSync(expandHome(typeof req.query.path === 'string' ? req.query.path : os.homedir())); } catch (error) { throw new HttpError(`Cannot browse directory: ${error.message}`); }
    if (!fs.statSync(requested).isDirectory()) throw new HttpError('Not a directory');
    const entries = fs.readdirSync(requested, { withFileTypes: true }).filter(entry => entry.isDirectory())
      .map(entry => ({ name: entry.name, isRepo: fs.existsSync(path.join(requested, entry.name, '.git')) }))
      .sort((a, b) => Number(b.isRepo) - Number(a.isRepo) || a.name.localeCompare(b.name));
    return { path: requested, parent: path.dirname(requested) === requested ? null : path.dirname(requested), entries };
  }));

  app.get('/api/sessions', (_req, res) => res.json(workspaces.list()));

  // The repository path is chosen by the local user on purpose: this loopback runner reviews their own folders.
  app.post('/api/session/local', handle(req => workspaces.open(req.body)));
  app.post('/api/session/clone', handle(req => workspaces.clone(req.body)));
  app.get('/api/session/:id', handle(req => workspaces.get(req.params.id)));
  app.get('/api/session/:id/reports', handle(req => sessionFor(req.params.id).reports.map(reports.metadata).reverse()));

  app.delete('/api/session/:id/reports/:reportId', handle(req => {
    const session = sessionFor(req.params.id);
    const report = session.reports.find(item => item.id === req.params.reportId);
    if (!report || report.sessionId !== session.id) throw new HttpError('Report not found', 404);
    try { reports.remove(report); }
    catch { throw new HttpError('The saved report could not be deleted. Check that the local report storage is writable.', 500); }
    return { id: report.id };
  }));

  app.get('/api/report/:sessionId/:agentId/:ts/pptx', handle(async (req, res) => {
    const { sessionId, agentId, ts } = req.params;
    const report = sessions.get(sessionId)?.reports.find(item => item.agentId === agentId && String(item.timestamp) === ts);
    if (!report) throw new HttpError('Report not found', 404);
    const findingId = req.query.finding;
    if (findingId !== undefined && (typeof findingId !== 'string' || !/^[A-Z][A-Z0-9]*-\d+$/.test(findingId) || findingId.length > 40)) {
      throw new HttpError('Choose a finding from this report');
    }
    let parsed;
    try { parsed = reports.read(report); } catch { throw new HttpError('The report file is no longer available', 404); }
    const finding = findingId ? parsed.findings.find(item => item.id === findingId) : primaryFinding(parsed.findings);
    if (!finding) throw new HttpError(findingId ? 'Finding not found in this report' : 'This report has no findings to export', 404);
    const { createFindingPptx } = require('../report-pptx.cjs');
    const deck = await createFindingPptx(onePageFinding(finding));
    res.attachment(`${finding.id}-threatlint-one-page.pptx`).send(deck);
  }));

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
