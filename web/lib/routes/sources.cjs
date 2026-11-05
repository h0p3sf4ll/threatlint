'use strict';

/** Source code managers: session-only tokens, read-only discovery, and checkout into a workspace. */

const { SOURCE_MANAGER_CAPABILITIES } = require('../scm.cjs');
const { handle } = require('../http.cjs');
const githubAppModule = require('../github-app.cjs');

// A failed saved-PAT connection is retried at most this often, so a bad PAT does not hit Azure DevOps on every refresh.
const SAVED_RETRY_MS = 60_000;

function registerSourceRoutes(app, { store, scm, integrations = {} }) {
  const cli = (...args) => (integrations.threatlintCli || require('../avit-batch.cjs').runCli)(...args);
  const failedAt = new Map();
  let connecting = null;
  // GitHub App (Settings → GitHub, or `threatlint github login`): installation tokens are minted here, held only by
  // the source manager, replaced before they expire, and never returned to the browser.
  const githubApp = integrations.githubApp || githubAppModule.createGitHubApp(integrations.fetchImpl ? { fetch: integrations.fetchImpl } : {});
  let appConnection = null, appFailedAt = 0;
  function dropAppConnection() {
    if (appConnection) scm.disconnect(appConnection.id);
    appConnection = null;
    appFailedAt = 0;
  }
  async function connectApp() {
    const config = githubAppModule.readConfig();
    if (!config) { dropAppConnection(); return; }
    // The source manager is github.com-only; a GitHub Enterprise App still serves the CLI.
    try { if (githubAppModule.validateApiUrl(config.apiUrl) !== githubAppModule.DEFAULT_API_URL) return; } catch { return; }
    const live = appConnection && scm.list().some(item => item.id === appConnection.id);
    if (live && appConnection.expiresAt - 5 * 60_000 > Date.now()) return;
    if (Date.now() - appFailedAt < SAVED_RETRY_MS) return;
    try {
      const { token, expiresAt } = await githubApp.installationToken(config);
      const connected = await scm.connect({ provider: 'github', token });
      if (appConnection) scm.disconnect(appConnection.id);
      appConnection = { id: connected.id, expiresAt };
      appFailedAt = 0; appFailure = '';
    } catch (error) { appFailedAt = Date.now(); appFailure = failureReason(error, 'installation token could not be minted'); }
  }
  // Azure DevOps organizations with a PAT saved in Settings, surfaced by the last connectSaved() pass, and why
  // each saved source last failed. Reasons are fixed phrases chosen here, never provider or token text.
  let savedAzureOrgs = [];
  const failureReasons = new Map();
  let appFailure = '';
  function failureReason(error, fallback) {
    return { SCM_AUTHORIZATION_FAILED: 'credential rejected or expired', SCM_TIMEOUT: 'provider timed out',
      SCM_LIMIT: 'connection limit reached' }[error?.code] || fallback;
  }
  function connectionsView() {
    const list = scm.list();
    const live = list.map(item => (appConnection && item.id === appConnection.id
      ? { ...item, label: `GitHub App · ${item.account}`, source: 'GitHub App', connected: true } : { ...item, connected: true }));
    // A saved source that is configured but could not be connected (expired/invalid PAT, mint failure) stays
    // visible as connected:false, so nothing a user set up silently disappears from the list.
    const liveAzure = new Set(live.filter(item => item.provider === 'azure-devops').map(item => item.account));
    const degraded = [];
    for (const organization of savedAzureOrgs) {
      const account = organization.toLowerCase();
      if (liveAzure.has(account)) continue;
      degraded.push({ id: `saved:azure-devops:${account}`, provider: 'azure-devops', account,
        label: `Azure DevOps · ${account}`, host: 'dev.azure.com', source: 'Saved PAT', connected: false,
        reason: failureReasons.get(account) || 'not connected yet' });
    }
    const appLive = appConnection && list.some(item => item.id === appConnection.id);
    if (!appLive) {
      const config = githubAppModule.readConfig();
      let cloudApp = false;
      if (config) { try { cloudApp = githubAppModule.validateApiUrl(config.apiUrl) === githubAppModule.DEFAULT_API_URL; } catch { cloudApp = false; } }
      if (cloudApp) degraded.push({ id: 'saved:github-app', provider: 'github', account: 'GitHub App',
        label: 'GitHub App', host: 'github.com', source: 'GitHub App', connected: false, reason: appFailure || 'not connected yet' });
    }
    return [...live, ...degraded];
  }
  // Azure DevOps organizations with a PAT saved in Settings (or `threatlint ado login`) connect without retyping it.
  // The PAT is read from the CLI over a pipe, held only by the source manager, and never returned.
  async function connectSaved() {
    await connectApp();
    const status = await cli(['ado', 'status']);
    const saved = [...status.stdout.matchAll(/^Azure DevOps PAT: .+ · ([A-Za-z0-9-]+)$/gm)].map(match => match[1]);
    savedAzureOrgs = saved;
    const live = new Set(scm.list().filter(item => item.provider === 'azure-devops').map(item => item.account));
    for (const organization of saved) {
      if (live.has(organization.toLowerCase()) || Date.now() - (failedAt.get(organization) || 0) < SAVED_RETRY_MS) continue;
      const token = await cli(['ado', 'token', '--organization', organization]);
      const account = organization.toLowerCase();
      try {
        if (token.code !== 0) throw Object.assign(new Error('no saved PAT'), { code: 'SAVED_PAT_UNREADABLE' });
        await scm.connect({ provider: 'azure-devops', token: token.stdout.trim(), organization });
        failedAt.delete(organization);
        failureReasons.delete(account);
      } catch (error) {
        failedAt.set(organization, Date.now());
        failureReasons.set(account, error.code === 'SAVED_PAT_UNREADABLE' ? 'saved PAT could not be read' : failureReason(error, 'provider unreachable'));
      }
    }
  }
  app.get('/api/scm/providers', (_req, res) => res.json(SOURCE_MANAGER_CAPABILITIES));
  app.get('/api/scm/connections', handle(async () => {
    connecting ||= connectSaved().catch(() => {}).finally(() => { connecting = null; });
    await connecting;
    return connectionsView();
  }, { fallback: 'Connections unavailable' }));
  // Settings → GitHub. GET and POST return only which values are set, never the key or a token.
  app.get('/api/github/settings', handle(() => githubApp.publicStatus()));
  app.post('/api/github/settings', handle(async req => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const result = await githubApp.save({ appId: body.appId, installationId: body.installationId, privateKeyFile: body.privateKeyFile, apiUrl: body.apiUrl });
    dropAppConnection();
    return result;
  }));
  app.delete('/api/github/settings', handle(() => {
    githubApp.clear();
    dropAppConnection();
    return githubApp.publicStatus();
  }));
  app.post('/api/scm/connections', handle(req => scm.connect(req.body), { status: 201, fallback: 'Connection failed' }));
  app.delete('/api/scm/connections/:id', (req, res) => res.status(scm.disconnect(req.params.id) ? 204 : 404).end());
  app.get('/api/scm/connections/:id/repositories', handle(req => {
    const input = {};
    if (typeof req.query.search === 'string' && req.query.search) input.search = req.query.search;
    if (req.query.page !== undefined) input.page = Number(req.query.page);
    return scm.repositories(req.params.id, input);
  }, { fallback: 'Repositories unavailable' }));
  app.get('/api/scm/connections/:id/branches', handle(req => scm.branches(req.params.id, String(req.query.repositoryId || ''),
    req.query.page !== undefined ? { page: Number(req.query.page) } : {}), { fallback: 'Branches unavailable' }));
  app.post('/api/scm/checkout', handle(async req => {
    const { connectionId, repositoryId, branch } = req.body || {};
    const result = await scm.checkout(connectionId, { repositoryId, ...(branch ? { branch } : {}) });
    const sessionId = store.create(result.repoPath, true, result.tempDir);
    store.sessions.get(sessionId).provenance = result.provenance;
    store.save();
    return { sessionId, repoPath: result.repoPath, provenance: result.provenance };
  }, { status: 201, fallback: 'Checkout failed' }));
}

module.exports = { registerSourceRoutes };
