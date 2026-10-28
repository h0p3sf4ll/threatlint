'use strict';

/** Source code managers: session-only tokens, read-only discovery, and checkout into a workspace. */

const { SOURCE_MANAGER_CAPABILITIES } = require('../scm.cjs');
const { handle } = require('../http.cjs');

// A failed saved-PAT connection is retried at most this often, so a bad PAT does not hit Azure DevOps on every refresh.
const SAVED_RETRY_MS = 60_000;

function registerSourceRoutes(app, { store, scm, integrations = {} }) {
  const cli = (...args) => (integrations.threatlintCli || require('../avit-batch.cjs').runCli)(...args);
  const failedAt = new Map();
  let connecting = null;
  // Azure DevOps organizations with a PAT saved in Settings (or `threatlint ado login`) connect without retyping it.
  // The PAT is read from the CLI over a pipe, held only by the source manager, and never returned.
  async function connectSaved() {
    const status = await cli(['ado', 'status']);
    const saved = [...status.stdout.matchAll(/^Azure DevOps PAT: .+ · ([A-Za-z0-9-]+)$/gm)].map(match => match[1]);
    const live = new Set(scm.list().filter(item => item.provider === 'azure-devops').map(item => item.account));
    for (const organization of saved) {
      if (live.has(organization.toLowerCase()) || Date.now() - (failedAt.get(organization) || 0) < SAVED_RETRY_MS) continue;
      const token = await cli(['ado', 'token', '--organization', organization]);
      try {
        if (token.code !== 0) throw new Error('no saved PAT');
        await scm.connect({ provider: 'azure-devops', token: token.stdout.trim(), organization });
        failedAt.delete(organization);
      } catch { failedAt.set(organization, Date.now()); }
    }
  }
  app.get('/api/scm/providers', (_req, res) => res.json(SOURCE_MANAGER_CAPABILITIES));
  app.get('/api/scm/connections', handle(async () => {
    connecting ||= connectSaved().catch(() => {}).finally(() => { connecting = null; });
    await connecting;
    return scm.list();
  }, { fallback: 'Connections unavailable' }));
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
