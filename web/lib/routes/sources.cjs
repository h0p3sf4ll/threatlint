'use strict';

/** Source code managers: session-only tokens, read-only discovery, and checkout into a workspace. */

const { SOURCE_MANAGER_CAPABILITIES } = require('../scm.cjs');
const { handle } = require('../http.cjs');

function registerSourceRoutes(app, { store, scm }) {
  app.get('/api/scm/providers', (_req, res) => res.json(SOURCE_MANAGER_CAPABILITIES));
  app.get('/api/scm/connections', (_req, res) => res.json(scm.list()));
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
