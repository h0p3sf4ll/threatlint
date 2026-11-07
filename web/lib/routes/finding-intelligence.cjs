'use strict';

const path = require('node:path');
const { handle, HttpError } = require('../http.cjs');
const { ingestionFromReport, text } = require('../finding-intelligence.cjs');
const { serviceNowPreview, developerRiskPreview } = require('../finding-intelligence-previews.cjs');

function registerFindingIntelligenceRoutes(app, { intelligence, store }) {
  function session(req) {
    const id = req.body?.sessionId || req.query?.sessionId;
    if (typeof id !== 'string' || !store.sessions.has(id)) throw new HttpError('Select an existing workspace session', 404);
    return store.sessions.get(id);
  }
  function scope(req) {
    return { repoId: session(req).repoPath, branch: text(req.query?.branch, 'branch filter', 500),
      commit: text(req.query?.commit, 'commit filter', 200), contentDigest: text(req.query?.contentDigest, 'content digest filter', 200) };
  }
  function finding(req) {
    const selected = intelligence.getFinding(req.params.id);
    if (!selected || selected.provenance.repo.id !== session(req).repoPath) throw new HttpError('Finding not found in this workspace', 404);
    return selected;
  }
  function composite(req) {
    const selected = intelligence.getComposite(req.params.id);
    if (!selected || selected.provenance.repo.id !== session(req).repoPath) throw new HttpError('Composite not found in this workspace', 404);
    return selected;
  }
  app.get('/api/intelligence/overview', handle(req => intelligence.overview(scope(req))));
  app.get('/api/intelligence/findings/:id', handle(req => finding(req)));
  app.post('/api/intelligence/sync', handle(req => {
    const selected = session(req);
    const results = [], errors = [];
    for (const report of selected.reports || []) {
      try { results.push(intelligence.ingest(ingestionFromReport(report, selected))); }
      catch (error) { errors.push({ reportId: report.id, error: error.message }); }
    }
    return { imported: results.filter(item => !item.duplicate).length, duplicates: results.filter(item => item.duplicate).length, errors,
      overview: intelligence.overview({ repoId: selected.repoPath }) };
  }));
  app.post('/api/intelligence/ingestions', handle(req => {
    const selected = session(req);
    return intelligence.ingest({ ...req.body, repo: { id: selected.repoPath, name: path.basename(selected.repoPath) }, sessionId: selected.id, origin: 'imported' });
  }, { status: 201 }));
  app.post('/api/intelligence/findings/:id/reviews', handle(req => intelligence.review(finding(req).id, req.body)));
  app.post('/api/intelligence/composites', handle(req => {
    const selected = session(req);
    for (const node of req.body?.contributors || []) {
      if (intelligence.getFinding(node.findingId)?.provenance.repo.id !== selected.repoPath) throw new HttpError('Contributing finding not found in this workspace', 404);
    }
    return intelligence.correlate(req.body);
  }, { status: 201 }));
  app.get('/api/intelligence/composites/:id', handle(req => composite(req)));
  app.post('/api/intelligence/composites/:id/servicenow-preview', handle(req => serviceNowPreview(composite(req), intelligence.snapshot().findings)));
  app.post('/api/intelligence/developer-risk-preview', handle(req => {
    const selected = session(req);
    return developerRiskPreview(intelligence.snapshot().findings.filter(item => item.provenance.repo.id === selected.repoPath), req.body);
  }));
}
module.exports = { registerFindingIntelligenceRoutes };
