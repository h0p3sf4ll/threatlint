'use strict';

/** Authorized runtime scanning. Credentials stay in runner memory for one scan. */

const { handle } = require('../http.cjs');

const HISTORY_LIMIT = 25;
const EXPORT_FORMATS = ['json', 'md', 'html'];

function createRuntimeHistory(runtime) {
  const ids = [];
  const snapshot = id => { try { return runtime.get(id); } catch { return null; } };
  return {
    add(id) { ids.push(id); if (ids.length > HISTORY_LIMIT) ids.shift(); },
    summaries: () => ids.map(snapshot).filter(Boolean).reverse().map(scan => ({ id: scan.id, status: scan.status, target: scan.target, startedAt: scan.startedAt, findings: scan.findings.length })),
    finished: () => ids.map(snapshot).filter(scan => scan && scan.status !== 'running'),
  };
}

function registerRuntimeRoutes(app, { runtime, history }) {
  app.post('/api/runtime/scans', handle(req => { const { id } = runtime.start(req.body); history.add(id); return { id }; }, { status: 202, fallback: 'Scan rejected' }));
  app.get('/api/runtime/scans', (_req, res) => res.json(history.summaries()));
  app.get('/api/runtime/scans/:id', handle(req => runtime.get(req.params.id)));
  app.post('/api/runtime/scans/:id/cancel', handle(req => { runtime.cancel(req.params.id); return { ok: true }; }));
  app.get('/api/runtime/scans/:id/export', (req, res) => {
    const format = EXPORT_FORMATS.includes(req.query.format) ? req.query.format : 'json';
    handle(() => {
      const { contentType, body } = runtime.exportScan(req.params.id, format);
      res.setHeader('Content-Type', contentType);
      res.setHeader('Content-Disposition', `attachment; filename="threatlint-runtime-${req.params.id.slice(0, 8)}.${format}"`);
      res.send(body);
    })(req, res);
  });
  app.post('/api/runtime/auth/browser/start', handle(req => runtime.startBrowser(req.body), { status: 201, fallback: 'Browser sign-in unavailable' }));
  app.post('/api/runtime/auth/browser/:id/finish', handle(req => runtime.finishBrowser(req.params.id), { fallback: 'Browser sign-in incomplete' }));
}

module.exports = { registerRuntimeRoutes, createRuntimeHistory };
