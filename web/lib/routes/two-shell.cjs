'use strict';

// Mount behind the server's same-origin loopback securityHeaders middleware. In the company gateway,
// POST routes require the `review` permission and GET routes `read` (lib/rbac.cjs defaults).
const { handle } = require('../http.cjs');

function registerTwoShellRoutes(app, { twoShellFleet }) {
  app.post('/api/detect-2shell/scans', handle(req => twoShellFleet.start(req.body), { status: 202, fallback: 'detect-2shell scan could not start' }));
  app.get('/api/detect-2shell/scans', handle(() => twoShellFleet.list()));
  app.get('/api/detect-2shell/scans/:id', handle(req => twoShellFleet.get(req.params.id, { results: req.query.results !== 'false' })));
  app.post('/api/detect-2shell/scans/:id/cancel', handle(req => twoShellFleet.cancel(req.params.id)));
  app.get('/api/detect-2shell/scans/:id/report', handle((req, res) => {
    const format = typeof req.query.format === 'string' ? req.query.format : 'json';
    const report = twoShellFleet.report(req.params.id, format);
    res.setHeader('Content-Type', report.contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${report.filename}"`);
    res.status(200).send(report.body);
  }));
}

module.exports = { registerTwoShellRoutes };
