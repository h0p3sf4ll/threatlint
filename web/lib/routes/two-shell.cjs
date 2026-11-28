'use strict';

// Mount behind the server's same-origin loopback securityHeaders middleware. In the company gateway,
// POST routes require the `review` permission and GET routes `read` (lib/rbac.cjs defaults).
const { handle } = require('../http.cjs');

// /api/detect-xshell is current; /api/detect-2shell stays as an alias for clients built before the rename.
const BASES = ['/api/detect-xshell/scans', '/api/detect-2shell/scans'];
const paths = suffix => BASES.map(base => base + suffix);

function registerTwoShellRoutes(app, { twoShellFleet }) {
  app.post(paths(''), handle(req => twoShellFleet.start(req.body), { status: 202, fallback: 'detect-xshell scan could not start' }));
  app.get(paths(''), handle(() => twoShellFleet.list()));
  app.get(paths('/:id'), handle(req => twoShellFleet.get(req.params.id, { results: req.query.results !== 'false' })));
  app.post(paths('/:id/cancel'), handle(req => twoShellFleet.cancel(req.params.id)));
  app.get(paths('/:id/report'), handle((req, res) => {
    const format = typeof req.query.format === 'string' ? req.query.format : 'json';
    const report = twoShellFleet.report(req.params.id, format);
    res.setHeader('Content-Type', report.contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${report.filename}"`);
    res.status(200).send(report.body);
  }));
}

module.exports = { registerTwoShellRoutes, BASES };
