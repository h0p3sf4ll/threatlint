'use strict';

// Mount behind the server's same-origin loopback securityHeaders middleware.
const { handle } = require('../http.cjs');

function registerSecurityScannerRoutes(app, { securityScanner }) {
  app.post('/api/security-scanner/scans', handle(req => securityScanner.start(req.body), { status: 202 }));
  app.get('/api/security-scanner/scans', handle(req => securityScanner.list(typeof req.query.sessionId === 'string' ? req.query.sessionId : undefined)));
  app.get('/api/security-scanner/scans/:id', handle(req => securityScanner.get(req.params.id)));
  app.post('/api/security-scanner/scans/:id/cancel', handle(req => securityScanner.cancel(req.params.id)));
  app.post('/api/security-scanner/scans/:id/fixes', handle(req => securityScanner.propose(req.params.id, req.body), { status: 201 }));
  app.post('/api/security-scanner/fixes/:id/apply', handle(req => securityScanner.apply(req.params.id, req.body)));
}

module.exports = { registerSecurityScannerRoutes };
