'use strict';

/**
 * DefectDojo and SonarQube from the Workbench:
 *   GET/POST /api/scanners/:tool/settings   saved URL + token (shared with `threatlint dojo|sonar login`); GET never returns the token
 *   POST     /api/scanners/:tool/resolve    post one reviewed finding's verdict, only with {confirm: true}
 * :tool is "dojo" (DefectDojo) or "sonar" (SonarQube).
 */

const { handle, HttpError } = require('../http.cjs');
const scanners = require('../scanners.cjs');

function registerScannerRoutes(app, { scannerBatch, integrations = {} }) {
  const fetchImpl = integrations.fetchImpl || fetch;

  app.get('/api/scanners', handle(() => Object.keys(scanners.TOOLS).map(id => scanners.publicConfig(id))));
  app.get('/api/scanners/:tool/settings', handle(req => scanners.publicConfig(scanners.tool(req.params.tool).id)));
  app.post('/api/scanners/:tool/settings', handle(async req => {
    const id = scanners.tool(req.params.tool).id;
    const body = req.body || {};
    const saved = scanners.readConfig(id);
    const typed = typeof body.token === 'string' ? body.token.trim() : '';
    if (!String(body.url || '').trim() && !typed) { scanners.clearConfig(id); return scanners.publicConfig(id); }
    const url = scanners.validateBaseUrl(body.url, id);
    // An omitted token keeps the saved one, so the masked field can be left untouched.
    const token = typed || saved.token;
    if (!token) throw new HttpError(`Enter the ${scanners.tool(id).label} API token`);
    if (typed || url !== saved.url) await scanners.validateToken(id, url, token, { fetchImpl });
    scanners.writeConfig(id, { url, token });
    return scanners.publicConfig(id);
  }));
  app.post('/api/scanners/:tool/resolve', handle(req => scannerBatch.resolve(scanners.tool(req.params.tool).id, req.body || {})));
}

module.exports = { registerScannerRoutes };
