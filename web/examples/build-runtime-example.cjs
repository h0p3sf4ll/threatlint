'use strict';
/** Regenerates examples/runtime-scan.json by scanning the loopback demo app. Run: node examples/build-runtime-example.cjs */
const fs = require('node:fs');
const path = require('node:path');
const { createRuntimeScanner } = require('../lib/runtime.cjs');
const { createDemoApp } = require('./demo-app.cjs');

(async () => {
  const server = createDemoApp();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const scanner = createRuntimeScanner();
  const { id } = scanner.start({ target: base, paths: ['/', '/api/health', '/api/profile', '/api/orders', '/api/admin/users', '/debug'],
    authorization: { confirmed: true, allowPrivate: true, reason: 'synthetic loopback fixture' },
    auth: { type: 'oauth-client-credentials', tokenUrl: `${base}/oauth/token`, clientId: 'ci-client', clientSecret: 'ci-secret' },
    roles: [{ label: 'developer (form login)', auth: { type: 'form-login', loginUrl: `${base}/login`, username: 'dev', password: 'dev-pass' } }],
    checks: { compareAnonymous: true }, assertions: [{ path: '/api/orders', expectedAnonymousStatus: [401, 403] }, { path: '/api/profile', expectedAnonymousStatus: [401] }],
    limits: { maxRequests: 50, delayMs: 0 } });
  let scan;
  do { await new Promise(resolve => setTimeout(resolve, 25)); scan = scanner.get(id); } while (scan.status === 'running');
  server.close();
  // Fixed identifiers keep the example stable and obviously synthetic.
  const text = JSON.stringify({ ...scan, id: 'synthetic-example' }, null, 2).replaceAll(base, 'https://staging.demo-shop.test');
  fs.writeFileSync(path.join(__dirname, 'runtime-scan.json'), `${text}\n`);
  console.log(`runtime-scan.json: ${scan.findings.length} findings, ${scan.nodes.length} nodes`);
})();
