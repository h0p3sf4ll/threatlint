'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createRuntimeScanner, privateAddress, validateConfig } = require('../lib/runtime.cjs');
const { createDemoApp } = require('../examples/demo-app.cjs');

const authorization = { confirmed: true, allowPrivate: true, reason: 'owned local fixture' };
const PATHS = ['/', '/api/health', '/api/profile', '/api/orders', '/api/admin/users', '/debug'];

async function finished(scanner, id) {
  for (let attempt = 0; attempt < 200; attempt++) {
    const scan = scanner.get(id);
    if (scan.status !== 'running') return scan;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error('scan did not finish');
}

describe('Runtime scanner scope and safety', () => {
  it('requires explicit authorization, a reason, and normalized paths', () => {
    assert.throws(() => validateConfig({ target: 'https://example.com', paths: ['/'] }), /authorization/);
    assert.throws(() => validateConfig({ target: 'https://example.com', paths: ['/'], authorization: { confirmed: true } }), /authorization context/);
    for (const path of ['//evil', '/a?b=1', '/../etc', '/a%2fb', 'relative']) {
      assert.throws(() => validateConfig({ target: 'https://example.com', paths: [path], authorization }), /paths/);
    }
  });
  it('rejects private and loopback targets without the explicit opt-in', () => {
    for (const target of ['http://127.0.0.1:8080', 'http://localhost', 'http://10.0.0.5', 'http://[::1]/', 'http://169.254.169.254']) {
      assert.throws(() => validateConfig({ target, paths: ['/'], authorization: { ...authorization, allowPrivate: false } }), /private/);
    }
    assert.equal(privateAddress('8.8.8.8'), false);
    assert.equal(privateAddress('::ffff:127.0.0.1'), true);
  });
  it('rejects private DNS answers for public-looking hostnames', async () => {
    const scanner = createRuntimeScanner({ lookup: (_host, _options, callback) => callback(null, [{ address: '10.1.2.3', family: 4 }]) });
    const { id } = scanner.start({ target: 'https://rebind.example', paths: ['/'], authorization: { ...authorization, allowPrivate: false }, limits: { delayMs: 0 } });
    const scan = await finished(scanner, id);
    assert.equal(scan.requests[0].statusCode, null);
    assert.match(scan.requests[0].error, /private address/);
  });
  it('validates every authentication workflow shape', () => {
    const base = { target: 'https://app.example', paths: ['/'], authorization };
    const valid = [
      { type: 'bearer', token: 't' }, { type: 'basic', username: 'u', password: 'p' }, { type: 'api-key', name: 'X-Key', value: 'v', location: 'header' },
      { type: 'headers', headers: { 'X-Test': '1' } }, { type: 'cookie', cookie: 'a=b' },
      { type: 'oauth-client-credentials', tokenUrl: 'https://id.example/token', clientId: 'c', clientSecret: 's' },
      { type: 'oauth-refresh-token', tokenUrl: 'https://id.example/token', clientId: 'c', refreshToken: 'r' },
      { type: 'oauth-password', tokenUrl: 'https://id.example/token', clientId: 'c', username: 'u', password: 'p' },
      { type: 'form-login', loginUrl: 'https://app.example/login', username: 'u', password: 'p' },
      { type: 'mtls', cert: '-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----', key: '-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----' },
      { type: 'browser-state', storageState: { cookies: [{ name: 's', value: 'v', domain: 'app.example' }] } },
      { type: 'browser-session', sessionId: '00000000-0000-4000-8000-000000000000' },
    ];
    for (const auth of valid) assert.doesNotThrow(() => validateConfig({ ...base, auth }), auth.type);
    assert.throws(() => validateConfig({ ...base, auth: { type: 'headers', headers: { Host: 'x' } } }));
    assert.throws(() => validateConfig({ ...base, auth: { type: 'bearer', token: 'a\r\nInjected: 1' } }));
    assert.throws(() => validateConfig({ ...base, auth: { type: 'oauth-client-credentials', tokenUrl: 'http://id.example/token', clientId: 'c', clientSecret: 's' }, authorization: { ...authorization, allowPrivate: false } }), /HTTPS/);
  });
});

describe('Runtime scanner against the weak fixture app', () => {
  let server, base;
  before(async () => { server = createDemoApp(); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); base = `http://127.0.0.1:${server.address().port}`; });
  after(() => new Promise(resolve => server.close(resolve)));

  it('builds an attack chain, multi-role comparison, and findings without leaking credentials', async () => {
    const scanner = createRuntimeScanner();
    const { id } = scanner.start({ target: base, paths: PATHS, authorization,
      auth: { type: 'oauth-client-credentials', tokenUrl: `${base}/oauth/token`, clientId: 'ci-client', clientSecret: 'ci-secret' },
      roles: [{ label: 'developer (form login)', auth: { type: 'form-login', loginUrl: `${base}/login`, username: 'dev', password: 'dev-pass' } }],
      checks: { compareAnonymous: true }, assertions: [{ path: '/api/orders', expectedAnonymousStatus: [401, 403] }, { path: '/api/profile', expectedAnonymousStatus: [401] }],
      limits: { maxRequests: 50, delayMs: 0 } });
    const scan = await finished(scanner, id);
    assert.equal(scan.status, 'complete');
    assert.equal(scan.requests.length, PATHS.length * 3);
    const rules = new Set(scan.findings.map(finding => finding.rule));
    for (const rule of ['RT-AUTHZ-ASSERT', 'RT-CORS-REFLECT', 'RT-COOKIE-FLAGS', 'RT-DEBUG-LEAK', 'RT-DISCLOSE-VERSION', 'RT-AUTHZ-ROLE-EQUAL', 'RT-HDR-CSP']) assert.ok(rules.has(rule), rule);
    assert.ok(!scan.findings.some(finding => finding.rule === 'RT-AUTHZ-ASSERT' && finding.path === '/api/profile'));
    const kinds = new Set(scan.nodes.map(node => node.kind));
    for (const kind of ['target', 'identity', 'request', 'response', 'control', 'finding', 'impact']) assert.ok(kinds.has(kind), kind);
    const ids = new Set(scan.nodes.map(node => node.id));
    assert.ok(scan.edges.every(edge => ids.has(edge.from) && ids.has(edge.to)));
    const serialized = JSON.stringify(scan) + scanner.exportScan(id, 'md').body + scanner.exportScan(id, 'html').body;
    for (const secret of ['ci-secret', 'admin-token', 'dev-pass', 'sid=']) assert.ok(!serialized.includes(secret), secret);
  });
  it('only sends GET to the target and honors the request budget', async () => {
    const methods = [];
    const scanner = createRuntimeScanner({ request: async ({ method }) => { methods.push(method); return { status: 200, headers: {}, body: '', durationMs: 1, bytes: 0 }; } });
    const { id } = scanner.start({ target: base, paths: PATHS, authorization, limits: { maxRequests: 3, delayMs: 0 } });
    const scan = await finished(scanner, id);
    assert.deepEqual(methods, ['GET', 'GET', 'GET']);
    assert.equal(scan.coverage.pathsNotTested.length, PATHS.length - 3);
  });
  it('cancels a running scan', async () => {
    const scanner = createRuntimeScanner();
    const { id } = scanner.start({ target: base, paths: PATHS, authorization, limits: { delayMs: 2000 } });
    scanner.cancel(id);
    assert.equal((await finished(scanner, id)).status, 'cancelled');
  });
});
