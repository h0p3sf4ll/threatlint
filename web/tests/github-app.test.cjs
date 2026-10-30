'use strict';
/** GitHub App source: RS256 JWT, installation-token cache, settings routes, and Sources → GitHub. No real IDs, keys, or HTTP. */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.THREATLINT_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-home-'));
for (const name of ['THREATLINT_GITHUB_APP_ID', 'THREATLINT_GITHUB_APP_INSTALLATION_ID', 'THREATLINT_GITHUB_APP_PRIVATE_KEY_FILE', 'THREATLINT_GITHUB_API_URL']) delete process.env[name];
const { createGitHubApp, appJwt, configPath } = require('../lib/github-app.cjs');
const { createWorkbench } = require('../server.js');

const APP_ID = '1000001', INSTALLATION_ID = '2000002';
const TOKEN = `ghs_${'T'.repeat(36)}`;
const keyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-app-key-'));
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const KEY_FILE = path.join(keyDir, 'throwaway-app.pem');
const PEM = privateKey.export({ type: 'pkcs1', format: 'pem' });
fs.writeFileSync(KEY_FILE, PEM, { mode: 0o600 });
const CONFIG = { appId: APP_ID, installationId: INSTALLATION_ID, privateKeyFile: KEY_FILE, apiUrl: 'https://api.github.com' };
const decode = part => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));

function fakeGitHub({ expiresAt = '2099-01-01T00:00:00Z', tokens = [TOKEN] } = {}) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith('/access_tokens')) return { ok: true, status: 201, json: async () => ({ token: tokens.length > 1 ? tokens.shift() : tokens[0], expires_at: expiresAt }) };
    if (url.includes('/installation/repositories')) return { ok: true, status: 200, json: async () => ({ total_count: 3, repositories: [{ owner: { login: 'example-org' } }] }) };
    return { ok: false, status: 404, json: async () => ({}) };
  };
  return { fetch, calls };
}

describe('GitHub App JWT and tokens', () => {
  it('signs an RS256 JWT with iat backdated 60 s, exp within 10 minutes, and iss = App ID', () => {
    const now = 1_700_000_000_000;
    const [header, payload, signature] = appJwt(CONFIG, now).split('.');
    assert.deepEqual(decode(header), { alg: 'RS256', typ: 'JWT' });
    const claims = decode(payload);
    assert.equal(claims.iss, APP_ID);
    assert.equal(claims.iat, now / 1000 - 60);
    assert.ok(claims.exp > now / 1000 && claims.exp <= now / 1000 + 600);
    assert.ok(crypto.verify('RSA-SHA256', Buffer.from(`${header}.${payload}`), publicKey, Buffer.from(signature, 'base64url')));
  });

  it('exchanges the JWT for an installation token, caches it, and refreshes five minutes before expiry', async () => {
    const expires = Date.parse('2030-01-01T01:00:00Z');
    const github = fakeGitHub({ expiresAt: '2030-01-01T01:00:00Z', tokens: [`ghs_first${'a'.repeat(30)}`, `ghs_second${'b'.repeat(30)}`] });
    let clock = expires - 3_600_000;
    const app = createGitHubApp({ fetch: github.fetch, now: () => clock });
    const first = (await app.installationToken(CONFIG)).token;
    clock = expires - 301_000;
    assert.equal((await app.installationToken(CONFIG)).token, first);
    assert.equal(github.calls.length, 1);
    assert.equal(github.calls[0].url, `https://api.github.com/app/installations/${INSTALLATION_ID}/access_tokens`);
    assert.equal(github.calls[0].init.method, 'POST');
    assert.equal(github.calls[0].init.redirect, 'error', 'redirects are refused');
    assert.match(github.calls[0].init.headers.Authorization, /^Bearer ey/);
    clock = expires - 299_000;
    assert.notEqual((await app.installationToken(CONFIG)).token, first);
    assert.equal(github.calls.length, 2);
  });

  it('refuses a non-HTTPS API URL and reports rejected credentials without values', async () => {
    const app = createGitHubApp({ fetch: async () => ({ ok: false, status: 401, json: async () => ({}) }) });
    await assert.rejects(app.installationToken({ ...CONFIG, apiUrl: 'http://api.github.com' }), /https/);
    await assert.rejects(app.installationToken(CONFIG), error => /HTTP 401/.test(error.message) && !error.message.includes(APP_ID) && !error.message.includes(KEY_FILE));
  });
});

describe('Workbench GitHub App settings and Sources', () => {
  let wb, base;
  const github = fakeGitHub();
  const connected = [];
  before(async () => {
    const threatlintCli = async args => {
      if (args.join(' ') === 'ado status') return { code: 0, stdout: 'No Azure DevOps PAT configured.\n', stderr: '' };
      throw new Error(`unexpected ${args.join(' ')}`);
    };
    const scm = {
      list: () => connected.filter(item => !item.closed).map(({ id }) => ({ id, provider: 'github', account: 'example-org', label: 'GitHub · example-org', host: 'github.com' })),
      connect: async input => { const item = { ...input, id: `00000000-0000-4000-8000-00000000000${connected.length}` }; connected.push(item); return { id: item.id }; },
      disconnect: id => { const item = connected.find(entry => entry.id === id); if (item) item.closed = true; return !!item; },
    };
    wb = createWorkbench({ storageDir: fs.mkdtempSync(path.join(os.tmpdir(), 'tl-')), integrations: { threatlintCli, fetchImpl: github.fetch }, sourceManagers: scm });
    await new Promise(resolve => wb.server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${wb.server.address().port}`;
  });
  after(() => wb.close());
  const call = async (method, route, body) => {
    const response = await fetch(`${base}${route}`, { method, headers: { 'Content-Type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) });
    return { status: response.status, text: await response.text() };
  };
  const assertNoSecrets = text => {
    for (const secret of [TOKEN, KEY_FILE, APP_ID, INSTALLATION_ID, 'PRIVATE KEY', PEM.split('\n')[1]]) assert.ok(!text.includes(secret), `response leaks ${secret.slice(0, 12)}`);
    assert.ok(!/eyJ[\w-]+\.[\w-]+\.[\w-]+/.test(text), 'no JWT in a response');
  };

  it('starts unconfigured', async () => {
    const { status, text } = await call('GET', '/api/github/settings');
    assert.equal(status, 200);
    assert.equal(JSON.parse(text).configured, false);
  });

  it('rejects a missing key file and an http API URL', async () => {
    assert.equal((await call('POST', '/api/github/settings', { appId: APP_ID, installationId: INSTALLATION_ID, privateKeyFile: path.join(keyDir, 'missing.pem') })).status, 400);
    assert.equal((await call('POST', '/api/github/settings', { ...CONFIG, apiUrl: 'http://api.github.com' })).status, 400);
    assert.ok(!fs.existsSync(configPath()));
  });

  it('validates by minting a token, saves only the key path (0600), and never returns the key or token', async () => {
    const saved = await call('POST', '/api/github/settings', CONFIG);
    assert.equal(saved.status, 200, saved.text);
    const body = JSON.parse(saved.text);
    assert.equal(body.configured, true);
    assert.equal(body.repositories, 3);
    assertNoSecrets(saved.text);
    const file = fs.readFileSync(configPath(), 'utf8');
    assert.deepEqual(JSON.parse(file), CONFIG);
    assert.ok(!file.includes('PRIVATE KEY'));
    if (process.platform !== 'win32') assert.equal(fs.statSync(configPath()).mode & 0o777, 0o600);
    assert.ok(github.calls.some(entry => entry.url.endsWith('/installation/repositories?per_page=1') && entry.init.headers.Authorization === `Bearer ${TOKEN}`));
    assertNoSecrets((await call('GET', '/api/github/settings')).text);
  });

  it('connects Sources → GitHub with an installation token that never reaches the browser', async () => {
    const first = await call('GET', '/api/scm/connections');
    const second = await call('GET', '/api/scm/connections');
    assert.equal(connected.filter(item => !item.closed).length, 1, 'connected once while the token is fresh');
    assert.equal(connected[0].provider, 'github');
    assert.equal(connected[0].token, TOKEN);
    const [item] = JSON.parse(second.text);
    assert.equal(item.label, 'GitHub App · example-org');
    assertNoSecrets(first.text + second.text);
  });

  it('removes the settings and the App connection', async () => {
    const removed = await call('DELETE', '/api/github/settings');
    assert.equal(JSON.parse(removed.text).configured, false);
    assert.ok(!fs.existsSync(configPath()));
    assert.ok(fs.existsSync(KEY_FILE), 'the key file is left in place');
    assert.equal(connected.filter(item => !item.closed).length, 0);
  });
});
