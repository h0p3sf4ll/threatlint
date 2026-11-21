'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const helperScript = new vm.Script(fs.readFileSync(path.join(__dirname, '../public/auth0-client.js'), 'utf8'));
const loginScript = new vm.Script(fs.readFileSync(path.join(__dirname, '../public/login.js'), 'utf8'));
const publicConfig = { provider: 'auth0', domain: 'threatlint.us.auth0.com', clientId: 'eysUAb8yPNapU4TXqRHpIfhSX4xC4Qqy',
  audience: 'https://threatlint.dev/api', redirectUri: 'https://threatlint.dev/',
  connections: { google: 'google-oauth2', apple: 'apple', github: 'github' } };
const plain = value => JSON.parse(JSON.stringify(value));
function setup({ search = '', config = publicConfig, lazy = false, callbackError, token = 'api-access-token', status = 200 } = {}) {
  const calls = [];
  const client = {
    loginWithRedirect: async options => { calls.push({ kind: 'login', options }); },
    handleRedirectCallback: async () => { calls.push({ kind: 'callback' }); if (callbackError) throw callbackError; },
    getTokenSilently: async () => { calls.push({ kind: 'token' }); return token; },
    logout: async options => { calls.push({ kind: 'logout', options }); },
  };
  const sdk = { createAuth0Client: async options => { calls.push({ kind: 'create', options }); return client; } };
  const window = lazy ? {} : { auth0: sdk };
  const context = vm.createContext({ window, URL, URLSearchParams,
    location: { origin: 'https://threatlint.dev', search },
    history: { replaceState: (_state, _title, url) => calls.push({ kind: 'history', url }) },
    document: { title: 'Threatlint', createElement: () => ({ listeners: {}, addEventListener(type, callback) { this.listeners[type] = callback; } }),
      head: { append(script) { calls.push({ kind: 'script', src: script.src }); window.auth0 = sdk; script.listeners.load(); } } },
    fetch: async (url, options) => {
      calls.push({ kind: 'fetch', url, options });
      if (url === '/auth/config') return { ok: true, json: async () => config };
      assert.equal(url, '/auth/session');
      return { ok: status === 200, json: async () => status === 200 ? { user: { id: 'verified-profile' } } : { error: 'Token could not be verified' } };
    },
  });
  helperScript.runInContext(context);
  return { auth: window.ThreatlintAuth, calls };
}

test('helper is inert on desktop and loads one bundled SDK only when authentication is requested', async () => {
  const { auth, calls } = setup({ lazy: true });
  assert.deepEqual(calls, []);
  await Promise.all([auth.initialize(), auth.initialize()]);
  assert.equal(calls.filter(call => call.kind === 'create').length, 1);
  assert.deepEqual(calls.filter(call => call.kind === 'script'), [{ kind: 'script', src: '/vendor/auth0-spa-js.js' }]);
  assert.deepEqual(plain(calls.find(call => call.kind === 'create').options), {
    domain: publicConfig.domain, clientId: publicConfig.clientId, cacheLocation: 'memory',
    authorizationParams: { redirect_uri: publicConfig.redirectUri, audience: publicConfig.audience, scope: 'openid profile email' },
  });
});

test('Google, Apple, and GitHub redirects select the configured connections; SSO uses Universal Login', async () => {
  const { auth, calls } = setup();
  for (const provider of ['google', 'apple', 'github', 'sso']) await auth.login(provider);
  const redirects = calls.filter(call => call.kind === 'login');
  assert.deepEqual(plain(redirects.slice(0, 3).map(call => call.options)), [
    { authorizationParams: { connection: 'google-oauth2' } }, { authorizationParams: { connection: 'apple' } }, { authorizationParams: { connection: 'github' } },
  ]);
  assert.equal(redirects[3].options, undefined);
  await assert.rejects(auth.login('password'), /unavailable/);
  assert.equal(calls.filter(call => call.kind === 'login').length, 4);
});

test('callback processing relies on SDK validation, then exchanges only the access token in Authorization', async () => {
  const { auth, calls } = setup({ search: '?code=authorization-code&state=transaction-state' });
  assert.equal(auth.callbackPresent(), true);
  assert.equal((await auth.completeRedirect()).user.id, 'verified-profile');
  assert.deepEqual(calls.filter(call => ['callback', 'token'].includes(call.kind)).map(call => call.kind), ['callback', 'token']);
  const exchange = calls.find(call => call.kind === 'fetch' && call.url === '/auth/session');
  assert.deepEqual(plain(exchange.options), { method: 'POST', credentials: 'same-origin', headers: { Authorization: 'Bearer api-access-token' } });
  assert.equal(Object.hasOwn(exchange.options, 'body'), false);
  assert.equal(calls.find(call => call.kind === 'history').url, 'https://threatlint.dev/');
});

test('failed SDK state validation never creates a server session and clears processed callback parameters', async () => {
  const { auth, calls } = setup({ search: '?code=invalid&state=mismatch', callbackError: new Error('State mismatch') });
  await assert.rejects(auth.completeRedirect(), /State mismatch/);
  assert.equal(calls.some(call => call.kind === 'token'), false);
  assert.equal(calls.some(call => call.url === '/auth/session'), false);
  assert.equal(calls.filter(call => call.kind === 'history').length, 1);
});

test('incomplete callbacks and rejected bearer tokens never redirect into the workbench', async () => {
  const incomplete = setup({ search: '?code=missing-state' });
  await assert.rejects(incomplete.auth.completeRedirect(), /incomplete/);
  assert.equal(incomplete.calls.some(call => call.kind === 'callback'), false);
  const rejected = setup({ search: '?code=valid&state=valid', status: 401 });
  await assert.rejects(rejected.auth.completeRedirect(), /Token could not be verified/);
});

test('Auth0 logout uses the registered root return URL and never starts login', async () => {
  const { auth, calls } = setup();
  await auth.logout();
  assert.deepEqual(plain(calls.find(call => call.kind === 'logout').options), { logoutParams: { returnTo: 'https://threatlint.dev/' } });
  assert.equal(calls.some(call => call.kind === 'login' || call.kind === 'token'), false);
});

test('a callback URL outside this application is rejected before SDK initialization', async () => {
  const { auth, calls } = setup({ config: { ...publicConfig, redirectUri: 'https://other.example/' } });
  await assert.rejects(auth.initialize(), /does not match/);
  assert.equal(calls.some(call => call.kind === 'create'), false);
});

test('login page offers only social and SSO buttons and does not automatically restart login after logout', async () => {
  const html = fs.readFileSync(path.join(__dirname, '../public/login.html'), 'utf8');
  assert.doesNotMatch(html, /<input\b|<form\b|type=["']password|\/auth\/(?:register|login)/i);
  assert.deepEqual([...html.matchAll(/data-identity="([^"]+)"/g)].map(match => match[1]), ['google', 'apple', 'github', 'sso']);
  const nodes = Object.fromEntries(['identity-options', 'login-status', 'login-error'].map(id => [id, { textContent: '', setAttribute: () => {} }]));
  const buttons = ['google', 'apple', 'github', 'sso'].map(identity => ({ disabled: true, dataset: { identity }, addEventListener: () => {} }));
  let redirects = 0;
  let exchanges = 0;
  loginScript.runInContext(vm.createContext({ URLSearchParams,
    document: { getElementById: id => nodes[id], querySelectorAll: () => buttons },
    location: { search: '?notice=provider-logout', replace: () => { redirects += 1; } },
    window: { ThreatlintAuth: { initialize: async () => {}, callbackPresent: () => false,
      login: async () => { redirects += 1; }, completeRedirect: async () => { exchanges += 1; } } },
  }));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(redirects, 0);
  assert.equal(exchanges, 0);
  assert.ok(buttons.every(button => !button.disabled));
  assert.match(nodes['login-error'].textContent, /signed out of Threatlint/);
});
