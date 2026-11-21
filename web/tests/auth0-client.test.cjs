'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const helperScript = new vm.Script(fs.readFileSync(path.join(__dirname, '../public/auth0-client.js'), 'utf8'));
const loginScript = new vm.Script(fs.readFileSync(path.join(__dirname, '../public/login.js'), 'utf8'));
const publicConfig = { provider: 'auth0', domain: 'threatlint.us.auth0.com', clientId: 'eysUAb8yPNapU4TXqRHpIfhSX4xC4Qqy',
  audience: 'https://threatlint.dev/api', redirectUri: 'https://app.threatlint.dev/',
  connections: { google: 'google-oauth2', apple: 'apple', github: 'github' }, enabledProviders: ['google', 'apple', 'github', 'sso'] };
const plain = value => JSON.parse(JSON.stringify(value));
function setup({ search = '', pathname = '/', config = publicConfig, lazy = false, callbackError, token = 'api-access-token', status = 200,
  pendingCompany, callbackCompany = null, desktop = false } = {}) {
  const calls = [];
  const hints = new Map();
  if (pendingCompany) hints.set('threatlint.auth.pending-company.v1', pendingCompany);
  const companies = { acme: { slug: 'acme', name: 'Acme', organizationId: 'org_acme' }, beta: { slug: 'beta', name: 'Beta', organizationId: 'org_beta' } };
  const client = {
    loginWithRedirect: async options => { calls.push({ kind: 'login', options }); },
    handleRedirectCallback: async () => { calls.push({ kind: 'callback' }); if (callbackError) throw callbackError; return { appState: { companySlug: callbackCompany } }; },
    getTokenSilently: async options => { calls.push({ kind: 'token', options }); return token; },
    logout: async options => { calls.push({ kind: 'logout', options }); },
  };
  const sdk = { createAuth0Client: async options => { calls.push({ kind: 'create', options }); return client; } };
  const window = lazy ? {} : { auth0: sdk };
  window.sessionStorage = { getItem: key => hints.get(key) || null, setItem: (key, value) => hints.set(key, value), removeItem: key => hints.delete(key) };
  if (desktop) window.threatlintDesktop = { version: '1.0' };
  const context = vm.createContext({ window, URL, URLSearchParams,
    location: { origin: 'https://app.threatlint.dev', pathname, search },
    history: { replaceState: (_state, _title, url) => calls.push({ kind: 'history', url }) },
    document: { title: 'Threatlint', createElement: () => ({ listeners: {}, addEventListener(type, callback) { this.listeners[type] = callback; } }),
      head: { append(script) { calls.push({ kind: 'script', src: script.src }); window.auth0 = sdk; script.listeners.load(); } } },
    fetch: async (url, options) => {
      calls.push({ kind: 'fetch', url, options });
      if (url.startsWith('/auth/config')) {
        const slug = new URL(url, 'https://app.threatlint.dev').searchParams.get('company');
        return { ok: !slug || !!companies[slug], json: async () => ({ ...config, ...(slug ? { company: companies[slug] } : {}) }) };
      }
      assert.equal(url, '/auth/session');
      return { ok: status === 200, json: async () => status === 200 ? { user: { id: 'verified-profile',
        ...(options.headers['X-Threatlint-Company'] ? { company: companies[options.headers['X-Threatlint-Company']] } : {}) } } : { error: 'Token could not be verified' } };
    },
  });
  helperScript.runInContext(context);
  return { auth: window.ThreatlintAuth, calls, hints };
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
    { appState: { companySlug: null }, authorizationParams: { connection: 'google-oauth2' } },
    { appState: { companySlug: null }, authorizationParams: { connection: 'apple' } },
    { appState: { companySlug: null }, authorizationParams: { connection: 'github' } },
  ]);
  assert.deepEqual(plain(redirects[3].options), { appState: { companySlug: null } });
  await assert.rejects(auth.login('password'), /not configured/);
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
  assert.equal(calls.find(call => call.kind === 'history').url, 'https://app.threatlint.dev/');
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
  assert.deepEqual(plain(calls.find(call => call.kind === 'logout').options), { logoutParams: { returnTo: 'https://app.threatlint.dev/' } });
  assert.equal(calls.some(call => call.kind === 'login' || call.kind === 'token'), false);
});

test('a callback URL outside this application is rejected before SDK initialization', async () => {
  const { auth, calls } = setup({ config: { ...publicConfig, redirectUri: 'https://other.example/' } });
  await assert.rejects(auth.initialize(), /does not match/);
  assert.equal(calls.some(call => call.kind === 'create'), false);
});

test('login page offers only social and SSO buttons and does not automatically restart login after logout', async () => {
  const html = fs.readFileSync(path.join(__dirname, '../public/login.html'), 'utf8');
  assert.doesNotMatch(html, /type=["']password|name=["'](?:email|password|displayName)["']|\/auth\/(?:register|login)/i);
  assert.match(html, /name="companySlug"/);
  assert.deepEqual([...html.matchAll(/data-identity="([^"]+)"/g)].map(match => match[1]), ['google', 'apple', 'github', 'sso']);
  const nodes = Object.fromEntries(['identity-options', 'login-status', 'login-error', 'company-form', 'identity-sso-divider'].map(id => [id,
    { textContent: '', setAttribute: () => {}, addEventListener: () => {} }]));
  const buttons = ['google', 'apple', 'github', 'sso'].map(identity => ({ disabled: true, dataset: { identity }, addEventListener: () => {} }));
  let redirects = 0;
  let exchanges = 0;
  loginScript.runInContext(vm.createContext({ URLSearchParams,
    document: { getElementById: id => nodes[id], querySelectorAll: () => buttons },
    location: { search: '?notice=provider-logout', replace: () => { redirects += 1; } },
    window: { ThreatlintAuth: { initialize: async () => ({ config: publicConfig }), callbackPresent: () => false,
      login: async () => { redirects += 1; }, completeRedirect: async () => { exchanges += 1; } } },
  }));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(redirects, 0);
  assert.equal(exchanges, 0);
  assert.ok(buttons.every(button => !button.disabled));
  assert.match(nodes['login-error'].textContent, /signed out of Threatlint/);
});

test('the SDK never redirects to an unavailable provider even if its connection name is known', async () => {
  const { auth, calls } = setup({ config: { ...publicConfig, enabledProviders: ['google'] } });
  await auth.login('google');
  for (const provider of ['apple', 'github', 'sso']) await assert.rejects(auth.login(provider), /not configured/);
  assert.equal(calls.filter(call => call.kind === 'login').length, 1);
  assert.equal(calls.find(call => call.kind === 'login').options.authorizationParams.connection, 'google-oauth2');
});

test('login options remain hidden until configuration resolves and Google-only deployments hide unavailable buttons and SSO divider', async () => {
  const html = fs.readFileSync(path.join(__dirname, '../public/login.html'), 'utf8');
  for (const provider of ['google', 'apple', 'github', 'sso']) assert.match(html, new RegExp(`data-identity="${provider}" hidden disabled`));
  const nodes = Object.fromEntries(['identity-options', 'login-status', 'login-error', 'company-form', 'identity-sso-divider'].map(id => [id,
    { hidden: true, textContent: '', setAttribute: () => {}, addEventListener: () => {} }]));
  const buttons = ['google', 'apple', 'github', 'sso'].map(identity => ({ hidden: true, disabled: true, dataset: { identity }, addEventListener: () => {} }));
  let finishConfiguration;
  const pendingConfiguration = new Promise(resolve => { finishConfiguration = resolve; });
  loginScript.runInContext(vm.createContext({ URLSearchParams,
    document: { getElementById: id => nodes[id], querySelectorAll: () => buttons }, location: { search: '' },
    window: { ThreatlintAuth: { initialize: () => pendingConfiguration, callbackPresent: () => false } },
  }));
  assert.ok(buttons.every(button => button.hidden && button.disabled));
  finishConfiguration({ config: { ...publicConfig, enabledProviders: ['google'] } });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(buttons[0].hidden, false); assert.equal(buttons[0].disabled, false);
  assert.ok(buttons.slice(1).every(button => button.hidden && button.disabled));
  assert.equal(nodes['identity-sso-divider'].hidden, true);
});

test('company sign-in selects its Auth0 organization and preserves the slug inside the SDK transaction', async () => {
  const { auth, calls, hints } = setup({ pathname: '/c/acme/login' });
  await auth.login('github');
  assert.equal(calls.find(call => call.url?.startsWith('/auth/config')).url, '/auth/config?company=acme');
  assert.equal(calls.find(call => call.kind === 'create').options.authorizationParams.organization, 'org_acme');
  assert.deepEqual(plain(calls.find(call => call.kind === 'login').options), {
    appState: { companySlug: 'acme' }, authorizationParams: { connection: 'github' },
  });
  assert.equal(hints.get('threatlint.auth.pending-company.v1'), 'acme');
  await auth.login('sso');
  assert.deepEqual(plain(calls.filter(call => call.kind === 'login')[1].options), { appState: { companySlug: 'acme' } });
});

test('root callback uses the pending organization only for bootstrap and exchanges an organization-scoped access token', async () => {
  const { auth, calls, hints } = setup({ search: '?code=code&state=state', pendingCompany: 'acme', callbackCompany: 'acme' });
  const result = await auth.completeRedirect();
  assert.equal(result.user.company.slug, 'acme');
  assert.equal(calls.find(call => call.kind === 'create').options.authorizationParams.organization, 'org_acme');
  assert.deepEqual(plain(calls.find(call => call.kind === 'token').options), { authorizationParams: { organization: 'org_acme' } });
  const exchange = calls.find(call => call.url === '/auth/session');
  assert.deepEqual(plain(exchange.options.headers), { Authorization: 'Bearer api-access-token', 'X-Threatlint-Company': 'acme' });
  assert.equal(Object.hasOwn(exchange.options, 'body'), false);
  assert.equal(hints.has('threatlint.auth.pending-company.v1'), false);
});

test('missing routing hint can be recovered from SDK appState while a conflicting hint cannot grant company access', async () => {
  const recovered = setup({ search: '?code=code&state=state', callbackCompany: 'acme' });
  await recovered.auth.completeRedirect();
  assert.equal(recovered.calls.some(call => call.url === '/auth/config?company=acme'), true);
  assert.equal(recovered.calls.find(call => call.kind === 'token').options.authorizationParams.organization, 'org_acme');
  const conflicting = setup({ search: '?code=code&state=state', pendingCompany: 'beta', callbackCompany: 'acme' });
  await assert.rejects(conflicting.auth.completeRedirect(), /context changed/);
  assert.equal(conflicting.calls.some(call => call.url === '/auth/session'), false);
  assert.equal(conflicting.hints.has('threatlint.auth.pending-company.v1'), false);
});

test('native desktop never initializes Auth0 or fetches configuration', async () => {
  const { auth, calls } = setup({ desktop: true });
  await assert.rejects(auth.initialize(), /does not require web sign-in/);
  assert.deepEqual(calls, []);
});

test('company slug routing accepts only bounded slug syntax', () => {
  const { auth } = setup();
  assert.equal(auth.normalizeCompanySlug('  ACME-TEAM  '), 'acme-team');
  for (const value of ['ab', '../acme', 'acme/other', '-acme', 'acme-', 'a'.repeat(64), '<script>']) assert.throws(() => auth.normalizeCompanySlug(value), /company slug/);
});
