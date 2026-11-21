'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const WebSocket = require('ws');
const { createWebApp } = require('../web-server.cjs');
const { createAuth0Fixture } = require('./helpers/auth0.cjs');

const COMPANIES = [{ slug: 'acme', name: 'Acme', auth0OrganizationId: 'org_Acme123' },
  { slug: 'beta', name: 'Beta Company', auth0OrganizationId: 'org_Beta456' }];
const PREFERENCES = label => ({ provider: 'openai', models: { openai: `fixture-${label}` }, codexDaybreak: false,
  bedrockRegion: '', lmstudioUrl: 'http://localhost:1234/v1' });

function fixtureDirectory(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-company-web-'));
  const active = { web: null };
  t.after(async () => { await active.web?.close(); fs.rmSync(root, { recursive: true, force: true }); });
  return { root, active };
}
async function start(root, active, companies = COMPANIES) {
  const reserve = net.createServer(); await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
  const port = reserve.address().port; await new Promise(resolve => reserve.close(resolve));
  const origin = `http://127.0.0.1:${port}`, provider = createAuth0Fixture();
  const web = createWebApp({ directory: root, origin, mode: 'process', companies,
    auth0: provider.configuration, auth0Fetch: provider.fetch });
  active.web = web;
  await new Promise(resolve => web.server.listen(port, '127.0.0.1', resolve));
  async function call(route, { method = 'GET', cookie, profile, json, headers = {} } = {}) {
    const response = await fetch(`${origin}${route}`, { method, redirect: 'manual', headers: {
      ...(!['GET', 'HEAD'].includes(method) ? { Origin: origin } : {}), ...(cookie ? { Cookie: cookie } : {}),
      ...(profile ? { 'X-Threatlint-Profile': profile } : {}), ...(json === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
      ...(json === undefined ? {} : { body: JSON.stringify(json) }) });
    const text = await response.text(); let body = text; try { body = JSON.parse(text); } catch { /* HTML page */ }
    return { status: response.status, body, headers: response.headers, cookie: response.headers.get('set-cookie')?.split(';')[0] };
  }
  function signIn(company) {
    const token = provider.issue({ subject: 'google-oauth2|same-person', email: 'same@example.test', displayName: 'Same Person',
      ...(company ? { claims: { org_id: company.auth0OrganizationId } } : {}) });
    return call('/auth/session', { method: 'POST', headers: { Authorization: `Bearer ${token}`,
      ...(company ? { 'X-Threatlint-Company': company.slug } : {}) } });
  }
  return { web, provider, call, signIn, origin };
}
function socket(origin, cookie, profile) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${origin.replace('http:', 'ws:')}/?profile=${encodeURIComponent(profile)}`, { origin, headers: { Cookie: cookie } });
    ws.once('open', () => resolve(ws)); ws.once('error', reject);
  });
}
function deniedSocket(origin, cookie, profile) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${origin.replace('http:', 'ws:')}/?profile=${encodeURIComponent(profile)}`, { origin, headers: { Cookie: cookie } });
    ws.on('error', () => {});
    ws.once('open', () => { ws.terminate(); reject(new Error('Cross-profile socket was accepted')); });
    ws.once('unexpected-response', (_req, response) => { response.resume(); ws.terminate(); resolve(response.statusCode); });
  });
}
function replay(ws) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Socket replay timed out')), 4000);
    ws.once('message', raw => { clearTimeout(timeout); resolve(JSON.parse(raw)); }); ws.send(JSON.stringify({ action: 'avit_batch_attach' }));
  });
}

it('separates personal and two organization profiles for the same identity, persisting each worker home and settings', async t => {
  const { root, active } = fixtureDirectory(t); let app = await start(root, active);
  const contexts = [null, ...COMPANIES], profiles = [];
  for (let index = 0; index < contexts.length; index++) {
    const session = await app.signIn(contexts[index]);
    assert.equal(session.status, 200); profiles.push(session);
    const user = session.body.user;
    if (contexts[index]) assert.equal(user.company.organizationId, contexts[index].auth0OrganizationId);
    else assert.equal(Object.hasOwn(user, 'company'), false);
    assert.equal((await app.call('/api/model-preferences', { method: 'PUT', cookie: session.cookie, profile: user.id, json: PREFERENCES(index) })).status, 200);
    const home = await app.call('/api/fs/browse', { cookie: session.cookie, profile: user.id });
    assert.equal(home.status, 200); assert.equal(home.body.path, fs.realpathSync(path.join(root, 'profiles', user.id)));
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(home.body.path, '.threatlint/workbench/model-preferences.json'), 'utf8')), PREFERENCES(index));
  }
  assert.equal(new Set(profiles.map(session => session.body.user.id)).size, 3);
  await app.web.close(); app = await start(root, active);
  for (let index = 0; index < contexts.length; index++) {
    const again = await app.signIn(contexts[index]); assert.equal(again.status, 200);
    assert.equal(again.body.user.id, profiles[index].body.user.id);
    assert.deepEqual((await app.call('/api/model-preferences', { cookie: again.cookie, profile: again.body.user.id })).body.preferences, PREFERENCES(index));
  }
});

it('authorizes company entry pages from verified organization membership and rejects requested-company mismatches', async t => {
  const { root, active } = fixtureDirectory(t), app = await start(root, active);
  for (const route of ['/c/acme/login', '/c/acme/', '/c/beta/']) {
    const guest = await app.call(route); assert.equal(guest.status, 200); assert.match(guest.body, /class="login-page"/);
  }
  for (const route of ['/c/unknown/login', '/c/unknown/', '/auth/config?company=unknown']) assert.equal((await app.call(route)).status, 404);
  const config = await app.call('/auth/config?company=acme');
  assert.equal(config.status, 200); assert.deepEqual(config.body.company, { slug: 'acme', name: 'Acme', organizationId: 'org_Acme123' });
  assert.equal(Object.hasOwn((await app.call('/auth/config')).body, 'company'), false);
  const good = await app.signIn(COMPANIES[0]); assert.equal(good.status, 200);
  const matched = await app.call('/c/acme/', { cookie: good.cookie });
  assert.equal(matched.status, 200); assert.match(matched.body, /id="view-workbench"/);
  const other = await app.call('/c/beta/', { cookie: good.cookie });
  assert.equal(other.status, 200); assert.match(other.body, /class="login-page"/); assert.doesNotMatch(other.body, /id="view-workbench"/);
  for (const [claims, requested] of [[{}, 'acme'], [{ org_id: 'org_Unknown' }, undefined], [{ org_id: 'org_Acme123' }, 'beta'],
    [{ org_id: 'org_Acme123' }, 'unknown'], [{ org_id: 'org_Acme123' }, '../acme']]) {
    const token = app.provider.issue({ claims });
    const denied = await app.call('/auth/session', { method: 'POST', headers: { Authorization: `Bearer ${token}`,
      ...(requested === undefined ? {} : { 'X-Threatlint-Company': requested }) } });
    assert.equal(denied.status, 403); assert.equal(denied.cookie, undefined);
  }
  const orgToken = app.provider.issue({ claims: { org_id: 'org_Beta456' } });
  const inferred = await app.call('/auth/session', { method: 'POST', headers: { Authorization: `Bearer ${orgToken}` } });
  assert.equal(inferred.status, 200); assert.equal(inferred.body.user.company.organizationId, 'org_Beta456');
  const personalToken = app.provider.issue({ subject: 'github|person-with-forged-body' });
  const bodyOnly = await app.call('/auth/session', { method: 'POST', headers: { Authorization: `Bearer ${personalToken}` }, json: { org_id: 'org_Acme123', company: 'acme' } });
  assert.equal(bodyOnly.status, 200); assert.equal(Object.hasOwn(bodyOnly.body.user, 'company'), false);
});

it('rejects stale HTTP and WebSocket profile selectors before accessing or mutating the new company profile', async t => {
  const { root, active } = fixtureDirectory(t), app = await start(root, active);
  const acme = await app.signIn(COMPANIES[0]), beta = await app.signIn(COMPANIES[1]);
  const acmeId = acme.body.user.id, betaId = beta.body.user.id;
  assert.equal((await app.call('/api/model-preferences', { method: 'PUT', cookie: beta.cookie, profile: betaId, json: PREFERENCES('beta') })).status, 200);
  for (const method of ['GET', 'PUT']) {
    const stale = await app.call('/api/model-preferences', { method, cookie: beta.cookie, profile: acmeId,
      ...(method === 'PUT' ? { json: PREFERENCES('wrong-company') } : {}) });
    assert.equal(stale.status, 409);
  }
  assert.deepEqual((await app.call('/api/model-preferences', { cookie: beta.cookie, profile: betaId })).body.preferences, PREFERENCES('beta'));
  // Navigation/download requests carry the same profile boundary in the URL instead of a custom header.
  for (const selector of [`_profile=${acmeId}`, '_profile=', `_profile=${betaId}&_profile=${acmeId}`]) {
    assert.equal((await app.call(`/api/model-preferences?${selector}`, { cookie: beta.cookie })).status, 409);
  }
  assert.deepEqual((await app.call(`/api/model-preferences?_profile=${betaId}`, { cookie: beta.cookie })).body.preferences, PREFERENCES('beta'));
  assert.equal(await deniedSocket(app.origin, beta.cookie, acmeId), 403);
  const matching = await socket(app.origin, beta.cookie, betaId); t.after(() => matching.terminate());
  assert.deepEqual(await replay(matching), { type: 'avit_batch_replay', runId: null, active: false, events: [] });
  const staleLogout = await app.call('/auth/logout', { method: 'POST', cookie: beta.cookie, profile: acmeId });
  assert.equal(staleLogout.status, 409);
  assert.equal((await app.call('/auth/session', { cookie: beta.cookie })).status, 200);
});

it('refreshes company metadata for existing sessions after a rename and rejects removed organization sessions', async t => {
  const { root, active } = fixtureDirectory(t); let app = await start(root, active);
  const company = await app.signIn(COMPANIES[0]), personal = await app.signIn(null);
  assert.equal(company.status, 200); assert.equal(personal.status, 200);
  const profile = company.body.user.id, saved = PREFERENCES('survives-company-rename');
  assert.equal((await app.call('/api/model-preferences', { method: 'PUT', cookie: company.cookie, profile, json: saved })).status, 200);
  const switchPage = await app.call('/login', { cookie: company.cookie });
  assert.equal(switchPage.status, 200); assert.equal(switchPage.headers.get('location'), null);
  assert.match(switchPage.body, /class="login-page"/);
  await app.web.close();
  const renamed = { ...COMPANIES[0], slug: 'acme-renamed', name: 'Acme Renamed' };
  app = await start(root, active, [renamed, COMPANIES[1]]);
  // Reuse the pre-rename cookie without performing a new federated login.
  const session = await app.call('/auth/session', { cookie: company.cookie });
  assert.equal(session.status, 200); assert.equal(session.body.user.id, profile);
  assert.deepEqual(session.body.user.company, { slug: renamed.slug, name: renamed.name, organizationId: renamed.auth0OrganizationId });
  assert.deepEqual((await app.call('/api/model-preferences', { cookie: company.cookie, profile })).body.preferences, saved);
  const newPath = await app.call('/c/acme-renamed/', { cookie: company.cookie });
  assert.equal(newPath.status, 200); assert.match(newPath.body, /id="view-workbench"/);
  assert.equal((await app.call('/c/acme/', { cookie: company.cookie })).status, 404);
  await app.web.close(); app = await start(root, active, [COMPANIES[1]]);
  assert.equal((await app.call('/auth/session', { cookie: company.cookie })).status, 401);
  assert.equal((await app.call('/api/model-preferences', { cookie: company.cookie, profile })).status, 401);
  assert.equal(await deniedSocket(app.origin, company.cookie, profile), 401);
  assert.equal((await app.call('/auth/session', { cookie: personal.cookie })).status, 200);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, 'profiles', profile, '.threatlint/workbench/model-preferences.json'), 'utf8')), saved);
});
