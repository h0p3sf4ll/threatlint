'use strict';
const { it } = require('node:test');
const assert = require('node:assert/strict');
const { createAuth0Management } = require('../lib/auth0-management.cjs');
const base = { domain: 'tenant.auth0.test', clientId: 'm2m-client', clientSecret: 'fixture-only-not-a-real-secret', connectionIds: ['con_Google'] };

it('uses fixed tenant HTTPS, coalesces scoped M2M tokens, and paginates verified identity memberships', async () => {
  const calls = []; let tokens = 0;
  const management = createAuth0Management({ ...base, transport: async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith('/oauth/token')) { tokens++; return Response.json({ access_token: 'fixture-management-token', expires_in: 3600 }); }
    assert.equal(new Headers(init.headers).get('authorization'), 'Bearer fixture-management-token');
    const parsed = new URL(url);
    assert.equal(parsed.pathname, '/api/v2/users/github%7Cuser/organizations');
    return Response.json({ organizations: [{ id: 'org_Acme', name: 'acme' }], total: 1 });
  } });
  const result = await Promise.all([management.listUserOrganizations('github|user'), management.listUserOrganizations('github|user')]);
  assert.equal(tokens, 1); assert.equal(result[0][0].id, 'org_Acme');
  const request = JSON.parse(calls[0].init.body);
  assert.equal(request.audience, 'https://tenant.auth0.test/api/v2/');
  assert.match(request.scope, /read:organizations/); assert.doesNotMatch(request.scope, /delete:users|update:users|create:client_grants/);
  for (const call of calls) { assert.equal(call.init.redirect, 'error'); assert.ok(call.init.signal instanceof AbortSignal); }
  assert.throws(() => management.listUserOrganizations('auth0|password'), { status: 400 });
});

it('retrieves all member pages and sends invitation-only connection and exact subject mutations', async () => {
  const calls = [];
  const management = createAuth0Management({ ...base, transport: async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith('/oauth/token')) return Response.json({ access_token: 'token', expires_in: 3600 });
    if (init.method === 'GET') {
      const page = new URL(url).searchParams.has('from') ? 1 : 0;
      return Response.json({ members: Array.from({ length: page ? 1 : 100 }, (_, i) => ({ user_id: `github|${page * 100 + i}` })), ...(page ? {} : { next: 'next-checkpoint' }) });
    }
    return new Response(null, { status: 204 });
  } });
  assert.equal((await management.listMembers('org_Acme')).length, 101);
  await management.enableConnection('org_Acme', 'con_Google');
  assert.deepEqual(JSON.parse(calls.at(-1).init.body), { connection_id: 'con_Google', assign_membership_on_login: false, is_signup_enabled: false, show_as_button: true });
  await management.removeMember('org_Acme', 'github|123');
  assert.equal(calls.at(-1).init.method, 'DELETE'); assert.deepEqual(JSON.parse(calls.at(-1).init.body), { members: ['github|123'] });
  assert.throws(() => management.listMembers('../org_Elsewhere'), { status: 400 });
});

it('fails closed without exposing provider errors, bounds pages/body and does not retry writes', async () => {
  let writes = 0;
  const management = createAuth0Management({ ...base, transport: async (url, init) => {
    if (url.endsWith('/oauth/token')) return Response.json({ access_token: 'token', expires_in: 3600 });
    writes++; return Response.json({ message: 'private-provider-detail' }, { status: 429 });
  } });
  await assert.rejects(management.addMember('org_Acme', 'github|123'), error => error.status === 503 && !error.message.includes('private-provider-detail'));
  assert.equal(writes, 1);
  const repeated = createAuth0Management({ ...base, transport: async url => url.endsWith('/oauth/token') ? Response.json({ access_token: 'token', expires_in: 3600 }) : Response.json({ organizations: Array.from({ length: 100 }, (_, i) => ({ id: `org_${i}` })), next: 'repeating-checkpoint' }) });
  await assert.rejects(repeated.listUserOrganizations('github|123'), { status: 503 });
  const oversized = createAuth0Management({ ...base, transport: async () => Response.json({ excess: 'x'.repeat(2 * 1024 * 1024) }) });
  await assert.rejects(oversized.listUserOrganizations('github|123'), { status: 503 });
});

it('keeps management optional but rejects partial or untrusted configuration', () => {
  assert.equal(createAuth0Management({ domain: base.domain, clientId: '', clientSecret: '' }), null);
  assert.throws(() => createAuth0Management({ ...base, clientSecret: '' }), /both/);
  assert.throws(() => createAuth0Management({ ...base, domain: 'tenant.auth0.test/path' }), /domain/);
  assert.throws(() => createAuth0Management({ ...base, connectionIds: ['con_Google', 'con_Google'] }), /unique/);
});

it('uses checkpoint pagination beyond the Auth0 offset limit and aborts with the gateway', async () => {
  const calls = [], shutdown = new AbortController();
  const management = createAuth0Management({ ...base, signal: shutdown.signal, transport: async (url, init) => {
    if (init.signal.aborted) throw new Error('aborted');
    if (url.endsWith('/oauth/token')) return Response.json({ access_token: 'token', expires_in: 3600 });
    const parsed = new URL(url); calls.push(parsed); assert.equal(parsed.searchParams.has('page'), false);
    const from = Number(parsed.searchParams.get('from') || 0), size = Math.min(100, 1001 - from);
    return Response.json({ members: Array.from({ length: size }, (_, i) => ({ user_id: `github|${from + i}` })), ...(from + size < 1001 ? { next: String(from + size) } : {}) });
  } });
  assert.equal((await management.listMembers('org_Large')).length, 1001); assert.equal(calls.length, 11);
  shutdown.abort(); await assert.rejects(management.listMembers('org_Large'), { status: 503 });
});
