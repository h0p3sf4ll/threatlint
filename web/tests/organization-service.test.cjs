'use strict';
const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { createOrganizationService } = require('../lib/organization-service.cjs');
const { createCompanies } = require('../lib/companies.cjs');
const issuer = 'https://tenant.auth0.test/', identity = { issuer, subject: 'github|creator' };
function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-organizations-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const remote = new Map(), memberships = new Map(), calls = [], grants = [];
  let loseResponse = false, grantFailure = false;
  const management = { connections: ['con_Google'],
    async listUserOrganizations(subject) { return [...remote.values()].filter(value => memberships.get(value.id)?.has(subject)); },
    async getOrganizationByName(name) { calls.push('get'); return remote.get(name) || null; },
    async createOrganization(body) { calls.push('create'); const value = { ...body, id: `org_${remote.size + 1}` }; remote.set(body.name, value); if (loseResponse) { loseResponse = false; throw new Error('lost response'); } return value; },
    async listConnections(id) { return [...remote.values()].find(value => value.id === id).enabled_connections; },
    async enableConnection() { throw new Error('Expected atomic enabled connections'); },
    async addMember(id, subject) { calls.push('add'); if (!memberships.has(id)) memberships.set(id, new Set()); memberships.get(id).add(subject); },
  };
  const restart = () => {
    const companies = createCompanies({ directory, companies: [] });
    return { companies, service: createOrganizationService({ directory, issuer, companies, management,
      grantCreator: async (...args) => { if (grantFailure) { grantFailure = false; throw new Error('write failed'); } grants.push(args); } }) };
  };
  return { directory, remote, memberships, management, calls, grants, restart, loseResponse() { loseResponse = true; }, failGrant() { grantFailure = true; } };
}
it('discovers preadded users from exact verified subjects, never email, domain or supplied organization fields', async t => {
  const state = fixture(t), { service } = state.restart();
  state.remote.set('existing', { id: 'org_Existing', name: 'existing', display_name: 'Existing Team' }); state.memberships.set('org_Existing', new Set(['github|creator']));
  assert.deepEqual(await service.memberships(identity), [{ slug: 'existing', name: 'Existing Team', organizationId: 'org_Existing' }]);
  assert.deepEqual(await service.memberships({ issuer, subject: 'github|stranger', email: 'creator@example.test' }), []);
  await assert.rejects(service.memberships({ issuer: 'https://other.test/', subject: identity.subject }), { status: 401 });
  await assert.rejects(service.create(identity, { name: 'Other', idempotencyKey: crypto.randomUUID() }), { status: 409 });
});
it('resumes a lost create response across restart without duplicates and grants creator administration exactly once', async t => {
  const state = fixture(t), input = { name: 'My Team', idempotencyKey: crypto.randomUUID() };
  state.loseResponse(); await assert.rejects(state.restart().service.create(identity, input), /lost response/);
  const restarted = state.restart(), company = await restarted.service.create(identity, input);
  assert.equal(state.calls.filter(value => value === 'create').length, 1); assert.equal(state.grants.length, 1);
  assert.equal(state.grants[0][0].subject, identity.subject); assert.equal(company.organizationId, 'org_1');
  assert.equal(state.remote.size, 1); assert.equal(state.remote.values().next().value.enabled_connections[0].assign_membership_on_login, false);
  assert.equal(state.remote.values().next().value.enabled_connections[0].is_signup_enabled, false);
  assert.equal((await state.restart().service.create(identity, input)).organizationId, company.organizationId);
  assert.equal(state.grants.length, 1, 'retrying a completed request cannot promote a demoted creator');
  await assert.rejects(restarted.service.create(identity, { ...input, name: 'Changed' }), { status: 409 });
  state.memberships.get(company.organizationId).delete(identity.subject);
  await assert.rejects(state.restart().service.create(identity, input), { status: 403 });
  assert.equal(state.memberships.get(company.organizationId).size, 0, 'completed retry cannot re-add a removed creator');
});
it('hides incomplete creations and recovers after a local administrator write fails', async t => {
  const state = fixture(t), input = { name: 'Retry Team', idempotencyKey: crypto.randomUUID() };
  state.failGrant(); await assert.rejects(state.restart().service.create(identity, input), /write failed/);
  let restarted = state.restart();
  assert.deepEqual(await restarted.service.memberships(identity), []); assert.deepEqual(restarted.companies.list(), []);
  const company = await restarted.service.create(identity, input);
  restarted = state.restart(); assert.equal((await restarted.service.memberships(identity))[0].organizationId, company.organizationId);
  assert.equal(state.remote.size, 1);
});
it('serializes concurrent creation retries, rejects malformed input and preserves corrupt operation state', async t => {
  const state = fixture(t), input = { name: 'Team', idempotencyKey: crypto.randomUUID() }, { service } = state.restart();
  const values = await Promise.all([service.create(identity, input), service.create(identity, input)]);
  assert.equal(values[0].organizationId, values[1].organizationId); assert.equal(state.remote.size, 1); assert.equal(state.grants.length, 1);
  for (const invalid of [{ name: '', idempotencyKey: crypto.randomUUID() }, { ...input, organizationId: 'org_Forged' }, { ...input, idempotencyKey: 'invalid' }]) await assert.rejects(service.create(identity, invalid), { status: 400 });
  const file = path.join(state.directory, 'organization-operations.json'); fs.writeFileSync(file, '{ broken');
  assert.throws(state.restart, /original data was preserved/); assert.equal(fs.readFileSync(file, 'utf8'), '{ broken');
});

it('drains a stopped creation queue without issuing further remote writes and leaves its journal resumable', async t => {
  const state = fixture(t), input = { name: 'Restart Team', idempotencyKey: crypto.randomUUID() };
  let unblock, started;
  const ready = new Promise(resolve => { started = resolve; });
  const original = state.management.getOrganizationByName;
  state.management.getOrganizationByName = () => { started(); return new Promise(resolve => { unblock = resolve; }); };
  const { service } = state.restart(), first = service.create(identity, input);
  await ready;
  const queued = service.create(identity, input), closing = service.close(); unblock(null);
  const results = await Promise.allSettled([first, queued, closing]);
  assert.equal(results[0].status, 'rejected'); assert.equal(results[1].status, 'rejected'); assert.equal(results[2].status, 'fulfilled');
  assert.equal(state.remote.size, 0); assert.equal(state.grants.length, 0);
  state.management.getOrganizationByName = original;
  assert.equal((await state.restart().service.create(identity, input)).organizationId, 'org_1');
});

it('refuses to complete creation if enabled connections drift outside approved invitation-only policy', async t => {
  for (const connection of [{ connection_id: 'con_Unapproved', assign_membership_on_login: false },
    { connection_id: 'con_Google', assign_membership_on_login: true },
    { connection_id: 'con_Google', assign_membership_on_login: false, is_signup_enabled: true }]) {
    const state = fixture(t); state.management.listConnections = async () => [connection];
    const { service, companies } = state.restart();
    await assert.rejects(service.create(identity, { name: 'Private Team', idempotencyKey: crypto.randomUUID() }), { status: 503 });
    assert.equal(state.grants.length, 0); assert.equal(state.memberships.size, 0); assert.deepEqual(companies.list(), []);
  }
});
