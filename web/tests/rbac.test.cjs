'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { createAccessControl, requiredPermission, claimedRole } = require('../lib/rbac.cjs');

const ISSUER = 'https://tenant.example.test/';
const OTHER_ISSUER = 'https://other.example.test/';
const ACME = { slug: 'acme', name: 'Acme', organizationId: 'org_Acme123' };
const BETA = { slug: 'beta', name: 'Beta', organizationId: 'org_Beta456' };
function user(company = ACME) { return { id: crypto.randomUUID(), email: 'member@example.test', displayName: 'Member', ...(company ? { company } : {}) }; }
function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-access-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

it('gives personal owners administration and company members analyst access without first-user promotion', t => {
  const control = createAccessControl({ directory: fixture(t), adminSubjects: [] });
  const personal = user(null), member = user();
  assert.equal(control.access(personal).role, 'administrator');
  assert.equal(control.observe(member, { issuer: ISSUER, subject: 'github|first' }).role, 'analyst');
  assert.equal(control.access(member).permissions.manageSettings, false);
  assert.equal(control.access(member).permissions.manageFindings, true);
  assert.deepEqual(control.access(member).members, []);
  assert.equal(claimedRole({ administrator: true }), null);
  assert.equal(claimedRole(['unrecognized', 'viewer']), 'viewer');
});

it('persists administrator assignments per organization, restricts member changes and retains a final administrator', t => {
  const directory = fixture(t), admin = user(), analyst = user(), otherCompany = user(BETA);
  let control = createAccessControl({ directory, adminSubjects: ['github|bootstrap'] });
  assert.equal(control.observe(admin, { issuer: ISSUER, subject: 'github|bootstrap' }).role, 'administrator');
  control.observe(analyst, { issuer: ISSUER, subject: 'github|analyst' }); control.observe(otherCompany, { issuer: ISSUER, subject: 'github|other', roles: ['administrator'] });
  assert.throws(() => control.update(analyst, { userId: analyst.id, role: 'administrator' }), { status: 403 });
  assert.throws(() => control.update(admin, { userId: otherCompany.id, role: 'viewer' }), { status: 404 });
  assert.throws(() => control.update(admin, { userId: admin.id, role: 'analyst' }), { status: 409 });
  control.update(admin, { userId: analyst.id, role: 'viewer' });
  assert.equal(control.access(analyst).permissions.review, false);
  assert.equal(control.observe(analyst, { issuer: ISSUER, subject: 'github|analyst', roles: ['administrator'] }).role, 'viewer', 'an administrator assignment survives a later login');
  control = createAccessControl({ directory, adminSubjects: [] });
  assert.equal(control.access(admin).role, 'administrator');
  assert.equal(control.access(analyst).role, 'viewer');
  assert.equal(control.access(admin).members.length, 2);
  assert.equal(control.access(otherCompany).members.length, 1);
  control.update(admin, { userId: analyst.id, role: 'administrator' });
  control.update(admin, { userId: admin.id, role: 'analyst' });
  assert.equal(control.access(analyst).role, 'administrator');
});

it('scopes shared state by stable organization identity and keeps personal identities separate', t => {
  const control = createAccessControl({ directory: fixture(t) });
  const alice = user(), bob = user(), renamed = { ...alice, company: { ...ACME, name: 'New name', slug: 'acme-renamed' } };
  assert.equal(control.scopeDirectory(alice), control.scopeDirectory(bob));
  assert.equal(control.scopeDirectory(alice), control.scopeDirectory(renamed));
  assert.notEqual(control.scopeDirectory(alice), control.scopeDirectory({ ...alice, company: BETA }));
  assert.notEqual(control.scopeDirectory(user(null)), control.scopeDirectory(user(null)));
  assert.throws(() => control.scopeDirectory({ id: '../../escape' }), { status: 401 });
  assert.throws(() => control.scopeDirectory({ ...alice, company: { organizationId: '../../escape' } }), { status: 401 });
});

it('covers existing settings, integration writes and reviews with route-specific permissions', () => {
  for (const route of ['/api/github/settings', '/api/servicenow/settings', '/api/semgrep/settings', '/api/ado/settings/test-org',
    '/api/ado/service-account', '/api/issue-trackers/github/settings', '/api/issue-trackers/jira/settings/', '/API/ISSUE-TRACKERS/AZURE-DEVOPS/SETTINGS', '/api/scanners/dojo/settings',
    '/api/management/connections', '/api/management/connections/one', '/api/management/connections/one/test', '/API/GITHUB/SETTINGS']) {
    assert.equal(requiredPermission('POST', route), 'manageSettings', route);
    assert.equal(requiredPermission('GET', route), 'read', route);
  }
  for (const route of ['/api/model-preferences', '/API/MODEL-PREFERENCES/', '/api/scm/connections', '/API/SCM/CONNECTIONS/one/']) {
    assert.equal(requiredPermission('PUT', route), 'review', route);
    assert.equal(requiredPermission('DELETE', route), 'review', route);
  }
  assert.equal(requiredPermission('POST', '/api/access/members'), 'manageMembers');
  assert.equal(requiredPermission('POST', '/api/management/findings/create'), 'manageFindings');
  assert.equal(requiredPermission('POST', '/api/management/connections/one/activate'), 'review');
  assert.equal(requiredPermission('POST', '/api/session/local'), 'review');
  assert.equal(requiredPermission('POST', '/api/runtime/scans'), 'review');
  assert.equal(requiredPermission('DELETE', '/api/session/one/reports/two'), 'review');
  assert.equal(requiredPermission('POST', '/api/metrics/query'), 'read');
  assert.equal(requiredPermission('POST', '/api/trackers/servicenow-avit/items'), 'read');
  assert.equal(requiredPermission('POST', '/api/mcp'), 'review');
  assert.equal(requiredPermission('POST', '/api/intelligence/findings/resolve'), 'review');
});

it('fails closed if persisted access data is invalid and preserves the original file', t => {
  const directory = fixture(t), control = createAccessControl({ directory }), member = user();
  const scope = control.scopeDirectory(member); fs.mkdirSync(scope, { recursive: true });
  const file = path.join(scope, 'access.json'), malformed = '{"version":1,"members":[{"userId":"forged","role":"administrator"}]}';
  fs.writeFileSync(file, malformed);
  assert.throws(() => control.access(member), /original data was preserved/);
  assert.equal(fs.readFileSync(file, 'utf8'), malformed);
});

it('assigns pre-login members by exact issuer and subject and keeps managed roles through first login', t => {
  const directory = fixture(t), admin = user(), future = user(), sameEmail = user(), otherIssuer = user();
  let control = createAccessControl({ directory, adminSubjects: ['github|bootstrap'] });
  control.observe(admin, { issuer: ISSUER, subject: 'github|bootstrap' });
  let result = control.mergeMembers(admin, [
    { user_id: 'github|bootstrap', name: 'Current administrator' }, { user_id: 'github|future', name: 'Not signed in', email: future.email },
  ], { issuer: ISSUER, profileForIdentity: value => value.subject === 'github|bootstrap' ? admin : null });
  assert.equal(result.members.length, 2);
  assert.equal(result.members.find(member => member.subject === 'github|future').userId, null);
  assert.equal(result.members.find(member => member.subject === 'github|future').role, 'analyst');
  result = control.assignIdentity(admin, { issuer: ISSUER, subject: 'github|future', role: 'viewer' });
  assert.equal(result.members.find(member => member.subject === 'github|future').role, 'viewer');
  control = createAccessControl({ directory, adminSubjects: [] });
  assert.equal(control.observe(future, { issuer: ISSUER, subject: 'github|future', roles: ['administrator'] }).role, 'viewer');
  assert.equal(control.observe(sameEmail, { issuer: ISSUER, subject: 'github|someone-else' }).role, 'analyst', 'email never matches an assignment');
  assert.equal(control.observe(otherIssuer, { issuer: OTHER_ISSUER, subject: 'github|future' }).role, 'analyst', 'the same subject from another issuer is a different identity');
  assert.throws(() => control.observe({ ...future, id: crypto.randomUUID() }, { issuer: ISSUER, subject: 'github|future' }), { status: 409 });
  assert.throws(() => control.observe({ ...sameEmail, id: future.id }, { issuer: ISSUER, subject: 'github|someone-else' }), { status: 409 });
  assert.throws(() => control.assignIdentity(sameEmail, { issuer: ISSUER, subject: 'github|new', role: 'administrator' }), { status: 403 });
});

it('migrates UUID-only records on verified observation without losing explicit assignments', t => {
  const directory = fixture(t), admin = user(), member = user();
  let control = createAccessControl({ directory });
  const scope = control.scopeDirectory(admin), filename = path.join(scope, 'access.json');
  fs.mkdirSync(scope, { recursive: true });
  fs.writeFileSync(filename, JSON.stringify({ version: 1, members: [
    { userId: admin.id, displayName: 'Admin', email: admin.email, role: 'administrator', source: 'administrator' },
    { userId: member.id, displayName: 'Member', email: member.email, role: 'viewer', source: 'administrator' },
  ] }));
  assert.equal(control.observe(member, { issuer: ISSUER, subject: 'github|member', roles: ['administrator'] }).role, 'viewer');
  let data = JSON.parse(fs.readFileSync(filename, 'utf8'));
  assert.equal(data.version, 2);
  assert.equal(data.members[0].issuer, ISSUER);
  assert.equal(data.members[0].subject, 'github|member');
  assert.equal(data.legacyMembers[0].userId, admin.id);
  control.observe(admin, { issuer: ISSUER, subject: 'github|admin', roles: ['viewer'] });
  data = JSON.parse(fs.readFileSync(filename, 'utf8'));
  assert.deepEqual(data.legacyMembers, []);
  control = createAccessControl({ directory });
  assert.equal(control.access(admin).role, 'administrator');
  control.update(admin, { userId: member.id, role: 'analyst' });
  assert.equal(control.access(member).role, 'analyst', 'existing UUID-based updates remain supported');
  assert.throws(() => control.observe(member, { subject: 'github|member' }), { status: 400 });
});

it('grants only the explicit organization creator and does not replay over later administrator changes', t => {
  const control = createAccessControl({ directory: fixture(t), issuer: ISSUER }), creator = user(), other = user();
  assert.equal(control.grantCreator({ issuer: ISSUER, subject: 'github|creator' }, ACME).userId, null);
  assert.equal(control.observe(other, { issuer: ISSUER, subject: 'github|other' }).role, 'analyst');
  assert.equal(control.observe(creator, { issuer: ISSUER, subject: 'github|creator', roles: ['viewer'] }).role, 'administrator');
  assert.equal(control.grantCreator({ issuer: ISSUER, subject: 'github|creator' }, ACME).role, 'administrator');
  assert.throws(() => control.updateIdentity(creator, { issuer: ISSUER, subject: 'github|creator', role: 'analyst' }), { status: 409 });
  control.assignIdentity(creator, { issuer: ISSUER, subject: 'github|other', userId: other.id, role: 'administrator' });
  control.updateIdentity(creator, { issuer: ISSUER, subject: 'github|creator', role: 'analyst' });
  assert.throws(() => control.grantCreator({ issuer: ISSUER, subject: 'github|creator' }, ACME), { status: 409 });
  assert.throws(() => control.observe(user(), { issuer: OTHER_ISSUER, subject: 'github|creator' }), { status: 400 });
  assert.throws(() => control.grantCreator({ issuer: ISSUER, subject: 'auth0|password-account' }, ACME), { status: 400 });
});

it('counts actual Auth0 membership for final-admin guards and lists all members before their first login', t => {
  const control = createAccessControl({ directory: fixture(t), adminSubjects: ['github|bootstrap'] }), admin = user(), stale = user();
  control.observe(admin, { issuer: ISSUER, subject: 'github|bootstrap' });
  control.observe(stale, { issuer: ISSUER, subject: 'github|stale', roles: ['administrator'] });
  const remote = [{ user_id: 'github|bootstrap', name: 'Renamed administrator' }, { user_id: 'github|prelogin', name: 'Future member' }];
  const result = control.mergeMembers(admin, remote, { issuer: ISSUER, profileForIdentity: value => value.subject === 'github|bootstrap' ? admin : null });
  assert.deepEqual(result.members.map(member => member.subject), ['github|bootstrap', 'github|prelogin']);
  assert.equal(result.members[0].displayName, 'Renamed administrator');
  assert.equal(result.members[1].userId, null);
  assert.throws(() => control.update(admin, { userId: admin.id, role: 'viewer' }), { status: 409 });
  assert.throws(() => control.assertRemovable(admin, { issuer: ISSUER, subject: 'github|bootstrap' }), { status: 409 });
  assert.throws(() => control.update(admin, { userId: stale.id, role: 'viewer' }), { status: 404 });
  control.updateIdentity(admin, { issuer: ISSUER, subject: 'github|prelogin', role: 'administrator' });
  assert.doesNotThrow(() => control.assertRemovable(admin, { issuer: ISSUER, subject: 'github|bootstrap' }));
  assert.deepEqual(control.removeIdentity(admin, { issuer: ISSUER, subject: 'github|bootstrap' }), { removed: true });
  assert.throws(() => control.access(admin), { status: 403 });
});

it('removal cannot resurrect a managed role through old claims and explicit re-addition starts with its selected role', t => {
  const directory = fixture(t), admin = user(), member = user();
  let control = createAccessControl({ directory, adminSubjects: ['github|bootstrap'] });
  control.observe(admin, { issuer: ISSUER, subject: 'github|bootstrap' });
  control.observe(member, { issuer: ISSUER, subject: 'github|member' });
  control.assignIdentity(admin, { issuer: ISSUER, subject: 'github|member', role: 'administrator' });
  control.mergeMembers(admin, [{ user_id: 'github|bootstrap' }, { user_id: 'github|member' }], { issuer: ISSUER });
  assert.deepEqual(control.removeIdentity(admin, { issuer: ISSUER, subject: 'github|member' }), { removed: true });
  control = createAccessControl({ directory, adminSubjects: [] });
  assert.throws(() => control.observe(member, { issuer: ISSUER, subject: 'github|member', roles: ['administrator'] }), { status: 403 });
  assert.throws(() => control.access(member), { status: 403 });
  let merged = control.mergeMembers(admin, [{ user_id: 'github|bootstrap' }, { user_id: 'github|member' }], { issuer: ISSUER });
  const blocked = merged.members.find(item => item.subject === 'github|member');
  assert.equal(blocked.blocked, true, 'An ambiguous remote deletion remains visible as blocked');
  assert.equal(blocked.role, 'viewer');
  assert.equal(blocked.userId, member.id, 'Removal retries retain the original UUID binding');
  assert.throws(() => control.assertRemovable(admin, { issuer: ISSUER, subject: 'github|bootstrap' }), { status: 409 });
  control.removeIdentity(admin, { issuer: ISSUER, subject: 'github|member' });
  assert.throws(() => control.access(member), { status: 403 });
  merged = control.mergeMembers(admin, [{ user_id: 'github|bootstrap' }, { user_id: 'github|member' }], { issuer: ISSUER });
  assert.equal(merged.members.find(item => item.subject === 'github|member').blocked, true);
  control.updateIdentity(admin, { issuer: ISSUER, subject: 'github|member', role: 'viewer' });
  assert.equal(control.observe(member, { issuer: ISSUER, subject: 'github|member', roles: ['administrator'] }).role, 'viewer');
  assert.throws(() => control.removeIdentity(member, { issuer: ISSUER, subject: 'github|bootstrap' }), { status: 403 });
});

it('rejects ambiguous remote members and malformed v2 identity records without replacing persisted data', t => {
  const directory = fixture(t), admin = user(), control = createAccessControl({ directory, adminSubjects: ['github|bootstrap'] });
  control.observe(admin, { issuer: ISSUER, subject: 'github|bootstrap' });
  assert.throws(() => control.mergeMembers(admin, [{ user_id: 'github|one' }, { user_id: 'github|one' }], { issuer: ISSUER }), { status: 503 });
  assert.throws(() => control.mergeMembers(admin, [{ user_id: 'github|one' }, { user_id: 'github|two' }], { issuer: ISSUER, profileForIdentity: () => user(BETA) }), { status: 503 });
  const scope = control.scopeDirectory(admin), filename = path.join(scope, 'access.json');
  const data = JSON.parse(fs.readFileSync(filename, 'utf8'));
  data.members.push({ ...data.members[0], userId: crypto.randomUUID() });
  const malformed = JSON.stringify(data); fs.writeFileSync(filename, malformed);
  const restarted = createAccessControl({ directory });
  assert.throws(() => restarted.access(admin), /original data was preserved/);
  assert.equal(fs.readFileSync(filename, 'utf8'), malformed);
});
