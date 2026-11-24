'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { createAccessControl, requiredPermission, claimedRole } = require('../lib/rbac.cjs');

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
  assert.equal(control.observe(member, { subject: 'github|first' }).role, 'analyst');
  assert.equal(control.access(member).permissions.manageSettings, false);
  assert.equal(control.access(member).permissions.manageFindings, true);
  assert.deepEqual(control.access(member).members, []);
  assert.equal(claimedRole({ administrator: true }), null);
  assert.equal(claimedRole(['unrecognized', 'viewer']), 'viewer');
});

it('persists administrator assignments per organization, restricts member changes and retains a final administrator', t => {
  const directory = fixture(t), admin = user(), analyst = user(), otherCompany = user(BETA);
  let control = createAccessControl({ directory, adminSubjects: ['github|bootstrap'] });
  assert.equal(control.observe(admin, { subject: 'github|bootstrap' }).role, 'administrator');
  control.observe(analyst); control.observe(otherCompany, { roles: ['administrator'] });
  assert.throws(() => control.update(analyst, { userId: analyst.id, role: 'administrator' }), { status: 403 });
  assert.throws(() => control.update(admin, { userId: otherCompany.id, role: 'viewer' }), { status: 404 });
  assert.throws(() => control.update(admin, { userId: admin.id, role: 'analyst' }), { status: 409 });
  control.update(admin, { userId: analyst.id, role: 'viewer' });
  assert.equal(control.access(analyst).permissions.review, false);
  assert.equal(control.observe(analyst, { roles: ['administrator'] }).role, 'viewer', 'an administrator assignment survives a later login');
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
