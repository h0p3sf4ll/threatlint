'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createCompanies } = require('../lib/companies.cjs');

const COMPANIES = [{ slug: 'acme', name: 'Acme', auth0OrganizationId: 'org_Acme123' },
  { slug: 'example-company', name: 'Example Company', auth0OrganizationId: 'org_Example456' }];
function directory(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-companies-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

it('indexes configured companies by exact slug and organization ID without deriving membership from URL data', () => {
  const registry = createCompanies({ companies: COMPANIES });
  assert.deepEqual(registry.get('acme'), { slug: 'acme', name: 'Acme', organizationId: 'org_Acme123' });
  assert.strictEqual(registry.forOrganization('org_Acme123'), registry.get('acme'));
  assert.equal(registry.forOrganization('org_acme123'), null);
  for (const slug of ['ACME', '../acme', 'acme/path', '%61cme', 'https://acme.example', 'auth', null]) assert.equal(registry.get(slug), null);
  assert.deepEqual(registry.publicCompany(registry.get('acme')), { slug: 'acme', name: 'Acme' });
  assert.deepEqual(registry.list(), [{ slug: 'acme', name: 'Acme' }, { slug: 'example-company', name: 'Example Company' }]);
  assert.ok(Object.isFrozen(registry)); assert.ok(Object.isFrozen(registry.get('acme'))); assert.ok(Object.isFrozen(registry.list()));
  assert.throws(() => { registry.get('acme').organizationId = 'org_Attacker'; }, TypeError);
});

it('loads only an explicitly configured absolute JSON file and allows explicit empty test configuration', t => {
  const root = directory(t), file = path.join(root, 'companies.json');
  fs.writeFileSync(file, JSON.stringify(COMPANIES));
  assert.equal(createCompanies({ file }).get('acme').organizationId, 'org_Acme123');
  const prior = process.env.THREATLINT_COMPANIES_FILE;
  try {
    delete process.env.THREATLINT_COMPANIES_FILE; assert.deepEqual(createCompanies().list(), []);
    process.env.THREATLINT_COMPANIES_FILE = file;
    assert.equal(createCompanies().get('acme').organizationId, 'org_Acme123');
    assert.deepEqual(createCompanies({ companies: [] }).list(), []);
  } finally { if (prior === undefined) delete process.env.THREATLINT_COMPANIES_FILE; else process.env.THREATLINT_COMPANIES_FILE = prior; }
  assert.deepEqual(createCompanies({ companies: [], file }).list(), []);
  assert.deepEqual(createCompanies({ file: '' }).list(), []);
  assert.throws(() => createCompanies({ file: 'companies.json' }), /absolute/);
  assert.throws(() => createCompanies({ file: 'https://example.test/companies.json' }), /absolute/);
  fs.writeFileSync(file, '{ malformed registry');
  assert.throws(() => createCompanies({ file }), /could not be read/);
  assert.equal(fs.readFileSync(file, 'utf8'), '{ malformed registry');
});

it('rejects malformed, reserved or duplicate slugs and organizations before serving any company', () => {
  for (const slug of ['ab', 'a'.repeat(64), '-acme', 'acme-', 'Acme', 'a_b', 'a.b', '../acme', 'acme/path',
    'auth', 'api', 'login', 'admin', 'vendor', 'www', 'app', 'personal']) {
    assert.throws(() => createCompanies({ companies: [{ ...COMPANIES[0], slug }] }), /Invalid company/);
  }
  for (const fields of [{ name: '' }, { name: 'Name\nInjected' }, { name: 'x'.repeat(121) },
    { auth0OrganizationId: 'org_' }, { auth0OrganizationId: 'not-an-org' }, { auth0OrganizationId: 'org_../escape' },
    { organizationId: 'org_Untrusted' }]) {
    assert.throws(() => createCompanies({ companies: [{ ...COMPANIES[0], ...fields }] }), /Invalid company/);
  }
  assert.throws(() => createCompanies({ companies: [COMPANIES[0], { ...COMPANIES[0], auth0OrganizationId: 'org_Other' }] }), /slugs must be unique/);
  assert.throws(() => createCompanies({ companies: [COMPANIES[0], { ...COMPANIES[0], slug: 'different' }] }), /organization IDs must be unique/);
  assert.throws(() => createCompanies({ companies: {} }), /must be an array/);
});

it('keeps the organization binding stable when an administrator renames a company slug', () => {
  const before = createCompanies({ companies: [COMPANIES[0]] });
  const after = createCompanies({ companies: [{ ...COMPANIES[0], slug: 'acme-renamed', name: 'Acme Renamed' }] });
  assert.equal(before.get('acme').organizationId, after.get('acme-renamed').organizationId);
  assert.equal(after.get('acme'), null);
});

it('atomically retains discovered organizations across restart without replacing seeded operator metadata', t => {
  const root = directory(t);
  let companies = createCompanies({ directory: root, companies: COMPANIES });
  const discovered = { slug: 'new-organization', name: 'New Organization', organizationId: 'org_New' };
  companies.remember(discovered);
  assert.deepEqual(companies.get(discovered.slug), discovered);
  companies = createCompanies({ directory: root, companies: [{ ...COMPANIES[0], name: 'Renamed' }] });
  assert.deepEqual(companies.forOrganization('org_New'), discovered);
  assert.equal(companies.forOrganization('org_Acme123').name, 'Renamed');
  const file = path.join(root, 'organizations.json'), before = fs.readFileSync(file, 'utf8');
  assert.throws(() => companies.remember({ ...discovered, organizationId: 'org_Collision' }), /already in use/);
  assert.equal(fs.readFileSync(file, 'utf8'), before);
  fs.writeFileSync(file, '{ bad registry');
  assert.throws(() => createCompanies({ directory: root, companies: [] }), /original data was preserved/);
  assert.equal(fs.readFileSync(file, 'utf8'), '{ bad registry');
});

it('can reuse an obsolete dynamic slug after an operator seeds its organization under another name', t => {
  const root = directory(t);
  createCompanies({ directory: root, companies: [] }).remember({ slug: 'old-name', name: 'Original', organizationId: 'org_First' });
  const seeded = [{ slug: 'new-name', name: 'Renamed', auth0OrganizationId: 'org_First' }];
  createCompanies({ directory: root, companies: seeded }).remember({ slug: 'old-name', name: 'Another team', organizationId: 'org_Second' });
  const restarted = createCompanies({ directory: root, companies: seeded });
  assert.equal(restarted.get('new-name').organizationId, 'org_First'); assert.equal(restarted.get('old-name').organizationId, 'org_Second');
});
