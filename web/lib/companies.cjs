'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const RESERVED = new Set(['auth', 'api', 'login', 'admin', 'vendor', 'www', 'app', 'personal']);
const SLUG = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;
const ORGANIZATION_ID = /^org_[A-Za-z0-9]{1,128}$/;

function validSlug(value) { return typeof value === 'string' && SLUG.test(value) && !RESERVED.has(value); }
function record(value) { return !!value && typeof value === 'object' && !Array.isArray(value); }
function companyMetadata(value) {
  if (!record(value) || Object.keys(value).some(key => !['slug', 'name', 'organizationId'].includes(key)) ||
      !validSlug(value.slug) || typeof value.name !== 'string' || !value.name.trim() || value.name.length > 120 ||
      /[\x00-\x1f\x7f]/.test(value.name) || typeof value.organizationId !== 'string' || !ORGANIZATION_ID.test(value.organizationId)) {
    throw new Error('Invalid company configuration');
  }
  return Object.freeze({ slug: value.slug, name: value.name.trim(), organizationId: value.organizationId });
}

function publicCompany(company) {
  if (!company) return null;
  const value = companyMetadata(company);
  return Object.freeze({ slug: value.slug, name: value.name });
}

/** Operator seeds plus verified discovered organizations. URL slugs never establish membership. */
function createCompanies({ companies, file = process.env.THREATLINT_COMPANIES_FILE, directory } = {}) {
  if (directory !== undefined && !path.isAbsolute(directory)) throw new Error('Persistent organization storage requires an absolute directory');
  let records = companies;
  if (records === undefined && file !== undefined && file !== '') {
    if (typeof file !== 'string' || !path.isAbsolute(file)) throw new Error('THREATLINT_COMPANIES_FILE must be an absolute file path');
    try {
      const stat = fs.statSync(file);
      if (!stat.isFile() || stat.size > 1024 * 1024) throw new Error('Invalid registry file');
      records = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch { throw new Error('The company registry could not be read; check the configured file'); }
  }
  if (records === undefined) records = [];
  if (!Array.isArray(records) || records.length > 1000) throw new Error('The company registry must be an array of at most 1000 companies');
  const bySlug = new Map(), byOrganization = new Map();
  for (const value of records) {
    if (!record(value) || Object.keys(value).some(key => !['slug', 'name', 'auth0OrganizationId'].includes(key))) throw new Error('Invalid company configuration');
    const company = companyMetadata({ slug: value.slug, name: value.name, organizationId: value.auth0OrganizationId });
    if (bySlug.has(company.slug)) throw new Error('Company slugs must be unique');
    if (byOrganization.has(company.organizationId)) throw new Error('Auth0 organization IDs must be unique');
    bySlug.set(company.slug, company); byOrganization.set(company.organizationId, company);
  }
  const seeded = new Set(byOrganization.keys());
  const dynamicFile = directory ? path.join(directory, 'organizations.json') : null;
  let dynamic = [];
  if (dynamicFile && fs.existsSync(dynamicFile)) {
    try {
      const stat = fs.statSync(dynamicFile);
      if (!stat.isFile() || stat.size > 2 * 1024 * 1024) throw new Error();
      const data = JSON.parse(fs.readFileSync(dynamicFile, 'utf8'));
      if (data.version !== 1 || !Array.isArray(data.companies) || data.companies.length > 1000) throw new Error();
      const ids = new Set(), slugs = new Set();
      for (const value of data.companies) {
        const company = companyMetadata(value);
        if (ids.has(company.organizationId) || slugs.has(company.slug)) throw new Error();
        ids.add(company.organizationId); slugs.add(company.slug);
        // Explicit operator configuration remains canonical for existing organizations.
        if (!seeded.has(company.organizationId)) {
          if (bySlug.has(company.slug)) throw new Error();
          bySlug.set(company.slug, company); byOrganization.set(company.organizationId, company);
        }
        if (!seeded.has(company.organizationId)) dynamic.push(company);
      }
    } catch { throw new Error('The organization registry could not be read; original data was preserved'); }
  }
  function remember(value) {
    const company = companyMetadata(value), existing = byOrganization.get(company.organizationId);
    if (existing) return existing;
    if (!dynamicFile) throw new Error('Persistent organization storage is required');
    if (bySlug.has(company.slug) || byOrganization.size >= 1000) throw new Error('The organization registry is full or the workspace name is already in use');
    const next = [...dynamic, company], temporary = `${dynamicFile}.${crypto.randomUUID()}.tmp`;
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    try {
      fs.writeFileSync(temporary, `${JSON.stringify({ version: 1, companies: next }, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
      fs.renameSync(temporary, dynamicFile);
      if (process.platform !== 'win32') fs.chmodSync(dynamicFile, 0o600);
    } catch (error) { try { fs.unlinkSync(temporary); } catch {} throw error; }
    dynamic = next; bySlug.set(company.slug, company); byOrganization.set(company.organizationId, company);
    return company;
  }
  return Object.freeze({
    get: slug => typeof slug === 'string' ? bySlug.get(slug) || null : null,
    forOrganization: id => typeof id === 'string' ? byOrganization.get(id) || null : null,
    publicCompany,
    remember,
    list: () => Object.freeze([...bySlug.values()].map(publicCompany)),
  });
}

module.exports = { createCompanies, companyMetadata, publicCompany, validSlug };
