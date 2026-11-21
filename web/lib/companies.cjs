'use strict';

const fs = require('node:fs');
const path = require('node:path');

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

/** A startup-only administrator registry. URL slugs are lookup keys and never establish membership. */
function createCompanies({ companies, file = process.env.THREATLINT_COMPANIES_FILE } = {}) {
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
  return Object.freeze({
    get: slug => typeof slug === 'string' ? bySlug.get(slug) || null : null,
    forOrganization: id => typeof id === 'string' ? byOrganization.get(id) || null : null,
    publicCompany,
    list: () => Object.freeze([...bySlug.values()].map(publicCompany)),
  });
}

module.exports = { createCompanies, companyMetadata, publicCompany, validSlug };
