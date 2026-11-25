'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { companyMetadata, validSlug } = require('./companies.cjs');
const { unavailable } = require('./auth0-management.cjs');
const { permittedSubject } = require('./auth0-config.cjs');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function fail(message, status = 400) { return Object.assign(new Error(message), { status, ...(status === 503 ? { code: 'organization_operation_unavailable' } : {}) }); }
function digest(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function createOrganizationService({ directory, issuer, companies, management, grantCreator } = {}) {
  const file = path.join(directory, 'organization-operations.json');
  let operations = [], tail = Promise.resolve(), closed = false, pendingOperations = 0;
  if (fs.existsSync(file)) {
    try {
      const stat = fs.statSync(file);
      if (!stat.isFile() || stat.size > 32 * 1024 * 1024) throw new Error();
      const data = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (data.version !== 1 || !Array.isArray(data.operations) || data.operations.length > 10000) throw new Error();
      const keys = new Set();
      for (const operation of data.operations) {
        if (!operation || !/^[a-f0-9]{64}$/.test(operation.key) || operation.issuer !== issuer || !permittedSubject(operation.subject) ||
            typeof operation.name !== 'string' || !operation.name.trim() || operation.name.length > 120 || /[\x00-\x1f\x7f]/.test(operation.name) ||
            !validSlug(operation.slug) || operation.slug.length > 50 || typeof operation.complete !== 'boolean' ||
            (operation.organizationId !== undefined && !/^org_[A-Za-z0-9]{1,128}$/.test(operation.organizationId)) ||
            (operation.complete && !operation.organizationId) || Object.keys(operation).some(key => !['key', 'issuer', 'subject', 'name', 'slug', 'complete', 'organizationId'].includes(key)) || keys.has(operation.key)) throw new Error();
        keys.add(operation.key);
      }
      operations = data.operations;
    } catch { throw new Error('The organization operation store could not be read; original data was preserved'); }
  }
  function save(next) {
    if (closed) throw unavailable();
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const temporary = `${file}.${crypto.randomUUID()}.tmp`;
    try { fs.writeFileSync(temporary, `${JSON.stringify({ version: 1, operations: next }, null, 2)}\n`, { flag: 'wx', mode: 0o600 }); fs.renameSync(temporary, file); if (process.platform !== 'win32') fs.chmodSync(file, 0o600); }
    catch (error) { try { fs.unlinkSync(temporary); } catch {} throw error; }
    operations = next;
  }
  function requireIdentity(identity) { if (identity?.issuer !== issuer || !permittedSubject(identity?.subject)) throw fail('Sign in to continue', 401); }
  function requireManagement() { if (!management || closed) throw unavailable(); }
  function metadata(value) {
    requireManagement();
    if (!value || typeof value.id !== 'string' || !/^org_[A-Za-z0-9]{1,128}$/.test(value.id)) throw unavailable();
    const known = companies.forOrganization(value.id);
    if (known) return known;
    const name = typeof value.display_name === 'string' ? value.display_name : value.name;
    let slug = value.name;
    if (!validSlug(slug)) slug = `organization-${digest(value.id).slice(0, 16)}`;
    if (companies.get(slug)) slug = `${slug.slice(0, 40).replace(/-+$/, '')}-${digest(value.id).slice(0, 12)}`;
    try { return companies.remember(companyMetadata({ slug, name, organizationId: value.id })); }
    catch { throw unavailable(); }
  }
  async function memberships(identity) {
    requireIdentity(identity); requireManagement();
    const values = await management.listUserOrganizations(identity.subject);
    requireManagement();
    if (!Array.isArray(values) || values.length > 1000) throw unavailable();
    const seen = new Set(), result = [];
    for (const value of values) {
      if (seen.has(value?.id)) throw unavailable();
      seen.add(value?.id);
      if (operations.some(operation => operation.organizationId === value?.id && !operation.complete)) continue;
      result.push(metadata(value));
    }
    return result;
  }
  async function member(identity, organizationId) {
    return (await memberships(identity)).some(company => company.organizationId === organizationId);
  }
  function serialize(operation) {
    if (pendingOperations >= 16) return Promise.reject(Object.assign(fail('Organization management is busy. Try again shortly.', 503), { retryAfter: 30 }));
    pendingOperations++;
    const result = tail.then(() => { requireManagement(); return operation(); }).finally(() => { pendingOperations--; });
    tail = result.catch(() => {}); return result;
  }
  function create(identity, input) {
    return serialize(async () => {
      requireIdentity(identity); requireManagement();
      if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key => !['name', 'idempotencyKey'].includes(key)) ||
          typeof input.name !== 'string' || !input.name.trim() || input.name.length > 120 || /[\x00-\x1f\x7f]/.test(input.name) || !UUID.test(input.idempotencyKey || '')) throw fail('Enter an organization name and a valid creation request ID');
      if (!management.connections.length) throw fail('Organization creation requires an administrator-configured sign-in connection', 503);
      const name = input.name.trim(), key = digest(JSON.stringify([issuer, identity.subject, input.idempotencyKey]));
      let operation = operations.find(item => item.key === key);
      if (operation && operation.name !== name) throw fail('This creation request already belongs to another organization name', 409);
      if (operation?.complete) {
        if (!await member(identity, operation.organizationId)) throw fail('You are no longer a member of this organization', 403);
        return companies.forOrganization(operation.organizationId);
      }
      if (!operation) {
        if (operations.length >= 10000) throw fail('Organization creation capacity reached', 503);
        if (companies.list().length >= 1000) throw fail('Organization workspace capacity reached', 503);
        if (operations.some(item => item.issuer === issuer && item.subject === identity.subject && !item.complete)) throw fail('An earlier organization creation is unfinished. Retry the original request.', 409);
        if ((await memberships(identity)).length) throw fail('You already belong to an organization. Choose it to continue.', 409);
        const prefix = name.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 30).replace(/-+$/, '') || 'organization';
        operation = { key, issuer, subject: identity.subject, name, slug: `${prefix}-${key.slice(0, 16)}`, complete: false };
        save([...operations, operation]);
      }
      const update = fields => { operation = { ...operation, ...fields }; save(operations.map(item => item.key === key ? operation : item)); };
      // Resolve the deterministic name before any create: a lost HTTP response must not create a second organization.
      let remote = await management.getOrganizationByName(operation.slug);
      requireManagement();
      // Only common connection fields apply to all approved strategies. Auth0 rejects the
      // database-only signup field on social connections; its omitted default remains false.
      if (!remote) remote = await management.createOrganization({ name: operation.slug, display_name: operation.name,
        metadata: { threatlint_creation: key }, enabled_connections: management.connections.map(connection_id => ({ connection_id, assign_membership_on_login: false })) });
      requireManagement();
      if (!remote) remote = await management.getOrganizationByName(operation.slug);
      requireManagement();
      if (!remote || remote.name !== operation.slug || remote.metadata?.threatlint_creation !== key || !/^org_[A-Za-z0-9]{1,128}$/.test(remote.id || '') || (operation.organizationId && operation.organizationId !== remote.id)) throw fail('Organization creation could not be safely resumed. Ask the administrator to inspect this request.', 503);
      if (!operation.organizationId) update({ organizationId: remote.id });
      const connections = await management.listConnections(remote.id);
      requireManagement();
      for (const connection of connections) if (!management.connections.includes(connection.connection_id) || connection.assign_membership_on_login !== false || connection.is_signup_enabled === true) throw fail('The organization requires approved invitation-only sign-in connections', 503);
      for (const connection of management.connections) if (!connections.some(value => value.connection_id === connection)) { await management.enableConnection(remote.id, connection); requireManagement(); }
      // Both steps are idempotent; an interrupted creation never appears as a completed selectable workspace.
      await management.addMember(remote.id, identity.subject);
      requireManagement();
      // Auth0 membership indexes are eventually consistent. Keep this request resumable until
      // discovery can verify the explicit add, rather than completing an unusable workspace.
      if (!(await management.listUserOrganizations(identity.subject)).some(value => value.id === remote.id)) throw fail('Organization membership is still updating. Retry this creation request shortly.', 503);
      const company = companyMetadata({ slug: operation.slug, name: operation.name, organizationId: remote.id });
      requireManagement();
      await grantCreator(identity, company);
      requireManagement();
      companies.remember(company);
      if (!operation.complete) update({ complete: true });
      return company;
    });
  }
  return Object.freeze({ available: !!management, canCreate: !!management?.connections.length, memberships, member, create,
    serialize, management, close() { closed = true; return tail; } });
}
module.exports = { createOrganizationService };
