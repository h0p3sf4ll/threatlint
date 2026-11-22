'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROLES = Object.freeze(['administrator', 'analyst', 'viewer']);
const ROLE_CLAIM = 'https://threatlint.dev/roles';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PERMISSIONS = Object.freeze({
  administrator: Object.freeze({ read: true, review: true, manageFindings: true, manageSettings: true, manageMembers: true }),
  analyst: Object.freeze({ read: true, review: true, manageFindings: true, manageSettings: false, manageMembers: false }),
  viewer: Object.freeze({ read: true, review: false, manageFindings: false, manageSettings: false, manageMembers: false }),
});
function fail(message, status = 400) { return Object.assign(new Error(message), { status }); }
function roleValue(value) { return typeof value === 'string' && ROLES.includes(value); }
function bootstrapSubjects(value) {
  if (value === undefined || value === '') return new Set();
  const values = Array.isArray(value) ? value : String(value).split(',').map(item => item.trim());
  if (values.length > 1000 || values.some(item => typeof item !== 'string' || !item || item.length > 1024 || /[\x00-\x1f\x7f]/.test(item))) {
    throw new Error('THREATLINT_ADMIN_SUBJECTS must contain comma-separated verified Auth0 subjects');
  }
  return new Set(values);
}
function claimedRole(roles) {
  if (!Array.isArray(roles) || roles.length > 20 || roles.some(role => typeof role !== 'string')) return null;
  return ROLES.find(role => roles.includes(role)) || null;
}

/** One gateway owns these files. Company scopes come only from verified organization membership. */
function createAccessControl({ directory, adminSubjects = process.env.THREATLINT_ADMIN_SUBJECTS } = {}) {
  if (!path.isAbsolute(directory || '')) throw new Error('Access-control storage requires an absolute gateway directory');
  const bootstrap = bootstrapSubjects(adminSubjects), scopes = new Map();
  function scopeDirectory(user) {
    if (!UUID.test(user?.id || '')) throw fail('A verified profile is required', 401);
    if (!user.company) return path.join(directory, 'management', 'personal', user.id);
    const organization = user.company.organizationId;
    if (!/^org_[A-Za-z0-9]{1,128}$/.test(organization || '')) throw fail('A verified company is required', 401);
    return path.join(directory, 'management', 'organizations', crypto.createHash('sha256').update(organization).digest('hex'));
  }
  function load(user) {
    const scope = scopeDirectory(user);
    if (scopes.has(scope)) return scopes.get(scope);
    const file = path.join(scope, 'access.json');
    let members = [];
    if (fs.existsSync(file)) {
      try {
        const data = JSON.parse(fs.readFileSync(file, 'utf8'));
        if (data.version !== 1 || !Array.isArray(data.members) || data.members.length > 10000) throw new Error();
        const ids = new Set();
        for (const member of data.members) {
          if (!UUID.test(member?.userId || '') || !roleValue(member.role) || typeof member.displayName !== 'string' || member.displayName.length > 80 ||
              typeof member.email !== 'string' || member.email.length > 254 || !['identity', 'administrator'].includes(member.source) || ids.has(member.userId)) throw new Error();
          ids.add(member.userId);
        }
        members = data.members;
      } catch { throw new Error('The access-control store could not be read; original data was preserved'); }
    }
    const state = { file, members }; scopes.set(scope, state); return state;
  }
  function save(state, members) {
    fs.mkdirSync(path.dirname(state.file), { recursive: true, mode: 0o700 });
    const temporary = `${state.file}.${crypto.randomUUID()}.tmp`;
    try {
      fs.writeFileSync(temporary, `${JSON.stringify({ version: 1, members }, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
      fs.renameSync(temporary, state.file);
      if (process.platform !== 'win32') fs.chmodSync(state.file, 0o600);
    } catch (error) { try { fs.unlinkSync(temporary); } catch {} throw error; }
    state.members = members;
  }
  function role(user) {
    if (!user.company) return 'administrator';
    return load(user).members.find(member => member.userId === user.id)?.role || 'analyst';
  }
  function access(user) {
    const current = role(user);
    return { role: current, permissions: PERMISSIONS[current], roles: ROLES,
      members: current === 'administrator' && user.company ? load(user).members.map(member => ({ userId: member.userId, displayName: member.displayName, email: member.email, role: member.role })) : [] };
  }
  function observe(user, { subject, roles } = {}) {
    if (!user.company) return access(user);
    const state = load(user), existing = state.members.find(member => member.userId === user.id);
    const identityRole = bootstrap.has(subject) ? 'administrator' : claimedRole(roles) || 'analyst';
    // Explicit administrator assignments survive login. Identity claims are accepted only after JWT verification.
    const nextRole = existing?.source === 'administrator' ? existing.role : identityRole;
    const member = { userId: user.id, displayName: user.displayName, email: user.email, role: nextRole, source: existing?.source || 'identity' };
    if (!existing || JSON.stringify(member) !== JSON.stringify(existing)) {
      if (!existing && state.members.length >= 10000) throw fail('Company member capacity reached', 503);
      save(state, existing ? state.members.map(item => item.userId === user.id ? member : item) : [...state.members, member]);
    }
    return access(user);
  }
  function update(actor, input) {
    if (!access(actor).permissions.manageMembers || !actor.company) throw fail('Only company administrators can assign roles', 403);
    if (!input || Object.keys(input).some(key => !['userId', 'role'].includes(key)) || !UUID.test(input.userId || '') || !roleValue(input.role)) throw fail('Choose an existing member and a valid role');
    const state = load(actor), member = state.members.find(item => item.userId === input.userId);
    if (!member) throw fail('Company member not found', 404);
    if (member.role === 'administrator' && input.role !== 'administrator' && state.members.filter(item => item.role === 'administrator').length <= 1) throw fail('Keep at least one company administrator', 409);
    save(state, state.members.map(item => item.userId === member.userId ? { ...item, role: input.role, source: 'administrator' } : item));
    return access(actor);
  }
  return { scopeDirectory, role, access, observe, update };
}

/** The gateway rejects unauthorized actions before a personal worker or shared service sees them. */
function requiredPermission(method, pathname) {
  const verb = String(method || '').toUpperCase();
  // Express routes accept mixed case and an optional trailing slash by default.
  pathname = String(pathname || '').toLowerCase().replace(/\/+$/, '');
  if (['GET', 'HEAD', 'OPTIONS'].includes(verb)) return 'read';
  // Every member can choose their own display mode; this cannot change review or company settings.
  if (verb === 'PUT' && pathname === '/api/ui-preferences') return 'read';
  if (pathname.startsWith('/api/access/')) return 'manageMembers';
  if (/^\/api\/management\/connections(?:\/[^/]+)?(?:\/test)?\/?$/.test(pathname) ||
      /^\/api\/(?:servicenow|semgrep|github|ado)(?:\/settings(?:\/|$)|\/service-account(?:\/|$)|\/parameter-store(?:\/|$))/.test(pathname) ||
      /^\/api\/issue-trackers\/[^/]+\/settings(?:\/|$)/.test(pathname) ||
      /^\/api\/scanners\/[^/]+\/settings(?:\/|$)/.test(pathname)) return 'manageSettings';
  // Each analyst owns a separate model profile and in-memory source sessions. These actions
  // never change organization connection settings or another member's runtime.
  if (pathname === '/api/model-preferences' || /^\/api\/scm\/connections(?:\/|$)/.test(pathname)) return 'review';
  // POST is also used for these read-only queries. They never configure credentials or write findings.
  if (verb === 'POST' && (pathname === '/api/metrics/query' || pathname === '/api/semgrep/false-positive/matches')) return 'read';
  if (pathname.startsWith('/api/management/findings')) return 'manageFindings';
  return 'review';
}

module.exports = { createAccessControl, requiredPermission, PERMISSIONS, ROLES, ROLE_CLAIM, claimedRole };
