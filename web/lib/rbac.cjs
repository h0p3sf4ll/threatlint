'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { permittedSubject } = require('./auth0-config.cjs');

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
function createAccessControl({ directory, adminSubjects = process.env.THREATLINT_ADMIN_SUBJECTS, issuer: configuredIssuer } = {}) {
  if (!path.isAbsolute(directory || '')) throw new Error('Access-control storage requires an absolute gateway directory');
  const bootstrap = bootstrapSubjects(adminSubjects), scopes = new Map(), MAX_MEMBERS = 10000;
  function identity(value) {
    let url;
    try { url = new URL(value?.issuer); } catch { throw fail('A verified issuer and federated subject are required'); }
    if (typeof value.issuer !== 'string' || value.issuer.length > 2048 || /[\s\x00-\x1f\x7f]/.test(value.issuer) ||
        url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.search || url.hash ||
        (configuredIssuer && value.issuer !== configuredIssuer) || !permittedSubject(value.subject) ||
        value.subject.toLowerCase().endsWith('@clients')) throw fail('A verified issuer and federated subject are required');
    return { issuer: value.issuer, subject: value.subject };
  }
  if (configuredIssuer !== undefined) identity({ issuer: configuredIssuer, subject: 'github|configuration-check' });
  const key = member => JSON.stringify([member.issuer, member.subject]);
  const metadata = (value, fallback, max) => (typeof value === 'string' ? value : fallback).replace(/[\x00-\x1f\x7f]/g, ' ').trim().slice(0, max);
  function companyDirectory(company) {
    if (!/^org_[A-Za-z0-9]{1,128}$/.test(company?.organizationId || '')) throw fail('A verified company is required', 401);
    return path.join(directory, 'management', 'organizations', crypto.createHash('sha256').update(company.organizationId).digest('hex'));
  }
  function scopeDirectory(user) {
    if (!UUID.test(user?.id || '')) throw fail('A verified profile is required', 401);
    return user.company ? companyDirectory(user.company) : path.join(directory, 'management', 'personal', user.id);
  }
  function loadScope(scope) {
    if (scopes.has(scope)) return scopes.get(scope);
    const file = path.join(scope, 'access.json');
    let members = [], legacyMembers = [], removed = [];
    if (fs.existsSync(file)) {
      try {
        const data = JSON.parse(fs.readFileSync(file, 'utf8'));
        if (![1, 2].includes(data.version) || !Array.isArray(data.members)) throw new Error();
        members = data.version === 2 ? data.members : [];
        legacyMembers = data.version === 1 ? data.members : data.legacyMembers || [];
        removed = data.version === 2 ? data.removed || [] : [];
        if (![members, legacyMembers, removed].every(values => Array.isArray(values) && values.length <= MAX_MEMBERS)) throw new Error();
        const ids = new Set(), identities = new Set();
        const validateMember = member => {
          if (!roleValue(member?.role) || typeof member.displayName !== 'string' || member.displayName.length > 80 ||
              typeof member.email !== 'string' || member.email.length > 254 || !['identity', 'administrator'].includes(member.source)) throw new Error();
          if (member.userId !== null && (!UUID.test(member.userId || '') || ids.has(member.userId))) throw new Error();
          if (member.userId) ids.add(member.userId);
        };
        for (const member of members) {
          identity(member); validateMember(member);
          if (identities.has(key(member))) throw new Error();
          identities.add(key(member));
        }
        for (const member of legacyMembers) { if (!UUID.test(member?.userId || '')) throw new Error(); validateMember(member); }
        for (const member of removed) {
          identity(member);
          if (identities.has(key(member)) || (member.userId !== null && (!UUID.test(member.userId || '') || ids.has(member.userId)))) throw new Error();
          identities.add(key(member)); if (member.userId) ids.add(member.userId);
        }
      } catch { throw new Error('The access-control store could not be read; original data was preserved'); }
    }
    const state = { file, members, legacyMembers, removed, active: null }; scopes.set(scope, state); return state;
  }
  const load = user => loadScope(scopeDirectory(user));
  function save(state, members, legacyMembers = state.legacyMembers, removed = state.removed) {
    if (members.length + legacyMembers.length > MAX_MEMBERS || removed.length > MAX_MEMBERS) throw fail('Company member capacity reached', 503);
    fs.mkdirSync(path.dirname(state.file), { recursive: true, mode: 0o700 });
    const temporary = `${state.file}.${crypto.randomUUID()}.tmp`;
    try {
      fs.writeFileSync(temporary, `${JSON.stringify({ version: 2, members, legacyMembers, removed }, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
      fs.renameSync(temporary, state.file);
      if (process.platform !== 'win32') fs.chmodSync(state.file, 0o600);
    } catch (error) { try { fs.unlinkSync(temporary); } catch {} throw error; }
    Object.assign(state, { members, legacyMembers, removed });
  }
  const bound = (state, value) => state.members.find(member => key(member) === key(value));
  const legacy = (state, userId) => userId ? state.legacyMembers.find(member => member.userId === userId) : undefined;
  function currentMembers(state) {
    if (!state.active) return [...state.members, ...state.legacyMembers];
    return state.active.map(value => {
      const blocked = state.removed.some(member => key(member) === key(value));
      return { ...value, role: blocked ? 'viewer' : (bound(state, value) || legacy(state, value.userId))?.role || 'analyst', ...(blocked ? { blocked: true } : {}) };
    });
  }
  function publicMember(member) {
    return { ...(member.subject ? { issuer: member.issuer, subject: member.subject } : {}), userId: member.userId || null,
      displayName: member.displayName, email: member.email, role: member.role, ...(member.blocked ? { blocked: true } : {}) };
  }
  function role(user) {
    if (!user.company) return 'administrator';
    const state = load(user);
    if (state.removed.some(member => member.userId === user.id)) throw fail('Company membership was removed', 403);
    return state.members.find(member => member.userId === user.id)?.role || legacy(state, user.id)?.role || 'analyst';
  }
  function access(user) {
    const current = role(user);
    return { role: current, permissions: PERMISSIONS[current], roles: ROLES,
      members: current === 'administrator' && user.company ? currentMembers(load(user)).map(publicMember) : [] };
  }
  function requireAdministrator(actor) {
    if (!actor?.company || !access(actor).permissions.manageMembers) throw fail('Only company administrators can manage members', 403);
    return load(actor);
  }
  function guardLastAdministrator(state, member, nextRole) {
    const active = currentMembers(state);
    const counted = member && active.some(item => member.subject ? key(item) === key(member) : item.userId === member.userId);
    if (counted && member.role === 'administrator' && nextRole !== 'administrator' && active.filter(item => item.role === 'administrator').length <= 1) {
      throw fail('Keep at least one company administrator', 409);
    }
  }
  function checkProfileBinding(state, value, userId) {
    if (userId !== null && !UUID.test(userId || '')) throw fail('Choose a valid member profile');
    const existing = bound(state, value);
    if (existing?.userId && userId && existing.userId !== userId) throw fail('This identity is already bound to another profile', 409);
    if (userId && (state.members.some(member => member.userId === userId && key(member) !== key(value)) ||
        state.removed.some(member => member.userId === userId && key(member) !== key(value)))) throw fail('This profile is already bound to another identity', 409);
  }
  function observe(user, input = {}) {
    if (!user.company) return access(user);
    const value = identity(input), state = load(user);
    if (state.removed.some(member => key(member) === key(value))) throw fail('Company membership was removed', 403);
    checkProfileBinding(state, value, user.id);
    const existing = bound(state, value) || legacy(state, user.id);
    const identityRole = bootstrap.has(value.subject) ? 'administrator' : claimedRole(input.roles) || 'analyst';
    const member = { ...value, userId: user.id, displayName: metadata(user.displayName, existing?.displayName || 'Threatlint user', 80),
      email: metadata(user.email, existing?.email || '', 254), role: existing?.source === 'administrator' ? existing.role : identityRole,
      source: existing?.source || 'identity' };
    if (!bound(state, value) || JSON.stringify(member) !== JSON.stringify(bound(state, value))) {
      save(state, [...state.members.filter(item => key(item) !== key(value)), member], state.legacyMembers.filter(item => item.userId !== user.id));
    }
    return access(user);
  }
  function assignIdentity(actor, input) {
    const state = requireAdministrator(actor), value = identity(input);
    if (Object.keys(input).some(name => !['issuer', 'subject', 'role', 'displayName', 'email', 'userId'].includes(name)) || !roleValue(input.role) ||
        (input.displayName !== undefined && (typeof input.displayName !== 'string' || input.displayName.length > 80)) ||
        (input.email !== undefined && (typeof input.email !== 'string' || input.email.length > 254))) throw fail('Choose a member and a valid role');
    const active = state.active?.find(member => key(member) === key(value));
    const existing = bound(state, value) || legacy(state, input.userId || active?.userId);
    const userId = input.userId ?? existing?.userId ?? active?.userId ?? state.removed.find(member => key(member) === key(value))?.userId ?? null;
    checkProfileBinding(state, value, userId);
    guardLastAdministrator(state, existing, input.role);
    const member = { ...value, userId, displayName: metadata(input.displayName, existing?.displayName || active?.displayName || value.subject, 80),
      email: metadata(input.email, existing?.email || active?.email || '', 254), role: input.role, source: 'administrator' };
    save(state, [...state.members.filter(item => key(item) !== key(value)), member], state.legacyMembers.filter(item => item.userId !== userId), state.removed.filter(item => key(item) !== key(value)));
    if (state.active && !active) state.active.push(publicMember(member));
    return access(actor);
  }
  function updateIdentity(actor, input) {
    const state = requireAdministrator(actor), value = identity(input);
    if (Object.keys(input).some(name => !['issuer', 'subject', 'role'].includes(name)) || !roleValue(input.role)) throw fail('Choose an existing member and a valid role');
    const member = bound(state, value) || state.active?.find(item => key(item) === key(value));
    if (!member || (state.active && !state.active.some(item => key(item) === key(value)))) throw fail('Company member not found', 404);
    return assignIdentity(actor, { ...value, role: input.role, ...(member.userId ? { userId: member.userId } : {}) });
  }
  function update(actor, input) {
    const state = requireAdministrator(actor);
    if (!input || Object.keys(input).some(name => !['userId', 'role'].includes(name)) || !UUID.test(input.userId || '') || !roleValue(input.role)) throw fail('Choose an existing member and a valid role');
    const member = state.members.find(item => item.userId === input.userId) || legacy(state, input.userId);
    if (!member || (state.active && !state.active.some(item => item.userId === input.userId))) throw fail('Company member not found', 404);
    if (member.subject) return updateIdentity(actor, { issuer: member.issuer, subject: member.subject, role: input.role });
    guardLastAdministrator(state, member, input.role);
    save(state, state.members, state.legacyMembers.map(item => item.userId === member.userId ? { ...item, role: input.role, source: 'administrator' } : item));
    return access(actor);
  }
  function grantCreator(input, company) {
    const value = identity(input), state = loadScope(companyDirectory(company)), existing = bound(state, value);
    if (state.removed.some(member => key(member) === key(value)) || (existing?.source === 'administrator' && existing.role !== 'administrator')) throw fail('The creator assignment was already changed', 409);
    if (existing?.role === 'administrator' && existing.source === 'administrator') return publicMember(existing);
    const member = { ...value, userId: existing?.userId || null, displayName: metadata(existing?.displayName, value.subject, 80), email: existing?.email || '', role: 'administrator', source: 'administrator' };
    save(state, [...state.members.filter(item => key(item) !== key(value)), member]);
    return publicMember(member);
  }
  function mergeMembers(actor, remoteMembers, { issuer, profileForIdentity } = {}) {
    const state = requireAdministrator(actor);
    if (!Array.isArray(remoteMembers) || remoteMembers.length > MAX_MEMBERS) throw fail('Company membership could not be read', 503);
    const seen = new Set(), profileIds = new Set(), next = [];
    for (const remote of remoteMembers) {
      let value;
      try { value = identity({ issuer, subject: remote?.user_id ?? remote?.subject }); } catch { throw fail('Company membership could not be read', 503); }
      if (seen.has(key(value)) || (remote.subject && remote.user_id && remote.subject !== remote.user_id)) throw fail('Company membership could not be read', 503);
      seen.add(key(value));
      const known = bound(state, value), profile = profileForIdentity?.({ ...value, organizationId: actor.company.organizationId });
      if (profile && (!UUID.test(profile.id || '') || (profile.company && profile.company.organizationId !== actor.company.organizationId))) throw fail('Company profile could not be resolved', 503);
      if (known?.userId && profile?.id && known.userId !== profile.id) throw fail('Company profile binding changed', 503);
      const userId = known?.userId || profile?.id || state.removed.find(member => key(member) === key(value))?.userId || null;
      if (userId && profileIds.has(userId)) throw fail('Company profile binding is ambiguous', 503);
      if (userId) profileIds.add(userId);
      checkProfileBinding(state, value, userId);
      const saved = known || legacy(state, userId);
      next.push({ ...value, userId, displayName: metadata(remote.name ?? remote.displayName, saved?.displayName || value.subject, 80),
        email: metadata(remote.email, saved?.email || '', 254), role: saved?.role || 'analyst' });
    }
    state.active = next;
    return access(actor);
  }
  function assertRemovable(actor, input) {
    const state = requireAdministrator(actor), value = identity(input);
    if (Object.keys(input).some(name => !['issuer', 'subject'].includes(name))) throw fail('Choose an existing member');
    const active = state.active?.find(member => key(member) === key(value));
    const member = bound(state, value) || legacy(state, active?.userId);
    if (state.active && !active) throw fail('Company member not found', 404);
    guardLastAdministrator(state, member, null);
    return { ...value, userId: member?.userId || active?.userId || state.removed.find(item => key(item) === key(value))?.userId || null };
  }
  function removeIdentity(actor, input) {
    const target = assertRemovable(actor, input), state = load(actor);
    const removed = { issuer: target.issuer, subject: target.subject, userId: target.userId };
    save(state, state.members.filter(member => key(member) !== key(target)), state.legacyMembers.filter(member => member.userId !== target.userId),
      [...state.removed.filter(member => key(member) !== key(target)), removed]);
    if (state.active) state.active = state.active.filter(member => key(member) !== key(target));
    return { removed: true };
  }
  return { scopeDirectory, role, access, observe, update, assignIdentity, updateIdentity, grantCreator, mergeMembers, assertRemovable, removeIdentity };
}

/** The gateway rejects unauthorized actions before a personal worker or shared service sees them. */
function requiredPermission(method, pathname) {
  const verb = String(method || '').toUpperCase();
  // Express routes accept mixed case and an optional trailing slash by default.
  pathname = String(pathname || '').toLowerCase().replace(/\/+$/, '');
  if (pathname.startsWith('/api/aws/')) return 'manageSettings';
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
  if (verb === 'POST' && (pathname === '/api/metrics/query' || pathname === '/api/semgrep/false-positive/matches' || pathname === '/api/trackers/servicenow-avit/items')) return 'read';
  if (pathname.startsWith('/api/management/findings')) return 'manageFindings';
  return 'review';
}

module.exports = { createAccessControl, requiredPermission, PERMISSIONS, ROLES, ROLE_CLAIM, claimedRole };
