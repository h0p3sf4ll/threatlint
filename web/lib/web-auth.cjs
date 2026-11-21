'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { companyMetadata } = require('./companies.cjs');
const COOKIE_NAME = 'threatlint_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const HEX_32 = /^[0-9a-f]{64}$/;
const HUMAN_SUBJECT = /^(?:google-oauth2|apple|github|waad|ad|adfs|samlp|oidc|oauth2)\|[^\x00-\x1f\x7f]+$/;

function failure() { return Object.assign(new Error('A verified federated identity is required'), { status: 401 }); }
function validIssuer(value) {
  if (typeof value !== 'string' || value.length > 2048 || /[\s\x00-\x1f\x7f]/.test(value)) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !!url.hostname && !url.username && !url.password && !url.search && !url.hash;
  } catch { return false; }
}
function validSubject(value) {
  return typeof value === 'string' && value.length <= 1024 && HUMAN_SUBJECT.test(value) && !value.toLowerCase().endsWith('@clients');
}
function emailValue(value) {
  if (value === undefined || value === '') return '';
  if (typeof value !== 'string') throw failure();
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@\x00-\x1f\x7f]+@[^\s@\x00-\x1f\x7f]+\.[^\s@\x00-\x1f\x7f]+$/.test(email)) throw failure();
  return email;
}
function displayValue(value) {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw failure();
  return value.replace(/[\x00-\x1f\x7f]/g, ' ').trim().replace(/\s+/g, ' ').slice(0, 80);
}
function publicUser(user) {
  return { id: user.id, email: user.email, displayName: user.displayName,
    ...(user.company ? { company: { ...user.company } } : {}) };
}
function tokenHash(token) { return crypto.createHash('sha256').update(token).digest('hex'); }

function requestToken(req) {
  const cookie = req?.headers?.cookie;
  if (typeof cookie !== 'string' || cookie.length > 16384) return null;
  const values = cookie.split(';').map(part => part.trim()).filter(part => part.startsWith(`${COOKIE_NAME}=`));
  if (values.length !== 1) return null;
  const token = values[0].slice(COOKIE_NAME.length + 1);
  return TOKEN.test(token) ? token : null;
}

function cookieAttributes(secure) { return `Path=/; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`; }
function sessionCookie(result, { secure = true } = {}) {
  if (!TOKEN.test(result?.token) || !Number.isFinite(result?.expiresAt)) throw new TypeError('A valid session is required');
  return `${COOKIE_NAME}=${result.token}; ${cookieAttributes(secure)}; Expires=${new Date(result.expiresAt).toUTCString()}`;
}
function clearCookie({ secure = true } = {}) {
  return `${COOKIE_NAME}=; ${cookieAttributes(secure)}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

function validateState(value) {
  if (!value || ![2, 3].includes(value.version) || !Array.isArray(value.users) || !Array.isArray(value.sessions)) throw new Error('Invalid identity store');
  const ids = new Set(), identities = new Set(), hashes = new Set();
  for (const user of value.users) {
    const company = user?.company === undefined ? undefined : companyMetadata(user.company);
    const identity = JSON.stringify([user?.issuer, user?.subject, company?.organizationId || null]);
    if (!user || !UUID.test(user.id) || !validIssuer(user.issuer) || !validSubject(user.subject) ||
        emailValue(user.email) !== user.email || typeof user.displayName !== 'string' ||
        !user.displayName || user.displayName.length > 80 || /[\x00-\x1f\x7f]/.test(user.displayName) ||
        (value.version === 2 && company) || (company && company.name !== user.company.name) ||
        Object.keys(user).some(key => !['id', 'issuer', 'subject', 'email', 'displayName', 'company'].includes(key)) ||
        ids.has(user.id) || identities.has(identity)) throw new Error('Invalid identity store');
    ids.add(user.id); identities.add(identity);
  }
  for (const session of value.sessions) {
    if (!session || !HEX_32.test(session.tokenHash) || !ids.has(session.userId) || !Number.isSafeInteger(session.expiresAt) ||
        hashes.has(session.tokenHash)) throw new Error('Invalid identity store');
    hashes.add(session.tokenHash);
  }
  // Version 2 users and sessions remain personal; upgrading never changes a profile UUID or directory.
  return { ...value, version: 3 };
}

/**
 * One gateway owns this identity store. establish() accepts only identity metadata already verified by
 * the gateway's OIDC SDK; it does not verify a JWT and must never be exposed as a client-facing API.
 * Identities are keyed by the exact issuer, subject and organization ID, never by email or company slug.
 * The gateway validates company membership from a verified JWT before passing registry metadata here.
 * A company slug or org_id received directly from a client grants no access. Legacy accounts.json is ignored.
 */
function createAuth({ directory, sessionTtlMs = SESSION_TTL_MS, now = Date.now } = {}) {
  if (typeof directory !== 'string' || !directory) throw new TypeError('An identity storage directory is required');
  if (!Number.isSafeInteger(sessionTtlMs) || sessionTtlMs < 1000 || sessionTtlMs > 30 * 24 * 60 * 60 * 1000) throw new TypeError('Invalid session lifetime');
  const file = path.join(directory, 'identities.json');
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  let state = { version: 3, users: [], sessions: [] };
  if (fs.existsSync(file)) {
    try { state = validateState(JSON.parse(fs.readFileSync(file, 'utf8'))); }
    catch { throw new Error('The identity store could not be read; original data was preserved'); }
  }

  function persist(next) {
    const temporary = `${file}.${crypto.randomUUID()}.tmp`;
    try {
      fs.writeFileSync(temporary, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
      fs.renameSync(temporary, file);
      if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
    } catch (error) {
      try { fs.unlinkSync(temporary); } catch { /* preserve the prior store */ }
      throw error;
    }
    state = next;
  }
  function issue(user, identityExpiry, nextUsers) {
    const current = now();
    const token = crypto.randomBytes(32).toString('base64url');
    const expiresAt = Math.min(identityExpiry, current + sessionTtlMs);
    const sessions = state.sessions.filter(item => item.expiresAt > current);
    // Bound active sessions per profile. Establishing a session retires the oldest excess sessions.
    const own = sessions.filter(item => item.userId === user.id);
    const retired = new Set(own.slice(0, Math.max(0, own.length - 19)).map(item => item.tokenHash));
    persist({ version: 3, users: nextUsers, sessions: [...sessions.filter(item => !retired.has(item.tokenHash)), { tokenHash: tokenHash(token), userId: user.id, expiresAt }] });
    return { user: publicUser(user), token, expiresAt };
  }
  function establish(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input) || !validIssuer(input.issuer) ||
        !validSubject(input.subject) || !Number.isSafeInteger(input.expiresAt) || input.expiresAt <= now()) throw failure();
    let company;
    try { company = input.company === undefined ? undefined : companyMetadata(input.company); }
    catch { throw failure(); }
    const existing = state.users.find(user => user.issuer === input.issuer && user.subject === input.subject &&
      (user.company?.organizationId || null) === (company?.organizationId || null));
    const email = input.email === undefined ? (existing?.email || '') : emailValue(input.email);
    const displayName = displayValue(input.displayName) || existing?.displayName || email || 'Threatlint user';
    const user = { id: existing?.id || crypto.randomUUID(), issuer: input.issuer, subject: input.subject,
      displayName: displayName.slice(0, 80), email, ...(company ? { company } : {}) };
    const users = existing ? state.users.map(item => item.id === existing.id ? user : item) : [...state.users, user];
    return issue(user, input.expiresAt, users);
  }
  function authenticate(req) {
    const token = requestToken(req);
    if (!token) return null;
    const hash = tokenHash(token);
    const session = state.sessions.find(item => item.tokenHash === hash);
    if (!session || session.expiresAt <= now()) return null;
    const user = state.users.find(item => item.id === session.userId);
    return user ? { user: publicUser(user), tokenHash: hash, expiresAt: session.expiresAt } : null;
  }
  function logout(req) {
    const token = requestToken(req);
    if (!token) return;
    const hash = tokenHash(token);
    const sessions = state.sessions.filter(item => item.tokenHash !== hash && item.expiresAt > now());
    if (sessions.length !== state.sessions.length) persist({ ...state, sessions });
  }
  return { establish, authenticate, logout };
}

module.exports = { createAuth, sessionCookie, clearCookie, COOKIE_NAME };
