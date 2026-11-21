'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');

const derive = promisify(crypto.scrypt);
const COOKIE_NAME = 'threatlint_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const SCRYPT = Object.freeze({ N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const HEX_32 = /^[0-9a-f]{64}$/;
const HEX_64 = /^[0-9a-f]{128}$/;

function failure(message, status = 400) { return Object.assign(new Error(message), { status }); }
function emailValue(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  return email.length <= 254 && /^[^\s@\x00-\x1f\x7f]+@[^\s@\x00-\x1f\x7f]+\.[^\s@\x00-\x1f\x7f]+$/.test(email) ? email : null;
}
function validPassword(value) { return typeof value === 'string' && value.length >= 12 && value.length <= 128; }
function publicUser(user) { return { id: user.id, email: user.email, displayName: user.displayName }; }
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
  if (!value || value.version !== 1 || !Array.isArray(value.users) || !Array.isArray(value.sessions)) throw new Error('Invalid account store');
  const ids = new Set(), emails = new Set(), hashes = new Set();
  for (const user of value.users) {
    if (!user || !UUID.test(user.id) || emailValue(user.email) !== user.email || typeof user.displayName !== 'string' ||
        !user.displayName || user.displayName.length > 80 || /[\x00-\x1f\x7f]/.test(user.displayName) ||
        !HEX_32.test(user.salt) || !HEX_64.test(user.passwordHash) || ids.has(user.id) || emails.has(user.email)) throw new Error('Invalid account store');
    ids.add(user.id); emails.add(user.email);
  }
  for (const session of value.sessions) {
    if (!session || !HEX_32.test(session.tokenHash) || !ids.has(session.userId) || !Number.isSafeInteger(session.expiresAt) ||
        hashes.has(session.tokenHash)) throw new Error('Invalid account store');
    hashes.add(session.tokenHash);
  }
  return value;
}

/** One gateway owns this account store. Profile data is kept separately by the worker manager. */
function createAuth({ directory, sessionTtlMs = SESSION_TTL_MS, now = Date.now } = {}) {
  if (typeof directory !== 'string' || !directory) throw new TypeError('An account storage directory is required');
  if (!Number.isSafeInteger(sessionTtlMs) || sessionTtlMs < 1000 || sessionTtlMs > 30 * 24 * 60 * 60 * 1000) throw new TypeError('Invalid session lifetime');
  const file = path.join(directory, 'accounts.json');
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  let state = { version: 1, users: [], sessions: [] };
  if (fs.existsSync(file)) {
    try { state = validateState(JSON.parse(fs.readFileSync(file, 'utf8'))); }
    catch { throw new Error('The account store could not be read; original data was preserved'); }
  }
  const dummySalt = crypto.randomBytes(32).toString('hex');

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
  function issue(user, nextUsers = state.users) {
    const token = crypto.randomBytes(32).toString('base64url');
    const expiresAt = now() + sessionTtlMs;
    const sessions = state.sessions.filter(item => item.expiresAt > now());
    // Bound active sessions per account. A fresh login retires the oldest excess sessions.
    const own = sessions.filter(item => item.userId === user.id);
    const retired = new Set(own.slice(0, Math.max(0, own.length - 19)).map(item => item.tokenHash));
    persist({ version: 1, users: nextUsers, sessions: [...sessions.filter(item => !retired.has(item.tokenHash)), { tokenHash: tokenHash(token), userId: user.id, expiresAt }] });
    return { user: publicUser(user), token, expiresAt };
  }
  async function register(input = {}) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw failure('Enter account details');
    const email = emailValue(input.email);
    const displayName = typeof input.displayName === 'string' ? input.displayName.trim() : email?.split('@')[0];
    if (!email) throw failure('Enter a valid email address');
    if (!validPassword(input.password)) throw failure('Choose a password between 12 and 128 characters');
    if (!displayName || displayName.length > 80 || /[\x00-\x1f\x7f]/.test(displayName)) throw failure('Enter a display name between 1 and 80 characters');
    const salt = crypto.randomBytes(32).toString('hex');
    const hash = await derive(input.password, salt, 64, SCRYPT);
    // Recheck after asynchronous password derivation, so concurrent requests cannot create duplicates.
    if (state.users.some(user => user.email === email)) throw failure('An account could not be created with these details', 409);
    const user = { id: crypto.randomUUID(), email, displayName, salt, passwordHash: hash.toString('hex') };
    return issue(user, [...state.users, user]);
  }
  async function login(input = {}) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) input = {};
    const email = emailValue(input.email);
    const user = state.users.find(item => item.email === email);
    // Unknown accounts and malformed credentials still pay the password derivation cost.
    const password = validPassword(input.password) ? input.password : 'invalid credential placeholder';
    const hash = await derive(password, user?.salt || dummySalt, 64, SCRYPT);
    const expected = user ? Buffer.from(user.passwordHash, 'hex') : Buffer.alloc(64);
    if (!crypto.timingSafeEqual(hash, expected) || !user || !validPassword(input.password)) throw failure('Invalid email or password', 401);
    return issue(user);
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
  return { register, login, authenticate, logout };
}

module.exports = { createAuth, sessionCookie, clearCookie, COOKIE_NAME };
