'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createAuth, sessionCookie, clearCookie } = require('../lib/web-auth.cjs');

const ISSUER = 'https://tenant.example.auth0.com/';
const request = token => ({ headers: { cookie: `unrelated=1; threatlint_session=${token}` } });
function directory(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-auth-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
function identity(fields = {}) {
  return { issuer: ISSUER, subject: 'google-oauth2|user-123', email: 'Alice@Example.test', displayName: ' Alice ',
    expiresAt: Date.now() + 3600000, ...fields };
}

it('restores a stable issuer/subject profile without persisting provider or session tokens', t => {
  const root = directory(t), auth = createAuth({ directory: root });
  assert.deepEqual(Object.keys(auth).sort(), ['authenticate', 'establish', 'logout']);
  const first = auth.establish(identity({ accessToken: 'unpersisted-oidc-access-token', idToken: 'unpersisted-oidc-id-token' }));
  assert.deepEqual(Object.keys(first.user).sort(), ['displayName', 'email', 'id']);
  assert.equal(first.user.email, 'alice@example.test'); assert.equal(first.user.displayName, 'Alice');
  const profile = path.join(root, 'profiles', first.user.id);
  fs.mkdirSync(profile, { recursive: true }); fs.writeFileSync(path.join(profile, 'settings.json'), '{"provider":"fixture"}');
  const filename = path.join(root, 'identities.json'), contents = fs.readFileSync(filename, 'utf8'), saved = JSON.parse(contents);
  assert.equal(saved.version, 2);
  assert.equal(saved.users[0].issuer, ISSUER); assert.equal(saved.users[0].subject, 'google-oauth2|user-123');
  assert.equal(contents.includes(first.token), false);
  assert.doesNotMatch(contents, /unpersisted-oidc|password|salt|accessToken|idToken|refreshToken/);
  assert.deepEqual(Object.keys(saved.users[0]).sort(), ['displayName', 'email', 'id', 'issuer', 'subject']);
  if (process.platform !== 'win32') assert.equal(fs.statSync(filename).mode & 0o777, 0o600);
  const restored = createAuth({ directory: root });
  assert.deepEqual(restored.authenticate(request(first.token)).user, first.user);
  const next = restored.establish(identity({ email: 'renamed@example.test', displayName: 'New Name' }));
  assert.equal(next.user.id, first.user.id); assert.notEqual(next.token, first.token);
  assert.equal(fs.readFileSync(path.join(root, 'profiles', next.user.id, 'settings.json'), 'utf8'), '{"provider":"fixture"}');
  assert.equal(JSON.parse(fs.readFileSync(filename, 'utf8')).users.length, 1);
});

it('never links profiles by matching email and keeps subjects case-sensitive and issuers exact', t => {
  const auth = createAuth({ directory: directory(t) });
  const profiles = [auth.establish(identity()), auth.establish(identity({ subject: 'github|user-123' })),
    auth.establish(identity({ subject: 'apple|user-123' })), auth.establish(identity({ subject: 'google-oauth2|User-123' })),
    auth.establish(identity({ issuer: 'https://other.example.auth0.com/' }))];
  assert.equal(new Set(profiles.map(item => item.user.id)).size, profiles.length);
  assert.equal(new Set(profiles.map(item => item.user.email)).size, 1);
  assert.equal(auth.establish(identity()).user.id, profiles[0].user.id);
  assert.equal(auth.establish(identity({ subject: 'github|user-123', email: 'changed@example.test' })).user.id, profiles[1].user.id);
});

it('accepts supported human identities and rejects database, passwordless and machine subjects', t => {
  const root = directory(t), auth = createAuth({ directory: root });
  for (const strategy of ['google-oauth2', 'apple', 'github', 'waad', 'ad', 'adfs', 'samlp', 'oidc', 'oauth2']) {
    const profile = auth.establish(identity({ subject: `${strategy}|fixture`, email: undefined, displayName: undefined }));
    assert.equal(profile.user.email, ''); assert.equal(profile.user.displayName, 'Threatlint user');
  }
  const before = fs.readFileSync(path.join(root, 'identities.json'), 'utf8');
  for (const subject of ['auth0|local', 'email|passwordless', 'sms|123', 'anonymous|123', 'M2M|123', 'client-credentials|123',
    'machine@clients', 'oauth2|machine@clients', 'github|', 'github|user\nforged', 'github|' + 'a'.repeat(1024)]) {
    assert.throws(() => auth.establish(identity({ subject })), error => error.status === 401, subject);
  }
  assert.equal(fs.readFileSync(path.join(root, 'identities.json'), 'utf8'), before);
});

it('bounds display metadata and rejects malformed or expired verified identity metadata', t => {
  const auth = createAuth({ directory: directory(t) });
  const profile = auth.establish(identity({ displayName: `  Alice\n\t${'x'.repeat(90)} ` }));
  assert.equal(profile.user.displayName.length, 80); assert.doesNotMatch(profile.user.displayName, /[\x00-\x1f\x7f]/);
  assert.equal(auth.establish(identity({ displayName: undefined, email: undefined })).user.displayName, profile.user.displayName);
  for (const fields of [{ issuer: 'http://tenant.example/' }, { issuer: 'https://name:secret@tenant.example/' },
    { issuer: 'https://tenant.example/?secret=1' }, { issuer: ' https://tenant.example/' }, { email: 'invalid' },
    { email: 'a'.repeat(255) + '@example.test' }, { email: {} }, { displayName: {} }, { expiresAt: 0 },
    { expiresAt: Date.now() - 1 }, { expiresAt: Infinity }, { expiresAt: '1234567890' }]) {
    assert.throws(() => auth.establish(identity(fields)), error => error.status === 401);
  }
});

it('bounds session expiry by verified identity expiry and local TTL and persists expiry/logout', t => {
  const root = directory(t); let current = 1700000000000;
  const options = { directory: root, sessionTtlMs: 2000, now: () => current }, auth = createAuth(options);
  const first = auth.establish(identity({ expiresAt: current + 5000 })), second = auth.establish(identity({ expiresAt: current + 1000 }));
  assert.equal(first.expiresAt, current + 2000); assert.equal(second.expiresAt, current + 1000);
  auth.logout(request(first.token));
  const restored = createAuth(options);
  assert.equal(restored.authenticate(request(first.token)), null); assert.ok(restored.authenticate(request(second.token)));
  current += 1000;
  assert.equal(restored.authenticate(request(second.token)), null);
  assert.equal(createAuth(options).authenticate(request(second.token)), null);
});

it('limits active sessions per profile and rejects forged or ambiguous cookies', t => {
  const auth = createAuth({ directory: directory(t) });
  const sessions = Array.from({ length: 21 }, () => auth.establish(identity()));
  assert.equal(auth.authenticate(request(sessions[0].token)), null);
  assert.ok(auth.authenticate(request(sessions[1].token)));
  for (const req of [{}, request('a'.repeat(43)), request('../identities.json'), { headers: { cookie: `threatlint_session=${sessions[20].token}; threatlint_session=${sessions[20].token}` } }]) assert.equal(auth.authenticate(req), null);
});

it('ignores legacy local accounts/cookies without touching their profiles or linking a matching email', t => {
  const root = directory(t), legacyId = '00000000-0000-4000-8000-000000000001', oldToken = 'a'.repeat(43);
  const legacy = JSON.stringify({ version: 1, users: [{ id: legacyId, email: 'alice@example.test', passwordHash: 'legacy-value' }], sessions: [{ token: oldToken, userId: legacyId }] });
  fs.writeFileSync(path.join(root, 'accounts.json'), legacy);
  const oldProfile = path.join(root, 'profiles', legacyId); fs.mkdirSync(oldProfile, { recursive: true });
  fs.writeFileSync(path.join(oldProfile, 'settings.json'), 'untouched local settings');
  const auth = createAuth({ directory: root });
  assert.equal(auth.authenticate(request(oldToken)), null);
  assert.equal(Object.hasOwn(auth, 'register'), false); assert.equal(Object.hasOwn(auth, 'login'), false);
  const federated = auth.establish(identity());
  assert.notEqual(federated.user.id, legacyId);
  assert.equal(fs.readFileSync(path.join(root, 'accounts.json'), 'utf8'), legacy);
  assert.equal(fs.readFileSync(path.join(oldProfile, 'settings.json'), 'utf8'), 'untouched local settings');
});

it('fails closed on corrupt federated state and sets secure HTTP-only cookies', t => {
  const root = directory(t), file = path.join(root, 'identities.json');
  fs.writeFileSync(file, '{ broken private contents');
  assert.throws(() => createAuth({ directory: root }), /original data was preserved/);
  assert.equal(fs.readFileSync(file, 'utf8'), '{ broken private contents');
  const value = { token: 'a'.repeat(43), expiresAt: 1700000000000 };
  assert.match(sessionCookie(value), /Path=\/; HttpOnly; SameSite=Lax; Secure; Expires=/);
  assert.doesNotMatch(sessionCookie(value, { secure: false }), /Secure/);
  assert.match(clearCookie(), /HttpOnly; SameSite=Lax; Secure; Max-Age=0/);
  assert.throws(() => sessionCookie({ token: '\r\ninjected=1' }), /valid session/);
});
