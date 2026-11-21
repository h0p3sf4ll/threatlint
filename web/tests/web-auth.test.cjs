'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createAuth, sessionCookie, clearCookie } = require('../lib/web-auth.cjs');

const PASSWORD = 'correct horse battery staple';
const request = token => ({ headers: { cookie: `unrelated=1; threatlint_session=${token}` } });
function directory(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-auth-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

it('persists unique accounts with salted password hashes and hashed session tokens, restoring login across restart', async t => {
  const root = directory(t), auth = createAuth({ directory: root });
  const first = await auth.register({ email: ' Alice@Example.test ', displayName: ' Alice ', password: PASSWORD });
  const second = await auth.register({ email: 'bob@example.test', password: PASSWORD });
  assert.notEqual(first.user.id, second.user.id);
  assert.deepEqual(Object.keys(first.user).sort(), ['displayName', 'email', 'id']);
  assert.equal(first.user.email, 'alice@example.test');
  assert.equal(first.user.displayName, 'Alice');
  const filename = path.join(root, 'accounts.json'), contents = fs.readFileSync(filename, 'utf8'), saved = JSON.parse(contents);
  assert.equal(contents.includes(PASSWORD), false);
  assert.equal(contents.includes(first.token), false);
  assert.equal(contents.includes(second.token), false);
  assert.notEqual(saved.users[0].salt, saved.users[1].salt);
  assert.notEqual(saved.users[0].passwordHash, saved.users[1].passwordHash);
  if (process.platform !== 'win32') assert.equal(fs.statSync(filename).mode & 0o777, 0o600);
  const restored = createAuth({ directory: root });
  assert.deepEqual(restored.authenticate(request(first.token)).user, first.user);
  const login = await restored.login({ email: 'ALICE@example.test', password: PASSWORD });
  assert.deepEqual(login.user, first.user);
  assert.notEqual(login.token, first.token);
});

it('rejects concurrent duplicate registrations while preserving distinct users', async t => {
  const auth = createAuth({ directory: directory(t) });
  const results = await Promise.allSettled(Array.from({ length: 3 }, () => auth.register({ email: 'same@example.test', password: PASSWORD })));
  assert.equal(results.filter(item => item.status === 'fulfilled').length, 1);
  assert.equal(results.filter(item => item.status === 'rejected' && item.reason.status === 409).length, 2);
  assert.equal((await auth.login({ email: 'same@example.test', password: PASSWORD })).user.email, 'same@example.test');
});

it('rejects invalid credentials identically and never accepts forged or ambiguous cookies', async t => {
  const auth = createAuth({ directory: directory(t) });
  const account = await auth.register({ email: 'alice@example.test', password: PASSWORD });
  for (const credentials of [{ email: 'alice@example.test', password: 'wrong password' }, { email: 'nobody@example.test', password: PASSWORD }, { email: 'alice@example.test', password: {} }, {}, null]) {
    await assert.rejects(auth.login(credentials), error => error.status === 401 && error.message === 'Invalid email or password');
  }
  for (const req of [{}, request('a'.repeat(43)), request('../accounts.json'), { headers: { cookie: `threatlint_session=${account.token}; threatlint_session=${account.token}` } }]) assert.equal(auth.authenticate(req), null);
});

it('enforces expiry after restart and durably revokes only the logged-out session', async t => {
  const root = directory(t); let current = 1700000000000;
  const options = { directory: root, sessionTtlMs: 1000, now: () => current }, auth = createAuth(options);
  const first = await auth.register({ email: 'alice@example.test', password: PASSWORD });
  const second = await auth.login({ email: 'alice@example.test', password: PASSWORD });
  auth.logout(request(first.token));
  const restored = createAuth(options);
  assert.equal(restored.authenticate(request(first.token)), null);
  assert.ok(restored.authenticate(request(second.token)));
  current += 1000;
  assert.equal(restored.authenticate(request(second.token)), null);
  assert.equal(createAuth(options).authenticate(request(second.token)), null);
});

it('validates profile inputs without storing invalid accounts', async t => {
  const root = directory(t), auth = createAuth({ directory: root });
  for (const fields of [{ email: 'bad' }, { email: 'a@example.test', password: 'short' }, { email: 'a@example.test', password: 'a'.repeat(129) }, { email: 'a@example.test', displayName: 'mid\nline' }, { email: 'a@example.test', displayName: 'a'.repeat(81) }]) {
    await assert.rejects(auth.register({ password: PASSWORD, ...fields }), error => error.status === 400);
  }
  assert.equal(fs.existsSync(path.join(root, 'accounts.json')), false);
});

it('fails closed on corrupt persistent account data without overwriting evidence', t => {
  const root = directory(t), file = path.join(root, 'accounts.json');
  fs.writeFileSync(file, '{ broken private contents');
  assert.throws(() => createAuth({ directory: root }), /original data was preserved/);
  assert.equal(fs.readFileSync(file, 'utf8'), '{ broken private contents');
});

it('sets HTTP-only same-site cookies, secure by default, and expires the cookie on logout', () => {
  const value = { token: 'a'.repeat(43), expiresAt: 1700000000000 };
  assert.match(sessionCookie(value), /Path=\/; HttpOnly; SameSite=Lax; Secure; Expires=/);
  assert.doesNotMatch(sessionCookie(value, { secure: false }), /Secure/);
  assert.match(clearCookie(), /HttpOnly; SameSite=Lax; Secure; Max-Age=0/);
  assert.throws(() => sessionCookie({ token: '\r\ninjected=1' }), /valid session/);
});
