'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createWorkspaces } = require('../lib/workspaces.cjs');
const { createStore } = require('../lib/store.cjs');

test('local workspaces normalize folders, reuse existing sessions and reject missing/file targets', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-workspaces-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const workspaces = createWorkspaces({ store: createStore(root) });
  const first = workspaces.open({ repoPath: root });
  assert.deepEqual(workspaces.open({ repoPath: path.join(root, '.') }), first);
  assert.equal(workspaces.get(first.sessionId).repoPath, fs.realpathSync(root));
  assert.equal(workspaces.list().length, 1);
  assert.throws(() => workspaces.open({ repoPath: path.join(root, 'missing') }), /does not exist/);
  assert.throws(() => workspaces.open({ repoPath: path.join(root, 'sessions.json') }), /not a file/);
});

test('HTTPS clone reuses safe git flags, suppresses interactive credentials and preserves managed checkout metadata', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-workspace-clone-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const store = createStore(root), calls = [];
  const workspaces = createWorkspaces({ store, integrations: {
    createRepositoryDirectory: () => fs.mkdtempSync(path.join(root, 'checkout-')),
    execFile: async (...args) => { calls.push(args); fs.mkdirSync(args[1].at(-1)); },
  } });
  const result = await workspaces.clone({ url: 'https://example.test/org/repo.git', branch: 'feature/security' });
  assert.deepEqual(calls[0][1].slice(0, 7), ['-c', 'core.hooksPath=', 'clone', '--depth=20', '--branch', 'feature/security', '--']);
  assert.equal(calls[0][2].env.GIT_TERMINAL_PROMPT, '0'); assert.equal(calls[0][2].windowsHide, true);
  assert.equal(store.sessions.get(result.sessionId).isTempRepo, true);
  for (const input of [{ url: 'file:///repo' }, { url: 'https://user:pass@example.test/repo' }, { url: 'https://example.test/repo', branch: '--upload-pack=evil' }]) {
    await assert.rejects(workspaces.clone(input));
  }
  assert.equal(calls.length, 1);
});

test('failed clone cleans only its managed temporary folder and creates no workspace', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-workspace-cleanup-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const store = createStore(root), owned = path.join(root, 'owned');
  const workspaces = createWorkspaces({ store, integrations: {
    createRepositoryDirectory: () => { fs.mkdirSync(owned); return owned; },
    execFile: async () => { throw new Error('provider error with credentials'); },
  } });
  await assert.rejects(workspaces.clone({ url: 'https://example.test/repo' }), /Clone failed/);
  assert.equal(fs.existsSync(owned), false); assert.equal(fs.existsSync(root), true); assert.equal(store.sessions.size, 0);
});
