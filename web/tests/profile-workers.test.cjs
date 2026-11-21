'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createProfileWorkers, profileEnvironment, containerArguments } = require('../lib/profile-workers.cjs');

function directory(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-worker-tests-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

it('gives process workers isolated homes and CLI stores without inheriting gateway credentials or runtime injection', t => {
  const root = directory(t), home = path.join(root, 'profile-a');
  const parent = { PATH: '/trusted/bin', SystemRoot: 'C:\\Windows', LANG: 'en_US.UTF-8',
    HOME: '/operator', USERPROFILE: '/operator', APPDATA: '/operator/config', THREATLINT_HOME: '/operator/secrets',
    ANTHROPIC_API_KEY: 'private-anthropic', OPENAI_API_KEY: 'private-openai', AWS_ACCESS_KEY_ID: 'private-aws',
    AWS_SECRET_ACCESS_KEY: 'private-aws-secret', AWS_SESSION_TOKEN: 'private-session', AWS_PROFILE: 'operator',
    GH_TOKEN: 'private-github', GITHUB_TOKEN: 'private-github', THREATLINT_SNOW_CLIENT_SECRET: 'private-snow',
    NODE_OPTIONS: '--require /operator/inject.cjs', NODE_PATH: '/operator/modules', PYTHONPATH: '/operator/python',
    HTTPS_PROXY: 'https://user:password@example.test', THREATLINT_WORKER_TOKEN: 'private-worker-token' };
  const first = profileEnvironment(home, parent), second = profileEnvironment(path.join(root, 'profile-b'), parent);
  assert.equal(first.PATH, parent.PATH);
  assert.equal(first.SystemRoot, parent.SystemRoot);
  assert.equal(first.HOME, home);
  assert.equal(first.USERPROFILE, home);
  assert.equal(first.PYTHON_KEYRING_BACKEND, 'keyring.backends.null.Keyring');
  assert.equal(first.GIT_CONFIG_NOSYSTEM, '1');
  assert.equal(first.PORT, '0');
  for (const key of ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
    'AWS_PROFILE', 'GH_TOKEN', 'GITHUB_TOKEN', 'THREATLINT_SNOW_CLIENT_SECRET', 'NODE_OPTIONS', 'NODE_PATH', 'PYTHONPATH',
    'HTTPS_PROXY', 'THREATLINT_WORKER_TOKEN']) assert.equal(Object.hasOwn(first, key), false, key);
  for (const key of ['HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME',
    'THREATLINT_HOME', 'THREATLINT_STATE_DIR', 'CODEX_HOME', 'CLAUDE_CONFIG_DIR', 'GH_CONFIG_DIR', 'AWS_CONFIG_FILE',
    'AWS_SHARED_CREDENTIALS_FILE', 'TEMP', 'TMP', 'TMPDIR']) {
    const relative = path.relative(home, first[key]);
    assert.equal(relative.startsWith('..') || path.isAbsolute(relative), false, `${key} escapes the profile`);
    assert.notEqual(first[key], second[key], `${key} is shared between profiles`);
  }
  assert.equal(parent.HOME, '/operator');
});

it('uses named home volumes, separate networks, loopback ports and restricted container privileges', () => {
  const args = containerArguments({ name: 'profile-a', network: 'profile-a-net', volume: 'profile-a-home', image: 'threatlint-profile:local' });
  const value = option => args[args.indexOf(option) + 1];
  assert.equal(value('--name'), 'profile-a');
  assert.equal(value('--network'), 'profile-a-net');
  assert.equal(value('--mount'), 'type=volume,source=profile-a-home,target=/home/threatlint');
  assert.equal(value('--publish'), '127.0.0.1::3000');
  assert.ok(args.includes('--read-only'));
  assert.ok(args.includes('--cap-drop=ALL'));
  assert.equal(value('--security-opt'), 'no-new-privileges');
  assert.equal(value('--pids-limit'), '256');
  assert.ok(Number(value('--cpus')) > 0);
  assert.match(value('--memory'), /^\d+[mg]$/);
  assert.match(value('--tmpfs'), /^\/tmp:.*nosuid.*nodev/);
  assert.equal(args.includes('--privileged'), false);
  assert.equal(args.includes('--volume'), false);
  assert.equal(args.includes('-v'), false);
  assert.doesNotMatch(args.join(' '), /type=bind|docker\.sock|host\.docker|--network host/);
  assert.ok(args.includes('PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring'));
  assert.ok(args.includes('THREATLINT_WORKER_STDIN=1'));
  assert.equal(args.at(-1), 'threatlint-profile:local');
  const other = containerArguments({ name: 'profile-b', network: 'profile-b-net', volume: 'profile-b-home', image: 'threatlint-profile:local' });
  assert.notEqual(value('--network'), other[other.indexOf('--network') + 1]);
  assert.notEqual(value('--mount'), other[other.indexOf('--mount') + 1]);
});

it('builds the profile image with an unprivileged runtime user and no gateway entry point', () => {
  const dockerfile = fs.readFileSync(path.join(__dirname, '../../Dockerfile.web'), 'utf8');
  const runtimeUser = [...dockerfile.matchAll(/^USER\s+(.+)$/gm)].at(-1)?.[1].trim();
  assert.ok(runtimeUser && !/^(?:root|0)(?::|$)/.test(runtimeUser));
  assert.match(dockerfile, /CMD\s+\["node",\s*"web\/profile-worker\.cjs"\]/);
  assert.match(dockerfile, /chown[^\r\n]*\/home\/threatlint/);
});

it('rejects invalid modes, namespaces, worker limits, and profile IDs before starting a runtime', async t => {
  const root = directory(t);
  for (const options of [{ mode: 'shared' }, { namespace: '../escape' }, { namespace: '' }, { maxWorkers: 0 }, { maxWorkers: 101 }, { maxWorkers: 1.5 }]) {
    assert.throws(() => createProfileWorkers({ directory: root, ...options }));
  }
  const manager = createProfileWorkers({ directory: root, mode: 'process' });
  try {
    for (const id of ['../escape', 'not-a-uuid', 'a'.repeat(37), '']) await assert.rejects(manager.get({ id }), /Invalid profile ID/);
  } finally { await manager.close(); }
  await assert.rejects(manager.get({ id: '00000000-0000-4000-8000-000000000001' }), /closed/);
});
