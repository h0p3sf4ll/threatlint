'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createProfileWorkers, profileEnvironment, containerArguments, probeWorkerActivity, recoverNamespace, IDLE_TIMEOUT_MS } = require('../lib/profile-workers.cjs');

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
  for (const options of [{ mode: 'shared' }, { namespace: '../escape' }, { namespace: '' }, { maxWorkers: 0 }, { maxWorkers: 101 }, { maxWorkers: 1.5 },
    { idleTimeoutMs: 0 }, { sweepIntervalMs: -1 }, { startWorker: true }, { activityProbe: null }]) {
    assert.throws(() => createProfileWorkers({ directory: root, ...options }));
  }
  const manager = createProfileWorkers({ directory: root, mode: 'process' });
  try {
    for (const id of ['../escape', 'not-a-uuid', 'a'.repeat(37), '']) await assert.rejects(manager.get({ id }), /Invalid profile ID/);
  } finally { await manager.close(); }
  await assert.rejects(manager.get({ id: '00000000-0000-4000-8000-000000000001' }), /closed/);
});

const profile = index => ({ id: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}` });
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function runtimeFixture(t, options = {}) {
  let time = 0;
  const states = new Map(), started = [], stopped = [];
  const startWorker = async user => {
    started.push(user.id);
    const state = { id: user.id, busy: false, alive: true, stopError: false, activity: null };
    states.set(user.id, state);
    return { id: user.id, alive: () => state.alive, stop: async () => {
      if (state.stopError) throw new Error('Runtime unavailable');
      state.alive = false; stopped.push(user.id);
    } };
  };
  const manager = createProfileWorkers({ directory: directory(t), maxWorkers: 1, sweepIntervalMs: 0,
    now: () => time, startWorker, activityProbe: async worker => {
      const state = states.get(worker.id);
      return state.activity ? state.activity() : { busy: state.busy };
    }, ...options });
  t.after(() => manager.close());
  return { manager, states, started, stopped, time: value => { time = value; }, startWorker };
}

it('reuses a slot after an idle profile leaves while retaining leases for every open client', async t => {
  const { manager, stopped } = runtimeFixture(t);
  const first = await manager.acquire(profile(1));
  const secondTab = await manager.acquire(profile(1));
  assert.strictEqual(secondTab.worker, first.worker);
  first.release(); first.release();
  await assert.rejects(manager.acquire(profile(2)), error => error.status === 503 && error.retryAfter === 30 && error.code === 'profile_capacity');
  assert.deepEqual(stopped, []);
  secondTab.release();
  const replacement = await manager.acquire(profile(2));
  assert.equal(replacement.worker.id, profile(2).id);
  assert.deepEqual(stopped, [profile(1).id]);
  replacement.release();
});

it('never evicts detached jobs or a worker whose activity cannot be established', async t => {
  const { manager, states, started, stopped } = runtimeFixture(t);
  const first = await manager.acquire(profile(1)); first.release();
  const state = states.get(profile(1).id);
  for (const activity of [() => ({ busy: true }), () => ({}), () => ({ busy: 'false' }), () => null,
    () => { throw new Error('Activity unavailable'); }]) {
    state.activity = activity;
    await assert.rejects(manager.acquire(profile(2)), error => error.status === 503);
    assert.deepEqual(stopped, []);
    assert.deepEqual(started, [profile(1).id]);
  }
  state.activity = () => ({ busy: false });
  const next = await manager.acquire(profile(2)); next.release();
  assert.deepEqual(stopped, [profile(1).id]);
});

it('evicts the least recently used safe idle worker rather than an older busy worker', async t => {
  const { manager, states, stopped, time } = runtimeFixture(t, { maxWorkers: 3 });
  await manager.get(profile(1));
  time(100); await manager.get(profile(2));
  time(200); await manager.get(profile(3));
  time(300); await manager.get(profile(2));
  states.get(profile(1).id).busy = true;
  const newcomer = await manager.acquire(profile(4)); newcomer.release();
  assert.deepEqual(stopped, [profile(3).id]);
  assert.equal(states.get(profile(1).id).alive, true);
  assert.equal(states.get(profile(2).id).alive, true);
});

it('sweeps expired idle workers while preserving clients and background jobs', async t => {
  const { manager, states, stopped, time } = runtimeFixture(t, { maxWorkers: 3 });
  const client = await manager.acquire(profile(1));
  await manager.get(profile(2));
  await manager.get(profile(3));
  states.get(profile(3).id).busy = true;
  time(IDLE_TIMEOUT_MS - 1);
  assert.equal(await manager.sweep(), 0);
  time(IDLE_TIMEOUT_MS);
  assert.equal(await manager.sweep(), 1);
  assert.deepEqual(stopped, [profile(2).id]);
  states.get(profile(3).id).busy = false;
  assert.equal(await manager.sweep(), 1);
  client.release();
  assert.equal(await manager.sweep(), 0, 'releasing a client starts a fresh idle interval');
  time(IDLE_TIMEOUT_MS * 2);
  assert.equal(await manager.sweep(), 1);
});

it('reserves capacity and shares readiness while concurrent requests start the same profile', async t => {
  const ready = deferred(), entered = deferred();
  let launches = 0;
  const fixture = runtimeFixture(t, { startWorker: async user => {
    launches++; entered.resolve(); await ready.promise; return fixture.startWorker(user);
  } });
  const first = fixture.manager.acquire(profile(1));
  const second = fixture.manager.acquire(profile(1));
  await entered.promise;
  await assert.rejects(fixture.manager.acquire(profile(2)), error => error.status === 503);
  assert.equal(launches, 1);
  ready.resolve();
  const [a, b] = await Promise.all([first, second]);
  assert.strictEqual(a.worker, b.worker);
  a.release();
  await assert.rejects(fixture.manager.acquire(profile(2)), error => error.status === 503);
  b.release();
  const next = await fixture.manager.acquire(profile(2)); next.release();
  assert.equal(launches, 2);
});

it('serializes new leases behind an eviction decision so callers never receive a stopped worker', async t => {
  const checked = deferred(), answer = deferred();
  const { manager, states, stopped } = runtimeFixture(t);
  const first = await manager.acquire(profile(1)); first.release();
  states.get(profile(1).id).activity = async () => { checked.resolve(); return answer.promise; };
  const replacement = manager.acquire(profile(2));
  await checked.promise;
  const returning = manager.acquire(profile(1));
  const rejected = assert.rejects(returning, error => error.status === 503);
  answer.resolve({ busy: false });
  const current = await replacement;
  await rejected;
  assert.equal(current.worker.id, profile(2).id);
  assert.deepEqual(stopped, [profile(1).id]);
  current.release();
});

it('retains a capacity reservation when the runtime cannot confirm successful teardown', async t => {
  const { manager, states, started } = runtimeFixture(t);
  const first = await manager.acquire(profile(1)); first.release();
  states.get(profile(1).id).stopError = true;
  await assert.rejects(manager.acquire(profile(2)), error => error.status === 503);
  const stillLive = await manager.acquire(profile(1));
  assert.strictEqual(stillLive.worker, first.worker);
  assert.deepEqual(started, [profile(1).id]);
  states.get(profile(1).id).stopError = false;
  stillLive.release();
});

it('frees capacity after failed startup and supports repeated close calls', async t => {
  let attempts = 0;
  const fixture = runtimeFixture(t, { startWorker: user => {
    if (++attempts === 1) throw new Error('Startup failed');
    return fixture.startWorker(user);
  } });
  await assert.rejects(fixture.manager.acquire(profile(1)), /Startup failed/);
  const next = await fixture.manager.acquire(profile(2));
  assert.equal(next.worker.id, profile(2).id);
  next.release();
  await Promise.all([fixture.manager.close(), fixture.manager.close()]);
  await assert.rejects(fixture.manager.acquire(profile(2)), /closed/);
});

it('waits for a pending startup during close and never returns its worker to an awaiting client', async t => {
  const entered = deferred(), ready = deferred();
  const fixture = runtimeFixture(t, { startWorker: async user => {
    entered.resolve(); await ready.promise; return fixture.startWorker(user);
  } });
  const pending = fixture.manager.acquire(profile(1));
  await entered.promise;
  const rejected = assert.rejects(pending, /closed/);
  const closing = fixture.manager.close();
  ready.resolve();
  await Promise.all([closing, rejected]);
  assert.deepEqual(fixture.stopped, [profile(1).id]);
});

it('retains failed-startup capacity until uncertain cleanup is confirmed, including during close', async t => {
  let mayClean = false, cleanupCalls = 0, launches = 0;
  const cleanup = async () => { cleanupCalls++; if (!mayClean) throw new Error('Docker unavailable'); };
  const fixture = runtimeFixture(t, { startWorker: user => {
    if (++launches === 1) throw Object.assign(new Error('Unconfirmed startup cleanup'), { code: 'profile_cleanup_pending', cleanup });
    return fixture.startWorker(user);
  } });
  await assert.rejects(fixture.manager.acquire(profile(1)), /Unconfirmed startup cleanup/);
  await assert.rejects(fixture.manager.acquire(profile(2)), error => error.status === 503);
  await assert.rejects(fixture.manager.acquire(profile(1)), error => error.status === 503);
  assert.equal(launches, 1, 'an uncertain container still occupies the only slot');
  assert.equal(cleanupCalls, 2);
  mayClean = true;
  const next = await fixture.manager.acquire(profile(2)); next.release();
  assert.equal(launches, 2);
  assert.equal(cleanupCalls, 3);

  let closeCleanup = 0;
  const orphan = runtimeFixture(t, { startWorker: () => { throw Object.assign(new Error('Orphaned startup'),
    { cleanup: async () => { closeCleanup++; } }); } });
  await assert.rejects(orphan.manager.acquire(profile(1)), /Orphaned startup/);
  await orphan.manager.close();
  assert.equal(closeCleanup, 1, 'close retries cleanup despite the rejected readiness promise');
});

it('completes namespace recovery once before concurrent admissions and retries a failed inventory safely', async t => {
  const entered = deferred(), ready = deferred();
  let calls = 0;
  const fixture = runtimeFixture(t, { maxWorkers: 2, recoverRuntime: async () => {
    calls++; entered.resolve(); await ready.promise;
  } });
  const first = fixture.manager.acquire(profile(1)), second = fixture.manager.acquire(profile(2));
  await entered.promise;
  assert.deepEqual(fixture.started, []);
  ready.resolve();
  const clients = await Promise.all([first, second]); clients.forEach(client => client.release());
  assert.equal(calls, 1);
  assert.equal(fixture.started.length, 2);

  let inventories = 0;
  const retry = runtimeFixture(t, { recoverRuntime: async () => {
    if (++inventories === 1) throw new Error('Inventory unavailable');
  } });
  await assert.rejects(retry.manager.acquire(profile(1)), /Inventory unavailable/);
  assert.deepEqual(retry.started, []);
  const accepted = await retry.manager.acquire(profile(1)); accepted.release();
  assert.equal(inventories, 2);
});

it('recovers only exact owned stable container/network names and never removes profile volumes or unrelated resources', async () => {
  const own = `threatlint-production-${profile(1).id}`, other = `threatlint-other-${profile(2).id}`;
  const unrelated = [other, `${own}-abcd1234`, 'threatlint-production-not-a-profile', 'unrelated-application'];
  const commands = [];
  await recoverNamespace('production', async (command, args, options) => {
    assert.equal(command, 'docker');
    assert.ok(options.timeout > 0 && options.timeout <= 15000);
    commands.push(args);
    if (args[0] === 'container' && args[1] === 'ls') return { stdout: [own, ...unrelated].join('\n') };
    if (args[0] === 'network' && args[1] === 'ls') return { stdout: [own, ...unrelated].map(value => `${value}-net`).join('\n') };
    return { stdout: '' };
  });
  assert.deepEqual(commands.filter(args => args[0] === 'rm'), [['rm', '--force', own]]);
  assert.deepEqual(commands.filter(args => args[0] === 'network' && args[1] === 'rm'), [['network', 'rm', `${own}-net`]]);
  assert.equal(commands.some(args => args.includes('volume') || args.includes('--volumes') || args.includes('-v')), false);
  await assert.rejects(recoverNamespace('../invalid', async () => assert.fail('invalid namespace must not run Docker')), /namespace/);
});

it('refuses namespace recovery when container removal is uncertain', async () => {
  const own = `threatlint-production-${profile(1).id}`;
  const commands = [];
  await assert.rejects(recoverNamespace('production', async (_command, args) => {
    commands.push(args);
    if (args[0] === 'rm') throw new Error('Removal failed');
    if (args[0] === 'container' && args[1] === 'ls') return { stdout: own };
    throw new Error('Must not proceed to network cleanup');
  }), /could not be stopped/);
  assert.equal(commands.some(args => args[0] === 'network'), false);
});

it('uses the internal worker token and internal Host when probing runtime activity', async t => {
  let status = 200, body = '{"busy":false}', headers;
  const server = http.createServer((request, response) => {
    headers = request.headers;
    assert.equal(request.url, '/internal/activity');
    response.writeHead(status, { 'Content-Type': 'application/json' }); response.end(body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const worker = { port: server.address().port, workerPort: 3000, token: 'internal-only-token' };
  assert.deepEqual(await probeWorkerActivity(worker), { busy: false });
  assert.equal(headers.host, '127.0.0.1:3000');
  assert.equal(headers['x-threatlint-worker'], worker.token);
  for (const value of ['not json', '{"busy":"false"}', '{"unrelated":true}', 'x'.repeat(4097)]) {
    body = value; assert.equal(await probeWorkerActivity(worker), null);
  }
  status = 403; body = '{"busy":false}';
  assert.equal(await probeWorkerActivity(worker), null);
});
