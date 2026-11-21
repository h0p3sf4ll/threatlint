'use strict';

// A Workbench has process-global CLI credentials and caches. Never multiplex users inside it.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');
const { fork, spawn, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const exec = promisify(execFile);
const ENTRY = path.join(__dirname, '../profile-worker.cjs');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const IDLE_TIMEOUT_MS = 15 * 60_000;
const PROFILE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const pendingCleanup = cleanup => Object.assign(new Error('Profile startup cleanup could not be confirmed'),
  { code: 'profile_cleanup_pending', cleanup });

async function removeContainer(name, run = exec) {
  try { await run('docker', ['rm', '--force', name], { windowsHide: true, timeout: 15_000 }); }
  catch {
    // A failed Docker connection is not proof that the container has stopped.
    const inventory = await run('docker', ['container', 'ls', '--all', '--filter', `name=^/${name}$`, '--format', '{{.Names}}'],
      { windowsHide: true, timeout: 15_000 });
    if (inventory.stdout.trim()) throw new Error('Profile container could not be stopped');
  }
}

async function recoverNamespace(namespace, run = exec) {
  if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(namespace)) throw new Error('Invalid profile namespace');
  const deadline = Date.now() + 30_000;
  const boundedRun = (command, args, options = {}) => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error('Profile recovery timed out');
    return run(command, args, { ...options, windowsHide: true, timeout: Math.min(15_000, remaining), maxBuffer: 1024 * 1024 });
  };
  const prefix = `threatlint-${namespace}-`;
  const owned = value => value.startsWith(prefix) && PROFILE_ID.test(value.slice(prefix.length));
  const inventory = await boundedRun('docker', ['container', 'ls', '--all', '--filter', `name=^/${prefix}`, '--format', '{{.Names}}']);
  const names = inventory.stdout.trim().split(/\r?\n/).filter(owned);
  if (names.length > 100) throw new Error('Too many orphaned profile containers to recover automatically');
  for (const name of names) await removeContainer(name, boundedRun);
  const networkInventory = await boundedRun('docker', ['network', 'ls', '--filter', `name=^${prefix}`, '--format', '{{.Name}}']);
  const networks = networkInventory.stdout.trim().split(/\r?\n/).filter(value => value.endsWith('-net') && owned(value.slice(0, -4)));
  if (networks.length > 100) throw new Error('Too many orphaned profile networks to recover automatically');
  for (const network of networks) await boundedRun('docker', ['network', 'rm', network]);
  // Home volumes are deliberately never enumerated or removed during crash recovery.
}

function probeWorkerActivity(worker) {
  return new Promise(resolve => {
    let settled = false, timer;
    const done = value => { if (settled) return; settled = true; clearTimeout(timer); resolve(value); };
    const request = http.get({ hostname: '127.0.0.1', port: worker.port, path: '/internal/activity',
      headers: { Host: `127.0.0.1:${worker.workerPort}`, 'x-threatlint-worker': worker.token } }, response => {
      if (response.statusCode !== 200) { done(null); request.destroy(); return; }
      let body = '';
      response.on('data', chunk => {
        body += chunk;
        if (body.length > 4096) { done(null); request.destroy(); }
      });
      response.on('end', () => {
        try { const value = JSON.parse(body); done(typeof value?.busy === 'boolean' ? value : null); }
        catch { done(null); }
      });
      response.on('error', () => done(null));
    });
    request.on('error', () => done(null));
    timer = setTimeout(() => { done(null); request.destroy(); }, 2000);
  });
}

function profileEnvironment(directory, parent = process.env) {
  // Do not copy API tokens, inherited CLI logins, proxy credentials, or NODE_OPTIONS.
  const env = {};
  for (const key of ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'ProgramFiles', 'ProgramFiles(x86)', 'LANG']) {
    if (parent[key]) env[key] = parent[key];
  }
  return { ...env, HOME: directory, USERPROFILE: directory, APPDATA: path.join(directory, 'AppData/Roaming'),
    LOCALAPPDATA: path.join(directory, 'AppData/Local'), XDG_CONFIG_HOME: path.join(directory, '.config'),
    XDG_DATA_HOME: path.join(directory, '.local/share'), XDG_CACHE_HOME: path.join(directory, '.cache'),
    THREATLINT_HOME: path.join(directory, '.threatlint'), THREATLINT_STATE_DIR: path.join(directory, '.threatlint/workbench'),
    CODEX_HOME: path.join(directory, '.codex'), CLAUDE_CONFIG_DIR: path.join(directory, '.claude'),
    GH_CONFIG_DIR: path.join(directory, '.config/gh'), AWS_CONFIG_FILE: path.join(directory, '.aws/config'),
    AWS_SHARED_CREDENTIALS_FILE: path.join(directory, '.aws/credentials'),
    TEMP: path.join(directory, 'tmp'), TMP: path.join(directory, 'tmp'), TMPDIR: path.join(directory, 'tmp'),
    PYTHON_KEYRING_BACKEND: 'keyring.backends.null.Keyring', AWS_EC2_METADATA_DISABLED: 'true', GIT_CONFIG_NOSYSTEM: '1',
    THREATLINT_PROFILE_WORKER: '1', PORT: '0' };
}

function containerArguments({ name, network, volume, image }) {
  return ['run', '--rm', '--interactive', '--name', name, '--network', network,
    '--publish', '127.0.0.1::3000', '--read-only', '--cap-drop=ALL', '--security-opt', 'no-new-privileges',
    '--pids-limit', '256', '--memory', '2g', '--cpus', '2',
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m,mode=1777',
    '--mount', `type=volume,source=${volume},target=/home/threatlint`,
    '--env', 'THREATLINT_WORKER_STDIN=1', '--env', 'THREATLINT_PROFILE_WORKER=1',
    '--env', 'THREATLINT_WORKER_HOST=0.0.0.0', '--env', 'PORT=3000',
    '--env', 'HOME=/home/threatlint', '--env', 'USERPROFILE=/home/threatlint',
    '--env', 'THREATLINT_HOME=/home/threatlint/.threatlint',
    '--env', 'THREATLINT_STATE_DIR=/home/threatlint/.threatlint/workbench',
    '--env', 'AWS_EC2_METADATA_DISABLED=true', '--env', 'PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring', image];
}

function createProfileWorkers({ directory, mode = 'docker', image = 'threatlint-profile:local', maxWorkers = 8,
  namespace = crypto.createHash('sha256').update(path.resolve(directory)).digest('hex').slice(0, 12),
  idleTimeoutMs = IDLE_TIMEOUT_MS, sweepIntervalMs = 60_000, now = Date.now,
  startWorker, activityProbe = probeWorkerActivity, recoverRuntime }) {
  if (!['docker', 'process'].includes(mode)) throw new Error('Unknown profile worker mode');
  if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(namespace)) throw new Error('Invalid profile namespace');
  if (!Number.isInteger(maxWorkers) || maxWorkers < 1 || maxWorkers > 100) throw new Error('Invalid profile worker limit');
  if (!Number.isSafeInteger(idleTimeoutMs) || idleTimeoutMs < 1000 || !Number.isSafeInteger(sweepIntervalMs) || sweepIntervalMs < 0) throw new Error('Invalid profile idle timeout');
  if (typeof now !== 'function' || typeof activityProbe !== 'function' || (startWorker !== undefined && typeof startWorker !== 'function') ||
      (recoverRuntime !== undefined && typeof recoverRuntime !== 'function')) throw new Error('Invalid profile runtime adapter');
  const workers = new Map();
  let closed = false, recovered = false, operations = Promise.resolve(), sweeping = null, closing = null;

  // Admission, readiness reservations and eviction are serialized. No new lease can arrive
  // between a candidate's activity check and teardown; background jobs report busy in the worker.
  function serialized(work) {
    const result = operations.then(work);
    operations = result.catch(() => {});
    return result;
  }
  function capacityError() {
    return Object.assign(new Error('All Workbench slots are in use. Try again shortly.'),
      { status: 503, code: 'profile_capacity', retryAfter: 30 });
  }

  async function startRuntime(user) {
    if (!PROFILE_ID.test(user.id)) throw new Error('Invalid profile ID');
    const token = crypto.randomBytes(32).toString('hex');
    if (mode === 'process') {
      const home = path.join(directory, 'profiles', user.id);
      for (const sub of ['', 'tmp', 'workspace', '.config', '.threatlint']) fs.mkdirSync(path.join(home, sub), { recursive: true, mode: 0o700 });
      const child = fork(ENTRY, [], { env: { ...profileEnvironment(home), THREATLINT_WORKER_TOKEN: token },
        cwd: home, silent: true, windowsHide: true, execArgv: [] });
      // Do not print worker output: it can contain repository or integration details.
      child.stdout.resume(); child.stderr.resume();
      const stop = async () => {
        const exited = () => child.exitCode !== null || child.signalCode !== null;
        const waitForExit = timeout => new Promise(resolve => {
          if (exited()) { resolve(true); return; }
          const done = () => { clearTimeout(timer); child.removeListener('exit', done); resolve(true); };
          const timer = setTimeout(() => { child.removeListener('exit', done); resolve(exited()); }, timeout);
          child.once('exit', done);
        });
        if (exited()) return;
        try { child.send?.({ action: 'close' }, () => {}); } catch { /* force termination below */ }
        if (await waitForExit(3000)) return;
        if (!child.kill() && !exited()) throw new Error('Profile process could not be stopped');
        if (!(await waitForExit(2000))) throw new Error('Profile process termination could not be confirmed');
      };
      try {
        const port = await new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error('Profile startup timed out')), 30_000);
          const done = (error, value) => { clearTimeout(timer); error ? reject(error) : resolve(value); };
          child.once('error', () => done(new Error('Profile could not start')));
          child.once('exit', () => done(new Error('Profile exited')));
          child.once('message', message => message.type === 'ready' ? done(null, message.port) : done(new Error('Profile could not start')));
        });
        return { port, workerPort: port, token, stop, alive: () => child.exitCode === null && child.signalCode === null };
      } catch (error) {
        try { await stop(); } catch { throw pendingCleanup(stop); }
        throw error;
      }
    }

    // Each profile also gets its own bridge: workers cannot bypass the gateway over a shared network.
    // Stable names allow crash recovery before another writer mounts the same home volume.
    const name = `threatlint-${namespace}-${user.id}`;
    const network = `${name}-net`;
    const volume = `threatlint-${namespace}-${user.id}`;
    let child;
    const stop = async () => {
      await removeContainer(name);
      child?.kill();
      await exec('docker', ['network', 'rm', network], { windowsHide: true, timeout: 15_000 }).catch(() => {});
    };
    try {
      await exec('docker', ['rm', '--force', name], { windowsHide: true, timeout: 15_000 }).catch(() => {});
      await exec('docker', ['network', 'rm', network], { windowsHide: true, timeout: 15_000 }).catch(() => {});
      await exec('docker', ['network', 'create', network], { windowsHide: true, timeout: 15_000 });
      child = spawn('docker', containerArguments({ name, network, volume, image }), { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
      let exited = false;
      child.on('error', () => { exited = true; }); child.on('exit', () => { exited = true; });
      child.stdout.resume(); child.stderr.resume(); child.stdin.on('error', () => {});
      // The per-launch gateway secret travels through stdin, never a command argument or saved file.
      child.stdin.write(JSON.stringify({ token }) + '\n');
      for (let attempt = 0; attempt < 60; attempt++) {
        if (exited) throw new Error('Profile container exited; build the configured profile image first');
        const result = await exec('docker', ['port', name, '3000/tcp'], { windowsHide: true, timeout: 5000 }).catch(() => null);
        const port = Number(/127\.0\.0\.1:(\d+)/.exec(result?.stdout || '')?.[1]);
        if (port) {
          const ready = await new Promise(resolve => {
            // Node's fetch can normalize Host to the mapped host port; the worker validates its internal port.
            const request = http.get({ hostname: '127.0.0.1', port, path: '/api/agents',
              headers: { Host: '127.0.0.1:3000', 'x-threatlint-worker': token } }, response => {
              response.resume(); resolve(response.statusCode === 200);
            });
            request.on('error', () => resolve(false)); request.setTimeout(1000, () => request.destroy());
          });
          if (ready) return { port, workerPort: 3000, token, stop, alive: () => !exited };
        }
        await delay(500);
      }
      throw new Error('Profile container startup timed out');
    } catch (error) {
      try { await stop(); }
      catch {
        // Retain a capacity reservation when startup failed but its container may still exist.
        throw pendingCleanup(stop);
      }
      throw error;
    }
  }

  async function retire(entry) {
    const previous = entry.state;
    entry.state = 'draining';
    try { await entry.worker.stop(); }
    catch { entry.state = previous; return false; }
    if (workers.get(entry.id) === entry) workers.delete(entry.id);
    return true;
  }
  async function evict({ pressure = false } = {}) {
    let removed = 0;
    const candidates = [...workers.values()].filter(entry => ['ready', 'cleanup'].includes(entry.state) && entry.leases === 0)
      .sort((a, b) => a.lastUsed - b.lastUsed);
    for (const entry of candidates) {
      if (closed) break;
      if (entry.state !== 'cleanup' && !pressure && now() - entry.lastUsed < idleTimeoutMs) continue;
      if (entry.state !== 'cleanup' && entry.worker.alive()) {
        let activity;
        try { activity = await activityProbe(entry.worker); } catch { continue; }
        // Missing, failed or malformed worker activity information always fails closed.
        if (activity?.busy !== false) continue;
      }
      if (await retire(entry)) removed++;
      if (pressure && removed) break;
    }
    return removed;
  }
  async function reserve(user, leased) {
    const entry = await serialized(async () => {
      if (closed) throw new Error('Profile manager is closed');
      if (!PROFILE_ID.test(user?.id || '')) throw new Error('Invalid profile ID');
      if (!recovered) {
        if (recoverRuntime) await recoverRuntime();
        else if (!startWorker && mode === 'docker') await recoverNamespace(namespace);
        recovered = true;
      }
      if (closed) throw new Error('Profile manager is closed');
      let entry = workers.get(user.id);
      if (entry?.state === 'cleanup' || (entry?.state === 'ready' && !entry.worker.alive())) {
        if (!(await retire(entry))) throw capacityError();
        entry = null;
      }
      if (!entry) {
        if (workers.size >= maxWorkers) await evict({ pressure: true });
        if (closed) throw new Error('Profile manager is closed');
        if (workers.size >= maxWorkers) throw capacityError();
        entry = { id: user.id, state: 'starting', leases: 0, lastUsed: now(), worker: null, ready: null };
        workers.set(user.id, entry);
        entry.ready = Promise.resolve().then(() => (startWorker || startRuntime)(user)).then(worker => {
          entry.worker = worker; entry.state = 'ready'; return worker;
        }, error => {
          if (typeof error?.cleanup === 'function') {
            entry.state = 'cleanup'; entry.worker = { stop: error.cleanup };
          } else if (workers.get(user.id) === entry) workers.delete(user.id);
          throw error;
        });
        entry.ready.catch(() => {});
      }
      if (leased) entry.leases++;
      entry.lastUsed = now();
      return entry;
    });
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      if (leased) entry.leases--;
      entry.lastUsed = now();
    };
    try {
      const worker = await entry.ready;
      if (closed) throw new Error('Profile manager is closed');
      return { worker, release };
    } catch (error) { release(); throw error; }
  }
  async function acquire(user) { return reserve(user, true); }
  // Compatibility for callers that only inspect a worker. Proxied requests must use acquire().
  async function get(user) { return (await reserve(user, false)).worker; }
  function sweep() {
    if (closed) return Promise.resolve(0);
    if (!sweeping) sweeping = serialized(() => evict()).finally(() => { sweeping = null; });
    return sweeping;
  }
  const timer = sweepIntervalMs ? setInterval(() => { sweep().catch(() => {}); }, sweepIntervalMs) : null;
  timer?.unref();
  function close() {
    if (closing) return closing;
    closed = true;
    if (timer) clearInterval(timer);
    closing = serialized(async () => {
      await Promise.allSettled([...workers.values()].map(async entry => {
        try { await entry.ready; } catch { /* a rejected startup can still require cleanup */ }
        if (entry.worker) await entry.worker.stop();
      }));
      workers.clear();
    });
    return closing;
  }
  return { get, acquire, sweep, close };
}

module.exports = { createProfileWorkers, profileEnvironment, containerArguments, probeWorkerActivity, recoverNamespace, IDLE_TIMEOUT_MS };
