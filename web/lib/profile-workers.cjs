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
  namespace = crypto.createHash('sha256').update(path.resolve(directory)).digest('hex').slice(0, 12) }) {
  if (!['docker', 'process'].includes(mode)) throw new Error('Unknown profile worker mode');
  if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(namespace)) throw new Error('Invalid profile namespace');
  if (!Number.isInteger(maxWorkers) || maxWorkers < 1 || maxWorkers > 100) throw new Error('Invalid profile worker limit');
  const workers = new Map();
  let closed = false;

  async function start(user) {
    if (!/^[a-f0-9-]{36}$/.test(user.id)) throw new Error('Invalid profile ID');
    const token = crypto.randomBytes(32).toString('hex');
    if (mode === 'process') {
      const home = path.join(directory, 'profiles', user.id);
      for (const sub of ['', 'tmp', 'workspace', '.config', '.threatlint']) fs.mkdirSync(path.join(home, sub), { recursive: true, mode: 0o700 });
      const child = fork(ENTRY, [], { env: { ...profileEnvironment(home), THREATLINT_WORKER_TOKEN: token },
        cwd: home, silent: true, windowsHide: true, execArgv: [] });
      // Do not print worker output: it can contain repository or integration details.
      child.stdout.resume(); child.stderr.resume();
      const stop = async () => {
        if (child.exitCode !== null || child.signalCode !== null) return;
        child.send?.({ action: 'close' }, () => {});
        await Promise.race([new Promise(resolve => child.once('exit', resolve)), delay(3000)]);
        if (child.exitCode === null && child.signalCode === null) child.kill();
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
      } catch (error) { await stop(); throw error; }
    }

    // Each profile also gets its own bridge: workers cannot bypass the gateway over a shared network.
    // Stable names allow crash recovery before another writer mounts the same home volume.
    const name = `threatlint-${namespace}-${user.id}`;
    const network = `${name}-net`;
    const volume = `threatlint-${namespace}-${user.id}`;
    let child;
    const stop = async () => {
      await exec('docker', ['rm', '--force', name], { windowsHide: true, timeout: 15_000 }).catch(() => {});
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
    } catch (error) { await stop(); throw error; }
  }

  async function get(user) {
    if (closed) throw new Error('Profile manager is closed');
    let pending = workers.get(user.id);
    if (pending && !(await pending).alive()) {
      if (workers.get(user.id) !== pending) return get(user);
      const previous = await pending;
      // Reserve the replacement before awaiting teardown; simultaneous requests share one writer.
      pending = previous.stop().then(() => start(user));
      workers.set(user.id, pending);
      const replacement = pending;
      pending.catch(() => { if (workers.get(user.id) === replacement) workers.delete(user.id); });
    }
    if (!pending) {
      if (workers.size >= maxWorkers) { const error = new Error('Workbench capacity reached. Contact the administrator.'); error.status = 503; throw error; }
      pending = start(user);
      workers.set(user.id, pending);
      pending.catch(() => { if (workers.get(user.id) === pending) workers.delete(user.id); });
    }
    const worker = await pending;
    if (closed) { await worker.stop(); throw new Error('Profile manager is closed'); }
    return worker;
  }
  async function close() {
    closed = true;
    await Promise.allSettled([...workers.values()].map(async pending => (await pending).stop()));
    workers.clear();
  }
  return { get, close };
}

module.exports = { createProfileWorkers, profileEnvironment, containerArguments };
