'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');
const { spawnSync } = require('node:child_process');
const { it } = require('node:test');
const { REPOSITORY, prepareSource, clearAssetCaches } = require('../desktop/update-source.cjs');

function temporary(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-update-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

it('fetches upstream every launch, advances an existing checkout, and refreshes dependencies only when changed', async t => {
  const root = temporary(t), upstream = path.join(root, 'upstream'), checkout = path.join(root, 'managed');
  fs.mkdirSync(path.join(upstream, 'web'), { recursive: true });
  const git = (cwd, args, env = process.env) => {
    const result = spawnSync('git', args, { cwd, env, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
  };
  git(upstream, ['init', '-q']);
  git(upstream, ['config', 'user.email', 'fixture@example.invalid']);
  git(upstream, ['config', 'user.name', 'Fixture']);
  const write = (file, value) => fs.writeFileSync(path.join(upstream, 'web', file), value);
  const commit = () => { git(upstream, ['add', '.']); git(upstream, ['-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'fixture']); };
  write('package.json', '{"version":"1.0.0"}'); write('package-lock.json', '{}'); write('server.js', 'old'); commit();
  let installs = 0, fetches = 0, failInstall = false;
  const runCommand = async (command, args, options) => {
    if (command === 'git') {
      assert.equal(options.env.GIT_TERMINAL_PROMPT, '0');
      assert.equal(options.env.GIT_CONFIG_KEY_0, 'core.hooksPath');
      if (args[0] === 'fetch') {
        fetches++;
        assert.ok(args.includes(REPOSITORY));
        assert.equal(args.at(-1), 'HEAD');
        args = args.map(arg => arg === REPOSITORY ? upstream : arg);
      }
      git(options.cwd, args, options.env);
    } else {
      installs++;
      assert.deepEqual(args, ['ci', '--include=dev', '--no-audit', '--no-fund']);
      if (failInstall) throw new Error('install failed');
      for (const file of ['electron-builder/cli.js', 'electron/install.js']) {
        const target = path.join(options.cwd, 'node_modules', file);
        fs.mkdirSync(path.dirname(target), { recursive: true }); fs.writeFileSync(target, '');
      }
    }
  };
  const source = await prepareSource(checkout, { runCommand });
  assert.equal(installs, 1);
  write('server.js', 'new'); commit();
  await prepareSource(checkout, { runCommand });
  assert.equal(fs.readFileSync(path.join(source, 'server.js'), 'utf8'), 'new');
  assert.equal(installs, 1);
  write('package-lock.json', '{"changed":true}'); commit();
  failInstall = true;
  await assert.rejects(prepareSource(checkout, { runCommand }), /install failed/);
  assert.equal(fs.existsSync(path.join(checkout, '.desktop-dependencies')), false);
  failInstall = false;
  await prepareSource(checkout, { runCommand });
  assert.equal(installs, 3, 'failed installation must be retried');
  await prepareSource(checkout, { runCommand });
  assert.equal(fetches, 5, 'even unchanged launches must fetch');
  assert.equal(installs, 3);
});

it('propagates fetch failures before resetting source or installing dependencies', async t => {
  const calls = [];
  await assert.rejects(prepareSource(temporary(t), { runCommand: async (_command, args) => {
    calls.push(args[0]); if (args[0] === 'fetch') throw new Error('offline');
  } }), /offline/);
  assert.deepEqual(calls, ['init', 'fetch']);
});

it('clears asset caches without deleting preferences, cookies, or saved work', async () => {
  const calls = [];
  await clearAssetCaches({
    clearCache: async () => calls.push('http'),
    clearCodeCaches: async options => calls.push(options),
    clearStorageData: async options => calls.push(options),
  });
  assert.deepEqual(calls, ['http', {}, { storages: ['serviceworkers', 'cachestorage', 'shadercache'] }]);
});

function updater(t, { argv = [], env = {}, failFetch = false, fingerprint = 'fresh', failBuild = false, localBuild } = {}) {
  const root = temporary(t), calls = [], logs = [];
  const installed = path.join(root, 'installed');
  const staged = path.join(root, 'staged');
  for (const directory of [installed, staged]) fs.mkdirSync(directory);
  fs.writeFileSync(path.join(installed, 'marker'), 'old');
  fs.writeFileSync(path.join(staged, 'marker'), 'new');
  const electron = { app: { getPath: () => root,
    relaunch: options => calls.push(['relaunch', options]),
    exit: () => { throw new Error('exited to relaunch'); },
  }, BrowserWindow: {} };
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../desktop/updater.cjs'), 'utf8'), {
    module, __dirname: path.join(__dirname, '../desktop'),
    process: { platform: 'linux', execPath: path.join(installed, 'threatlint'), resourcesPath: path.join(installed, 'resources'), env, argv },
    require: name => {
      if (name === 'electron') return electron;
      if (name === './user-path.cjs') return { userPath: () => process.env.PATH };
      if (name === './update-source.cjs') return { prepareSource: async (directory, runtime) => {
        assert.equal(Object.hasOwn(runtime.env, 'THREATLINT_LOCAL_DESKTOP_BUILD'), false);
        calls.push(['fetch', directory]); if (failFetch) throw new Error('offline'); return path.join(root, 'managed/web');
      } };
      if (name === 'node:child_process') return { spawn: (_node, args, options) => {
        assert.equal(Object.hasOwn(options.env, 'THREATLINT_LOCAL_DESKTOP_BUILD'), false);
        calls.push(['script', ...args]);
        const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter();
        queueMicrotask(() => {
          child.stdout.emit('data', args[1] === 'current' ? '{"fingerprint":"fresh","commit":"latest"}\n' : `STAGED ${staged}\n`);
          child.emit('close', args[1] === 'stage' && failBuild ? 1 : 0);
        });
        return child;
      } };
      return require(name);
    },
  });
  return { update: () => module.exports.updateOnLaunch({ source: '/missing/build/machine', fingerprint, commit: 'latest', localBuild },
    { status: () => {} }, line => logs.push(line)), calls, installed, logs };
}

it('fetches before comparing fingerprints even without the original build checkout', async t => {
  const fixture = updater(t, { env: { THREATLINT_LOCAL_DESKTOP_BUILD: '1' }, localBuild: 'true' });
  assert.equal(await fixture.update(), true);
  assert.equal(fixture.calls[0][0], 'fetch');
  assert.equal(fixture.calls[1].at(-1), 'current');
});

it('keeps an explicitly stamped local build without fetching or staging upstream', async t => {
  const fixture = updater(t, { fingerprint: 'old', failFetch: true, localBuild: true });
  assert.equal(await fixture.update(), true);
  assert.deepEqual(fixture.calls, []);
  assert.equal(fs.readFileSync(path.join(fixture.installed, 'marker'), 'utf8'), 'old');
  assert.match(fixture.logs[0], /explicitly packaged local build/);
});

it('skips the immediate update relaunch to prevent an update loop', async t => {
  const fixture = updater(t, { argv: ['--threatlint-updated'] });
  assert.equal(await fixture.update(), true);
  assert.deepEqual(fixture.calls, []);
});

it('surfaces launch fetch failures instead of reporting the installed app as current', async t => {
  const fixture = updater(t, { failFetch: true });
  await assert.rejects(fixture.update(), /offline/);
  assert.equal(fixture.calls.length, 1);
});

it('stages and swaps a changed upstream build before relaunching', async t => {
  const fixture = updater(t, { fingerprint: 'old' });
  await assert.rejects(fixture.update(), /exited to relaunch/);
  assert.equal(fs.readFileSync(path.join(fixture.installed, 'marker'), 'utf8'), 'new');
  const relaunch = fixture.calls.find(call => call[0] === 'relaunch');
  assert.ok(relaunch[1].args.includes('--threatlint-updated'));
});

it('keeps the installed bundle when a new build fails', async t => {
  const fixture = updater(t, { fingerprint: 'old', failBuild: true });
  await assert.rejects(fixture.update(), /desktop-sync stage exited with 1/);
  assert.equal(fs.readFileSync(path.join(fixture.installed, 'marker'), 'utf8'), 'old');
  assert.equal(fixture.calls.some(call => call[0] === 'relaunch'), false);
});
