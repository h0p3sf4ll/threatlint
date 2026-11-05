'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { describe, it } = require('node:test');
const { swapInto, withLock } = require('../scripts/desktop-sync.cjs');

const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-desktop-sync-'));
const bundle = (dir, marker) => { fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(path.join(dir, 'marker'), marker); return dir; };
const marker = dir => fs.readFileSync(path.join(dir, 'marker'), 'utf8');

function buildFixture(t, { installFails = false } = {}) {
  const root = temp();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const write = (relative, source) => {
    const target = path.join(root, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, source);
  };
  write('scripts/desktop-sync.cjs', fs.readFileSync(path.join(__dirname, '../scripts/desktop-sync.cjs')));
  write('package.json', JSON.stringify({ version: '1.0.0' }));
  write('desktop/build-icon.cjs', '');
  write('node_modules/electron/install.js', installFails ? 'process.exit(1);' : `
    const fs = require('node:fs');
    const path = require('node:path');
    const dist = path.join(__dirname, 'dist');
    fs.mkdirSync(dist, { recursive: true });
    fs.writeFileSync(path.join(dist, 'electron.exe'), 'fixture runtime');
  `);
  write('node_modules/electron-builder/cli.js', `
    const assert = require('node:assert/strict');
    const fs = require('node:fs');
    const path = require('node:path');
    fs.writeFileSync('builder-ran', 'yes');
    assert.ok(fs.existsSync('node_modules/electron/dist/electron.exe'), 'runtime must be installed before packaging');
    const output = process.argv.find(arg => arg.startsWith('--config.directories.output=')).split('=').slice(1).join('=');
    fs.mkdirSync(path.join(output, 'win-unpacked'), { recursive: true });
  `);
  const run = (...args) => spawnSync(process.execPath, [path.join(root, 'scripts/desktop-sync.cjs'), ...args], { cwd: root, encoding: 'utf8' });
  return { root, run };
}

describe('desktop sync', () => {
  it('installs a missing Electron runtime before staging and keeps the stamp current', t => {
    const { root, run } = buildFixture(t);
    const output = path.join(root, 'release/staging');
    assert.equal(fs.existsSync(path.join(root, 'node_modules/electron/dist')), false);

    const staged = run('stage', output);
    assert.equal(staged.status, 0, staged.stderr);
    assert.ok(fs.existsSync(path.join(output, 'win-unpacked')));
    assert.ok(fs.existsSync(path.join(root, 'builder-ran')));

    const stamped = JSON.parse(fs.readFileSync(path.join(root, 'build-assets/build-info.json'), 'utf8'));
    const current = run('current');
    assert.equal(current.status, 0, current.stderr);
    assert.equal(stamped.fingerprint, JSON.parse(current.stdout).fingerprint);
  });

  it('does not package or replace the working app when Electron installation fails', t => {
    const { root, run } = buildFixture(t, { installFails: true });
    const target = bundle(path.join(root, 'release/win-unpacked'), 'working app');

    const synced = run('ensure');
    assert.notEqual(synced.status, 0);
    assert.equal(marker(target), 'working app');
    assert.equal(fs.existsSync(path.join(root, 'builder-ran')), false);
    assert.equal(fs.existsSync(path.join(root, 'release/.staging')), false);
    assert.equal(fs.existsSync(path.join(root, 'release/.desktop-sync.lock')), false);
  });

  it('swaps a staged app in and leaves no backup behind', () => {
    const root = temp();
    const target = bundle(path.join(root, 'release/mac-arm64/Threatlint.app'), 'old');
    swapInto(bundle(path.join(root, 'staging/Threatlint.app'), 'new'), target);
    assert.equal(marker(target), 'new');
    assert.ok(!fs.existsSync(`${target}.previous`) && !fs.existsSync(path.join(root, 'staging/Threatlint.app')));
  });

  it('keeps the working app when the staged one cannot be moved in', () => {
    const root = temp();
    const target = bundle(path.join(root, 'release/mac-arm64/Threatlint.app'), 'old');
    assert.throws(() => swapInto(path.join(root, 'missing/Threatlint.app'), target));
    assert.equal(marker(target), 'old');
  });

  it('runs one sync at a time and recovers a stale lock', () => {
    const lock = path.join(temp(), '.desktop-sync.lock');
    let runs = 0;
    fs.writeFileSync(lock, String(process.pid)); // held by a live process (this one)
    withLock(() => { runs += 1; }, lock);
    assert.equal(runs, 0, 'a held lock skips the build');
    fs.writeFileSync(lock, '999999999'); // owner no longer exists
    withLock(() => { runs += 1; assert.equal(fs.readFileSync(lock, 'utf8'), String(process.pid)); }, lock);
    assert.equal(runs, 1);
    assert.ok(!fs.existsSync(lock), 'the lock is released afterwards');
  });
});
