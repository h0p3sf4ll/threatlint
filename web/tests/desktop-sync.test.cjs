'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { describe, it } = require('node:test');
const { swapInto, withLock } = require('../scripts/desktop-sync.cjs');

const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-desktop-sync-'));
const bundle = (dir, marker) => { fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(path.join(dir, 'marker'), marker); return dir; };
const marker = dir => fs.readFileSync(path.join(dir, 'marker'), 'utf8');

describe('desktop sync', () => {
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
