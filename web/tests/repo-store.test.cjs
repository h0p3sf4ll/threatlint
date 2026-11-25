'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { repoStoreBase, createRepositoryDirectory, mountedStorageDirectory } = require('../lib/repo-store.cjs');
const { createStore } = require('../lib/store.cjs');

function fixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-repo-store-test-')));
  const external = path.join(root, 'external'), primary = path.join(root, 'primary');
  fs.mkdirSync(external); fs.mkdirSync(primary);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, external, primary };
}
const failure = code => Object.assign(new Error('Synthetic unavailable storage'), { code });

it('rejects an existing but unmounted POSIX volume directory before probing or downloading', t => {
  const f = fixture(t);
  let probes = 0;
  const filesystem = { ...fs,
    realpathSync() { return '/mnt/external/repos'; },
    statSync() { return { isDirectory: () => true, dev: 1 }; },
    readFileSync() { return ''; },
    openSync() { probes++; throw new Error('Must not write on an unmounted volume path'); },
  };
  const directory = createRepositoryDirectory('threatlint-scm-', { configured: '/mnt/external/repos',
    temporary: f.primary, filesystem, platform: 'linux' });
  assert.equal(path.dirname(directory), f.primary); assert.equal(probes, 0);
});

it('recognizes mounted device boundaries and same-device bind mounts without searching other disks', () => {
  const sameDevice = { readFileSync: () => '', statSync: () => ({ dev: 1 }) };
  assert.equal(mountedStorageDirectory('/media/user/external/repos', { filesystem: sameDevice, platform: 'linux' }), false);
  assert.equal(mountedStorageDirectory('/home/user/custom-repos', { filesystem: sameDevice, platform: 'linux' }), true);
  const external = { ...sameDevice, statSync: value => ({ dev: value === '/mnt' ? 1 : 9 }) };
  assert.equal(mountedStorageDirectory('/mnt/external/repos', { filesystem: external, platform: 'linux' }), true);
  const bind = { ...sameDevice, readFileSync: () => '31 20 0:1 /source /mnt/External\\040Drive rw - ext4 /dev/synthetic rw\n' };
  assert.equal(mountedStorageDirectory('/mnt/External Drive/repos', { filesystem: bind, platform: 'linux' }), true);
});

it('accepts a conventional volume parent itself only when a real mount is proven', () => {
  const ordinary = { readFileSync: () => '', statSync: () => ({ dev: 1 }) };
  assert.equal(mountedStorageDirectory('/mnt', { filesystem: ordinary, platform: 'linux' }), false);
  assert.equal(mountedStorageDirectory('/media/repos', { filesystem: ordinary, platform: 'linux' }), false);
  const mounted = { ...ordinary, statSync: value => ({ dev: value === '/' ? 1 : 9 }) };
  assert.equal(mountedStorageDirectory('/mnt', { filesystem: mounted, platform: 'linux' }), true);
  assert.equal(mountedStorageDirectory('/mnt/repos', { filesystem: mounted, platform: 'linux' }), true);
  const bind = { ...ordinary, readFileSync: () => '31 20 0:1 /source /media rw - ext4 /dev/synthetic rw\n' };
  assert.equal(mountedStorageDirectory('/media', { filesystem: bind, platform: 'linux' }), true);
  assert.equal(mountedStorageDirectory('/media/repos', { filesystem: bind, platform: 'linux' }), true);
});

it('allocates on an existing writable configured disk and retains that exact path in saved sessions', t => {
  const f = fixture(t);
  const directory = createRepositoryDirectory('threatlint-scm-', { configured: f.external, temporary: f.primary });
  assert.equal(path.dirname(directory), fs.realpathSync(f.external));
  assert.deepEqual(fs.readdirSync(f.external), [path.basename(directory)]);
  const repository = path.join(directory, 'repository'); fs.mkdirSync(repository);
  fs.writeFileSync(path.join(repository, 'evidence.txt'), 'same selected checkout');
  const history = path.join(f.root, 'history'), store = createStore(history);
  const id = store.create(repository, true, directory);
  const laterDirectory = createRepositoryDirectory('threatlint-scm-', { configured: path.join(f.root, 'missing'), temporary: f.primary });
  assert.equal(path.dirname(laterDirectory), f.primary);
  const restored = createStore(history).sessions.get(id);
  assert.equal(restored.repoPath, repository); assert.equal(restored.tempDir, directory);
  assert.equal(fs.readFileSync(path.join(restored.repoPath, 'evidence.txt'), 'utf8'), 'same selected checkout');
});

it('falls back before download and never creates a missing optional mount or directory', t => {
  const f = fixture(t), absent = path.join(f.root, 'unmounted', 'repositories');
  assert.equal(repoStoreBase({ configured: absent }), null);
  const directory = createRepositoryDirectory('threatlint-scm-', { configured: absent, temporary: f.primary });
  assert.equal(path.dirname(directory), f.primary);
  assert.equal(fs.existsSync(path.join(f.root, 'unmounted')), false);
});

for (const code of ['EACCES', 'EROFS', 'ENODEV', 'ENOSPC']) {
  it(`falls back when the configured directory cannot accept writes (${code})`, t => {
    const f = fixture(t);
    const filesystem = { ...fs, openSync() { throw failure(code); } };
    const directory = createRepositoryDirectory('threatlint-scm-', { configured: f.external, temporary: f.primary, filesystem });
    assert.equal(path.dirname(directory), f.primary);
    assert.deepEqual(fs.readdirSync(f.external), []);
  });
}

it('handles a disk disappearing after its write probe but before checkout allocation', t => {
  const f = fixture(t), attempted = [];
  const filesystem = { ...fs, mkdtempSync(prefix) {
    attempted.push(prefix);
    if (path.dirname(prefix) === f.external) throw failure('ENOENT');
    return fs.mkdtempSync(prefix);
  } };
  const directory = createRepositoryDirectory('threatlint-scm-', { configured: f.external, temporary: f.primary, filesystem });
  assert.equal(path.dirname(directory), f.primary); assert.equal(attempted.length, 2);
  assert.deepEqual(fs.readdirSync(f.external), []);
});

it('rejects a configured file and fails at allocation if primary storage is also unavailable', t => {
  const f = fixture(t), file = path.join(f.root, 'not-a-directory'); fs.writeFileSync(file, 'preserve');
  assert.equal(repoStoreBase({ configured: file }), null);
  assert.throws(() => createRepositoryDirectory('threatlint-scm-', { configured: file, temporary: f.primary,
    filesystem: { ...fs, mkdtempSync() { throw failure('ENOSPC'); } } }), { code: 'ENOSPC' });
  assert.equal(fs.readFileSync(file, 'utf8'), 'preserve');
});

it('honors the repo-store environment override ahead of local configuration', t => {
  const f = fixture(t), home = path.join(f.root, 'home'); fs.mkdirSync(home);
  fs.writeFileSync(path.join(home, 'org.json'), JSON.stringify({ repoStore: path.join(f.root, 'missing') }));
  const before = { home: process.env.THREATLINT_HOME, root: process.env.THREATLINT_REPO_STORE };
  t.after(() => { for (const [key, value] of [['THREATLINT_HOME', before.home], ['THREATLINT_REPO_STORE', before.root]]) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  } });
  process.env.THREATLINT_HOME = home; process.env.THREATLINT_REPO_STORE = f.external;
  assert.equal(path.dirname(createRepositoryDirectory('threatlint-scm-', { temporary: f.primary })), f.external);
});
