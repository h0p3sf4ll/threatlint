'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { orgValue } = require('./org-config.cjs');
const VOLUME_PARENTS = ['/Volumes', '/mnt', '/media', '/run/media'];

function mountedStorageDirectory(directory, { filesystem = fs, platform = process.platform } = {}) {
  if (platform === 'win32') return true; // realpath/stat still require the actual drive/share to exist.
  const parent = VOLUME_PARENTS.find(root => directory === root || directory.startsWith(root + '/'));
  if (!parent) return true; // Ordinary existing folders may intentionally use the primary filesystem.
  const mounts = new Set();
  try {
    const table = filesystem.readFileSync('/proc/self/mountinfo', { encoding: 'utf8' });
    if (table.length <= 1024 * 1024) for (const line of table.split('\n')) {
      const fields = line.split(/\s+/);
      if (fields.length > 5 && /^\d+$/.test(fields[0])) mounts.add(fields[4].replace(/\\([0-7]{3})/g, (_match, octal) => String.fromCharCode(parseInt(octal, 8))));
    }
  } catch { /* macOS and other systems use filesystem device boundaries below. */ }
  for (let current = directory; current === parent || current.startsWith(parent + '/'); current = path.posix.dirname(current)) {
    try {
      if (mounts.has(current)) return true; // Includes Linux bind mounts on the same device.
      if (filesystem.statSync(current).dev !== filesystem.statSync(path.posix.dirname(current)).dev) return true;
    } catch { return false; }
    if (current === parent) break;
  }
  return false;
}

/** Optional storage is an existing directory, never a mount path we create for the user. */
function repoStoreBase({ configured, filesystem = fs, platform = process.platform } = {}) {
  const value = configured === undefined ? orgValue('repoStore') : configured;
  if (typeof value !== 'string' || !value.trim()) return null;
  const expanded = value.trim().replace(/^~(?=[\\/]|$)/, os.homedir());
  let probe;
  try {
    const paths = platform === 'win32' ? path.win32 : path.posix;
    const requested = paths.resolve(expanded);
    const directory = filesystem.realpathSync(requested);
    const stat = filesystem.statSync(directory);
    if (!stat.isDirectory() || !mountedStorageDirectory(requested, { filesystem, platform })
        || !mountedStorageDirectory(directory, { filesystem, platform })) return null;
    probe = path.join(directory, `.threatlint-storage-${randomUUID()}.tmp`);
    const fd = filesystem.openSync(probe, 'wx', 0o600);
    try { filesystem.writeFileSync(fd, '1'); filesystem.fsyncSync(fd); }
    finally { filesystem.closeSync(fd); }
    filesystem.unlinkSync(probe); probe = null;
    return directory;
  } catch { return null; }
  finally { if (probe) { try { filesystem.unlinkSync(probe); } catch { /* Missing/unmounted optional storage. */ } } }
}

/** Select once, before download. The returned absolute path owns the complete checkout lifecycle. */
function createRepositoryDirectory(prefix = 'threatlint-', options = {}) {
  if (typeof prefix !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(prefix)) throw new TypeError('Invalid repository directory prefix');
  const filesystem = options.filesystem || fs;
  const base = repoStoreBase({ configured: options.configured, filesystem, platform: options.platform });
  if (base) {
    try { return filesystem.mkdtempSync(path.join(base, prefix)); }
    catch { /* The optional disk may disappear between its probe and allocation. */ }
  }
  // Do not reselect/migrate a repository after work starts. Fail here if default storage also fails.
  return filesystem.mkdtempSync(path.join(options.temporary || os.tmpdir(), prefix));
}

module.exports = { repoStoreBase, createRepositoryDirectory, mountedStorageDirectory };
