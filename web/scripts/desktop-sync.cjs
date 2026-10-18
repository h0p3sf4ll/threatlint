'use strict';

/**
 * Keeps the packaged Electron app in step with the shared workbench code.
 *
 *   node scripts/desktop-sync.cjs stamp    write build-assets/build-info.json (run before packaging)
 *   node scripts/desktop-sync.cjs verify   exit 1 if web/release holds a build of older code
 *   node scripts/desktop-sync.cjs ensure   repackage (electron-builder --dir) only when stale
 *
 * The fingerprint hashes every file electron-builder packages: server.js, lib/, public/,
 * desktop/, examples/, package.json, package-lock.json, and ../src/threatlint/data.
 */

const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const WEB = path.resolve(__dirname, '..');
const INPUTS = ['server.js', 'package.json', 'package-lock.json', 'lib', 'public', 'desktop', 'examples', '../src/threatlint/data'];
const INFO = path.join(WEB, 'build-assets/build-info.json');

function files(entry) {
  const absolute = path.join(WEB, entry);
  if (!fs.existsSync(absolute)) return [];
  if (fs.statSync(absolute).isFile()) return [absolute];
  return fs.readdirSync(absolute, { recursive: true, withFileTypes: true })
    .filter(item => item.isFile() && item.name !== '.DS_Store' && !item.parentPath.includes('__pycache__'))
    .map(item => path.join(item.parentPath, item.name));
}

function fingerprint() {
  const hash = crypto.createHash('sha256');
  for (const file of INPUTS.flatMap(files).sort()) {
    hash.update(path.relative(WEB, file)).update('\0').update(fs.readFileSync(file)).update('\0');
  }
  return hash.digest('hex').slice(0, 16);
}

function commit() {
  try { return execFileSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: WEB, encoding: 'utf8' }).trim(); } catch { return 'unknown'; }
}

function packagedInfo() {
  const release = path.join(WEB, 'release');
  if (!fs.existsSync(release)) return null;
  const candidates = fs.readdirSync(release).flatMap(dir => [
    path.join(release, dir, 'Threatlint.app/Contents/Resources/build-info.json'),
    path.join(release, dir, 'resources/build-info.json'),
  ]);
  const found = candidates.filter(file => fs.existsSync(file)).sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)[0];
  return found ? { file: found, ...JSON.parse(fs.readFileSync(found, 'utf8')) } : { file: null, fingerprint: null };
}

const command = process.argv[2];
if (command === 'stamp') {
  const info = { fingerprint: fingerprint(), commit: commit(), version: require('../package.json').version, builtAt: new Date().toISOString() };
  fs.mkdirSync(path.dirname(INFO), { recursive: true });
  fs.writeFileSync(INFO, `${JSON.stringify(info, null, 2)}\n`);
  console.log(`Desktop build stamped: ${info.version} · ${info.commit} · ${info.fingerprint}`);
} else if (command === 'verify' || command === 'ensure') {
  const current = fingerprint(), packaged = packagedInfo();
  const fresh = packaged?.fingerprint === current;
  if (fresh) { console.log(`Packaged desktop app is current (${current}).`); process.exit(0); }
  console.log(packaged ? `Packaged desktop app is stale: built ${packaged.fingerprint || 'without a stamp'}, code is ${current}.` : 'No packaged desktop app found in web/release.');
  if (command === 'verify') process.exit(1);
  execFileSync('npm', ['run', 'desktop:pack'], { cwd: WEB, stdio: 'inherit' });
} else {
  console.error('Usage: desktop-sync.cjs stamp | verify | ensure');
  process.exit(2);
}
