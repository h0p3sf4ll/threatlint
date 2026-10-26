'use strict';

/**
 * Process setup so a Workbench started from Finder, the Dock, or the Start menu behaves like one started
 * from a terminal:
 *  - TLS trusts the OS certificate store as well as Node's bundled roots, so corporate TLS-inspection
 *    roots (macOS Keychain, Windows certificate store) work for model gateways and provider APIs.
 *  - Connections try IPv6 and IPv4 together (Happy Eyeballs), so hosts with unreachable IPv6 addresses do not
 *    stall until timeout.
 *  - PATH includes the user's login-shell PATH and the usual install locations, so `gh`, `git`, `az`,
 *    `aws`, and `semgrep` are found.
 * Both are idempotent and safe to call more than once.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const tls = require('node:tls');
const { spawnSync } = require('node:child_process');

let trusted = false, extended = false;

function trustSystemCertificates() {
  if (trusted || typeof tls.getCACertificates !== 'function' || typeof tls.setDefaultCACertificates !== 'function') return trusted;
  try {
    const system = tls.getCACertificates('system');
    if (system.length) tls.setDefaultCACertificates([...new Set([...tls.getCACertificates('default'), ...system])]);
    trusted = true;
  } catch { /* keep Node's defaults */ }
  return trusted;
}

function extraDirectories(env = process.env, platform = process.platform) {
  if (platform === 'win32') {
    const programs = [env.ProgramFiles, env['ProgramFiles(x86)'], env.LOCALAPPDATA && path.join(env.LOCALAPPDATA, 'Programs')].filter(Boolean);
    return [...programs.flatMap(root => ['GitHub CLI', 'Git\\cmd', 'Amazon\\AWSCLIV2', 'Microsoft SDKs\\Azure\\CLI2\\wbin'].map(dir => path.join(root, dir))),
      env.APPDATA && path.join(env.APPDATA, 'npm')].filter(Boolean);
  }
  return ['/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', path.join(os.homedir(), '.local/bin')];
}

function extendPath(env = process.env, platform = process.platform) {
  if (extended) return env.PATH;
  const parts = [];
  if (platform !== 'win32' && !process.env.NODE_TEST_CONTEXT) {
    const probe = spawnSync(env.SHELL || '/bin/zsh', ['-ilc', 'printf "__PATH__%s" "$PATH"'], { encoding: 'utf8', timeout: 5000 });
    const found = /__PATH__(.*)$/s.exec(probe.stdout || '')?.[1]?.trim();
    if (found) parts.push(...found.split(path.delimiter));
  }
  parts.push(...String(env.PATH || '').split(path.delimiter), ...extraDirectories(env, platform).filter(dir => fs.existsSync(dir)));
  env.PATH = [...new Set(parts.filter(Boolean))].join(path.delimiter);
  extended = true;
  return env.PATH;
}

function preferWorkingAddressFamily() {
  if (typeof net.setDefaultAutoSelectFamily === 'function') net.setDefaultAutoSelectFamily(true);
  if (typeof net.setDefaultAutoSelectFamilyAttemptTimeout === 'function') net.setDefaultAutoSelectFamilyAttemptTimeout(500);
}

function prepareProcess() { trustSystemCertificates(); preferWorkingAddressFamily(); extendPath(); }

module.exports = { prepareProcess, trustSystemCertificates, extendPath, extraDirectories };
