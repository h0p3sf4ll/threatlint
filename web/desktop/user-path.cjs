'use strict';

/**
 * Apps opened from Finder, the Dock, Spotlight, or a desktop launcher start with a minimal PATH
 * (/usr/bin:/bin:/usr/sbin:/sbin on macOS), not the one a terminal has. Without the user's PATH, the Workbench
 * cannot find Homebrew's Semgrep, the Python that has python-docx (Word export), git, or node for self-updates.
 * userPath() asks the login shell for its PATH once and merges it ahead of the inherited one.
 * Windows launchers can keep an old environment after an installer updates User PATH. Read that
 * one registry value at startup and append new entries without changing inherited precedence.
 */

const { spawnSync } = require('node:child_process');
const path = require('node:path');

const PROBE_TIMEOUT_MS = 8000;
const COMMON_DIRS = ['/opt/homebrew/bin', '/usr/local/bin'];
const WINDOWS_PATH_SCRIPT = "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); $value = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($null -ne $value) { [Console]::Out.Write($value) }";

// Windows environment names are case-insensitive, including copied plain objects.
const pathKey = (env, platform) => platform === 'win32'
  ? Object.keys(env).find(key => key.toUpperCase() === 'PATH') || 'PATH' : 'PATH';
const environmentValue = (env, name) => {
  const key = Object.keys(env).find(candidate => candidate.toUpperCase() === name.toUpperCase());
  return key === undefined ? undefined : env[key];
};

/** Read only HKCU's Path through a fixed UTF-8 command, never a login shell or registry write. */
function windowsRegistryPath({ env = process.env, spawnSyncImpl = spawnSync } = {}) {
  const systemRoot = environmentValue(env, 'SystemRoot') || 'C:\\Windows';
  if (!/^[a-z]:[\\/]/i.test(systemRoot)) return '';
  const executable = path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  try {
    const probe = spawnSyncImpl(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', WINDOWS_PATH_SCRIPT], {
      env, encoding: 'utf8', timeout: PROBE_TIMEOUT_MS, maxBuffer: 65536, windowsHide: true, shell: false,
    });
    if (probe.error || probe.status !== 0 || typeof probe.stdout !== 'string' ||
        probe.stdout.length > 65536 || /[\0\r\n]/.test(probe.stdout)) return '';
    return probe.stdout.replace(/^\uFEFF/, '').trim();
  } catch { return ''; }
}

function expandWindowsVariables(value, env) {
  for (let round = 0; round < 8; round++) {
    const expanded = value.replace(/%([^%]+)%/g, (reference, name) => {
      const replacement = environmentValue(env, name);
      return typeof replacement === 'string' ? replacement : reference;
    });
    if (expanded === value) break;
    if (expanded.length > 65536) return '';
    value = expanded;
  }
  return value;
}

function windowsUserPath(options) {
  const inherited = options.env[pathKey(options.env, 'win32')] || '';
  const fresh = expandWindowsVariables(windowsRegistryPath(options), options.env);
  if (!fresh) return inherited;
  const seen = new Set();
  return [inherited, fresh].flatMap(value => value.split(';')).map(value => value.trim()).filter(value => {
    if (!value) return false;
    const normalized = path.win32.normalize(value.replace(/^"(.*)"$/, '$1'));
    const key = (normalized.length > path.win32.parse(normalized).root.length
      ? normalized.replace(/[\\/]+$/, '') : normalized).toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key); return true;
  }).join(';');
}

/** The login shell's PATH, or '' when it cannot be read (the shell is printed between markers to skip rc noise). */
function loginShellPath({ shell = process.env.SHELL || '/bin/zsh', spawnSyncImpl = spawnSync } = {}) {
  const probe = spawnSyncImpl(shell, ['-ilc', 'printf "__PATH__%s__END__" "$PATH"'], { encoding: 'utf8', timeout: PROBE_TIMEOUT_MS });
  return /__PATH__(.*?)__END__/s.exec(probe.stdout || '')?.[1]?.trim() || '';
}

/** The user's PATH: login shell entries first, then the inherited ones and common install dirs, without duplicates. */
function userPath({ env = process.env, platform = process.platform, ...probe } = {}) {
  if (platform === 'win32') return windowsUserPath({ env, ...probe });
  // The supplied platform owns PATH syntax; it may differ from this process's host in tests.
  const delimiter = path.posix.delimiter;
  const entries = [loginShellPath(probe), env.PATH, ...COMMON_DIRS].filter(Boolean).flatMap(value => value.split(delimiter));
  return [...new Set(entries.filter(Boolean))].join(delimiter);
}

/** Adopts the user's PATH for this process and everything it starts. */
function adoptUserPath(options = {}) {
  const env = options.env || process.env;
  const key = pathKey(env, options.platform || process.platform);
  env[key] = userPath({ ...options, env });
  return env[key];
}

module.exports = { loginShellPath, windowsRegistryPath, userPath, adoptUserPath };
