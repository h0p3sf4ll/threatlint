'use strict';

/**
 * Apps opened from Finder, the Dock, Spotlight, or a desktop launcher start with a minimal PATH
 * (/usr/bin:/bin:/usr/sbin:/sbin on macOS), not the one a terminal has. Without the user's PATH, the Workbench
 * cannot find Homebrew's Semgrep, the Python that has python-docx (Word export), git, or node for self-updates.
 * userPath() asks the login shell for its PATH once and merges it ahead of the inherited one.
 * Windows apps launched from Explorer already inherit the user's PATH, so it is left alone there.
 */

const { spawnSync } = require('node:child_process');
const path = require('node:path');

const PROBE_TIMEOUT_MS = 8000;
const COMMON_DIRS = ['/opt/homebrew/bin', '/usr/local/bin'];

/** The login shell's PATH, or '' when it cannot be read (the shell is printed between markers to skip rc noise). */
function loginShellPath({ shell = process.env.SHELL || '/bin/zsh', spawnSyncImpl = spawnSync } = {}) {
  const probe = spawnSyncImpl(shell, ['-ilc', 'printf "__PATH__%s__END__" "$PATH"'], { encoding: 'utf8', timeout: PROBE_TIMEOUT_MS });
  return /__PATH__(.*?)__END__/s.exec(probe.stdout || '')?.[1]?.trim() || '';
}

/** The user's PATH: login shell entries first, then the inherited ones and common install dirs, without duplicates. */
function userPath({ env = process.env, platform = process.platform, ...probe } = {}) {
  if (platform === 'win32') return env.PATH || '';
  const entries = [loginShellPath(probe), env.PATH, ...COMMON_DIRS].filter(Boolean).flatMap(value => value.split(path.delimiter));
  return [...new Set(entries.filter(Boolean))].join(path.delimiter);
}

/** Adopts the user's PATH for this process and everything it starts. */
function adoptUserPath(options = {}) {
  const env = options.env || process.env;
  env.PATH = userPath({ ...options, env });
  return env.PATH;
}

module.exports = { loginShellPath, userPath, adoptUserPath };
