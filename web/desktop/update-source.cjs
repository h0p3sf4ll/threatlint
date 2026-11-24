'use strict';

// Updates belong in an app-owned checkout, never in the developer's working tree.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const REPOSITORY = 'https://github.com/h0p3sf4ll/threatlint.git';

function run(command, args, { cwd, env, onLine = () => {}, timeout = 120_000 }) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env, windowsHide: true,
      shell: process.platform === 'win32' && command === 'npm.cmd' });
    let pending = '', tail = '';
    const collect = chunk => {
      tail = (tail + chunk).slice(-4000);
      pending += chunk;
      const lines = pending.split(/\r?\n/); pending = lines.pop();
      for (const line of lines) if (line.trim()) onLine(line.trim());
    };
    child.stdout.on('data', collect); child.stderr.on('data', collect);
    const timer = setTimeout(() => { child.kill(); reject(new Error(`${command} timed out`)); }, timeout);
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => {
      clearTimeout(timer);
      if (pending.trim()) onLine(pending.trim());
      if (code === 0) resolve();
      else reject(new Error(`${command} exited with ${code}: ${tail.trim()}`));
    });
  });
}

async function prepareSource(directory, { env = process.env, onLine, runCommand = run } = {}) {
  fs.mkdirSync(directory, { recursive: true });
  // git init also recovers a first launch interrupted before the initial fetch.
  const options = { cwd: directory, env: { ...env, GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'core.hooksPath', GIT_CONFIG_VALUE_0: path.join(directory, '.no-hooks') }, onLine };
  await runCommand('git', ['init', '--quiet'], options);
  // Fetch HEAD from the explicit upstream URL, independent of local branch or remote configuration.
  await runCommand('git', ['fetch', '--no-tags', '--depth=1', REPOSITORY, 'HEAD'], options);
  await runCommand('git', ['reset', '--hard', 'FETCH_HEAD'], options);
  const source = path.join(directory, 'web');
  const lock = fs.readFileSync(path.join(source, 'package-lock.json'));
  const manifest = fs.readFileSync(path.join(source, 'package.json'));
  const signature = crypto.createHash('sha256').update(lock).update(manifest).update(process.platform).update(process.arch).digest('hex');
  const marker = path.join(directory, '.desktop-dependencies');
  const previous = fs.existsSync(marker) ? fs.readFileSync(marker, 'utf8') : '';
  if (previous !== signature || !fs.existsSync(path.join(source, 'node_modules/electron-builder/cli.js'))
      || !fs.existsSync(path.join(source, 'node_modules/electron/install.js'))) {
    fs.rmSync(marker, { force: true });
    await runCommand(process.platform === 'win32' ? 'npm.cmd' : 'npm',
      ['ci', '--include=dev', '--no-audit', '--no-fund'], { ...options, cwd: source, timeout: 600_000 });
    fs.writeFileSync(marker, signature);
  }
  return source;
}

async function clearAssetCaches(session) {
  await session.clearCache();
  await session.clearCodeCaches({});
  await session.clearStorageData({ storages: ['serviceworkers', 'cachestorage', 'shadercache'] });
}

module.exports = { REPOSITORY, prepareSource, clearAssetCaches };
