'use strict';

/**
 * Launch-time updater for packaged builds. The stamp written by scripts/desktop-sync.cjs records the
 * checkout the app was built from; when that checkout's fingerprint no longer matches the stamp, the
 * splash window stays up while a fresh unpacked app is built beside this one, swapped in, and relaunched.
 */

const { app, BrowserWindow } = require('electron');
const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const RELAUNCHED = '--threatlint-updated';

function createSplash() {
  const splash = new BrowserWindow({
    width: 440, height: 260, frame: false, resizable: false, movable: true, show: false,
    backgroundColor: '#101617', alwaysOnTop: false, skipTaskbar: false, title: 'Threatlint',
    webPreferences: { preload: path.join(__dirname, 'splash-preload.cjs'), nodeIntegration: false, contextIsolation: true, sandbox: true },
  });
  splash.once('ready-to-show', () => splash.show());
  const ready = splash.loadFile(path.join(__dirname, 'splash.html'));
  const status = (title, detail = '') => ready.then(() => { if (!splash.isDestroyed()) splash.webContents.send('splash:status', { title, detail }); });
  return { window: splash, status, close: () => { if (!splash.isDestroyed()) splash.close(); } };
}

// Apps opened from Finder or a desktop launcher get a minimal PATH; the build needs the user's node/npm.
function userEnvironment() {
  const env = { ...process.env };
  if (process.platform !== 'win32') {
    const shell = process.env.SHELL || '/bin/zsh';
    const probe = spawnSync(shell, ['-ilc', 'printf "__PATH__%s" "$PATH"'], { encoding: 'utf8', timeout: 8000 });
    const found = /__PATH__(.*)$/s.exec(probe.stdout || '')?.[1]?.trim();
    env.PATH = [found, env.PATH, '/opt/homebrew/bin', '/usr/local/bin'].filter(Boolean).join(path.delimiter);
  }
  const node = env.PATH.split(path.delimiter).map(dir => path.join(dir, process.platform === 'win32' ? 'node.exe' : 'node')).find(file => fs.existsSync(file));
  if (node) { delete env.ELECTRON_RUN_AS_NODE; return { env, node }; }
  // No system Node: Electron's bundled Node runs the build scripts instead.
  return { env: { ...env, ELECTRON_RUN_AS_NODE: '1' }, node: process.execPath };
}

function runScript(runtime, source, args, onLine) {
  return new Promise((resolve, reject) => {
    const child = spawn(runtime.node, [path.join(source, 'scripts/desktop-sync.cjs'), ...args], { cwd: source, env: { ...runtime.env, CSC_IDENTITY_AUTO_DISCOVERY: runtime.env.CSC_IDENTITY_AUTO_DISCOVERY ?? 'false' } });
    let output = '', pending = '';
    const collect = chunk => {
      output += chunk; pending += chunk;
      const lines = pending.split(/\r?\n/); pending = lines.pop();
      for (const line of lines) if (line.trim()) onLine?.(line.trim());
    };
    child.stdout.on('data', collect); child.stderr.on('data', collect);
    child.on('error', reject);
    child.on('close', code => (code === 0 ? resolve(output) : reject(new Error(`desktop-sync ${args[0]} exited with ${code}`))));
  });
}

// The directory the user launches: Threatlint.app on macOS, the unpacked folder elsewhere.
function installedBundle() {
  return process.platform === 'darwin' ? path.resolve(process.resourcesPath, '..', '..') : path.dirname(process.execPath);
}

function swapAndRelaunch(staged, bundle) {
  const previous = `${bundle}.previous`;
  if (process.platform === 'win32') {
    // A running executable cannot be replaced on Windows; a detached helper copies once this process exits.
    const exe = path.join(bundle, path.basename(process.execPath));
    const script = `$p=${process.pid}; while (Get-Process -Id $p -ErrorAction SilentlyContinue) { Start-Sleep -Milliseconds 200 }; ` +
      `robocopy '${staged}' '${bundle}' /MIR /NFL /NDL /NJH /NJS | Out-Null; Start-Process '${exe}' -ArgumentList '${RELAUNCHED}'`;
    spawn('powershell.exe', ['-NoProfile', '-WindowStyle', 'Hidden', '-Command', script], { detached: true, stdio: 'ignore' }).unref();
    app.exit(0);
    return;
  }
  // POSIX keeps this process's open files alive by inode, so the bundle can be renamed out from under it.
  fs.rmSync(previous, { recursive: true, force: true });
  fs.renameSync(bundle, previous);
  try { fs.renameSync(staged, bundle); } catch (error) { fs.renameSync(previous, bundle); throw error; }
  app.relaunch({ execPath: process.execPath, args: [...process.argv.slice(1).filter(arg => arg !== RELAUNCHED), RELAUNCHED] });
  app.exit(0);
}

/**
 * Resolves to true when the app is current (or cannot update) and startup should continue;
 * never resolves when an update was installed, because the process exits to relaunch.
 */
async function updateOnLaunch(info, splash, log) {
  const bundle = installedBundle();
  const stageDir = path.join(path.dirname(bundle), '.threatlint-update');
  // Leftovers from the previous update; the old process has exited by the time this one runs.
  for (const leftover of [`${bundle}.previous`, stageDir]) {
    try { fs.rmSync(leftover, { recursive: true, force: true, maxRetries: 3 }); } catch (error) { log(`Could not remove ${leftover}: ${error.message}`); }
  }
  if (process.env.THREATLINT_SKIP_UPDATE === '1') return true;
  const source = info.source;
  if (!source || !fs.existsSync(path.join(source, 'scripts/desktop-sync.cjs')) || !fs.existsSync(path.join(source, 'node_modules/electron-builder'))) {
    log(`No source checkout recorded for this build (${source || 'none'}); skipping update check.`);
    return true;
  }
  splash.status('Checking for updates…', `Build ${info.commit} · ${info.fingerprint}`);
  const runtime = userEnvironment();
  const current = JSON.parse((await runScript(runtime, source, ['current'])).trim().split('\n').pop());
  log(`Installed ${info.fingerprint} (${info.commit}); source ${current.fingerprint} (${current.commit}).`);
  if (current.fingerprint === info.fingerprint) return true;
  if (process.argv.includes(RELAUNCHED)) {
    log('Source changed again right after an update; continuing with the build just installed.');
    return true;
  }
  splash.status('Updating Threatlint…', `${info.commit} → ${current.commit}`);
  const output = await runScript(runtime, source, ['stage', stageDir], line => { log(line); splash.status('Updating Threatlint…', line.slice(0, 120)); });
  const staged = /^STAGED (.+)$/m.exec(output)?.[1];
  if (!staged || !fs.existsSync(staged)) throw new Error('The rebuilt app could not be found');
  splash.status('Restarting…', current.commit);
  swapAndRelaunch(staged, bundle);
  return new Promise(() => {});
}

module.exports = { createSplash, updateOnLaunch };
