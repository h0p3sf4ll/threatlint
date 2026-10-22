'use strict';

/**
 * Saved ServiceNow connection in the shared Threatlint config, so the instance URL, client ID, and secret
 * are entered once. The file is ~/.threatlint/servicenow.json (%USERPROFILE%\.threatlint\servicenow.json on
 * Windows; THREATLINT_HOME overrides), created readable only by the current user, and read by both the
 * Workbench and the `threatlint` CLI. The secret never goes back to the browser: the UI only learns that
 * one is saved and shows it masked.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function configPath() {
  return path.join(process.env.THREATLINT_HOME || path.join(os.homedir(), '.threatlint'), 'servicenow.json');
}

function readServiceNow() {
  try {
    const value = JSON.parse(fs.readFileSync(configPath(), 'utf8'));
    return { instance: String(value.instance || ''), clientId: String(value.clientId || ''), clientSecret: String(value.clientSecret || '') };
  } catch { return { instance: '', clientId: '', clientSecret: '' }; }
}

function writeServiceNow(values) {
  const file = configPath();
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temp, `${JSON.stringify(values, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temp, file);
  if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
}

/** What the settings page may see: never the secret itself. */
function publicServiceNow() {
  const saved = readServiceNow();
  return { instance: saved.instance, clientId: saved.clientId, hasSecret: !!saved.clientSecret, path: configPath() };
}

function clearServiceNow() {
  try { fs.unlinkSync(configPath()); return true; } catch { return false; }
}

// Semgrep API token, shared with `threatlint semgrep login`. A token the CLI put in the OS credential store
// ("storage": "keyring") is not readable here; the settings page can save one to the file instead.
function semgrepPath() { return path.join(path.dirname(configPath()), 'semgrep.json'); }
function readSemgrep() {
  try { const value = JSON.parse(fs.readFileSync(semgrepPath(), 'utf8')); return { token: String(value.token || ''), deployment: String(value.deployment || ''), storage: String(value.storage || '') }; }
  catch { return { token: '', deployment: '', storage: '' }; }
}
function writeSemgrep(values) {
  const file = semgrepPath();
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temp, `${JSON.stringify({ ...values, storage: 'file' }, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temp, file);
  if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
}
function publicSemgrep() {
  const saved = readSemgrep();
  return { hasToken: !!saved.token || saved.storage === 'keyring', inKeyring: saved.storage === 'keyring' && !saved.token, deployment: saved.deployment, path: semgrepPath() };
}

module.exports = { configPath, readServiceNow, writeServiceNow, publicServiceNow, clearServiceNow, readSemgrep, writeSemgrep, publicSemgrep };
