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

module.exports = { configPath, readServiceNow, writeServiceNow, publicServiceNow, clearServiceNow };
