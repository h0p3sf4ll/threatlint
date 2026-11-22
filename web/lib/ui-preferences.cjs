'use strict';

/** Presentation choices live with each Workbench profile, independently of browser origin. */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { HttpError } = require('./http.cjs');

const MAX_FILE_BYTES = 1024;
function normalizeUiPreferences(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== 1 || !Object.hasOwn(value, 'experience') ||
      !['guided', 'advanced'].includes(value.experience)) {
    throw new HttpError('UI preferences require only experience: guided or advanced');
  }
  return { experience: value.experience };
}

function createUiPreferences(directory) {
  const filename = directory ? path.join(directory, 'ui-preferences.json') : null;
  let memory = null;

  function read() {
    if (!filename) return structuredClone(memory);
    let raw;
    try {
      const info = fs.lstatSync(filename);
      if (!info.isFile() || info.size > MAX_FILE_BYTES) throw new Error('Invalid UI preferences file');
      raw = fs.readFileSync(filename, 'utf8');
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw new HttpError('Saved UI preferences could not be read; the original file was preserved', 500);
    }
    try { return normalizeUiPreferences(JSON.parse(raw)); }
    catch { throw new HttpError('Saved UI preferences are invalid; the original file was preserved', 500); }
  }

  function save(value) {
    const normalized = normalizeUiPreferences(value);
    // An unreadable or corrupt existing preference is never silently replaced.
    read();
    if (!filename) { memory = normalized; return structuredClone(memory); }
    const temporary = `${filename}.${crypto.randomUUID()}.tmp`;
    try {
      fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
      fs.writeFileSync(temporary, JSON.stringify(normalized, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
      fs.renameSync(temporary, filename);
    } catch {
      try { fs.unlinkSync(temporary); } catch { /* A failed write may not create a temporary file. */ }
      throw new HttpError('UI preferences could not be saved; previous preferences were preserved', 500);
    }
    return normalized;
  }

  return { read, save };
}

module.exports = { createUiPreferences, normalizeUiPreferences };
