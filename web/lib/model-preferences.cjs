'use strict';

/** Non-secret model choices live with the Workbench, independent of its HTTP port. */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { HttpError } = require('./http.cjs');
const { validateBaseUrl } = require('./providers.cjs');

const PROVIDERS = new Set(['lmstudio', 'claude', 'claude-code', 'bedrock', 'daybreak', 'daybreak-bedrock', 'openai', 'codex', 'copilot']);
const FIELDS = new Set(['provider', 'models', 'codexDaybreak', 'bedrockRegion', 'lmstudioUrl']);
const MAX_FILE_BYTES = 32 * 1024;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

function normalizePreferences(value) {
  if (!object(value) || Object.keys(value).some(key => !FIELDS.has(key))) throw new HttpError('Model preferences contain unsupported fields');
  if (typeof value.provider !== 'string' || !PROVIDERS.has(value.provider)) throw new HttpError('Choose a valid model provider');
  if (!object(value.models) || Object.keys(value.models).some(key => !PROVIDERS.has(key))) throw new HttpError('Model preferences need a valid model map');
  const models = {};
  for (const [provider, model] of Object.entries(value.models)) {
    if (typeof model !== 'string' || model.length > 200 || /[\x00-\x1f\x7f]/.test(model)) throw new HttpError('Model IDs must be text of at most 200 characters');
    models[provider] = model.trim();
  }
  if (value.codexDaybreak !== undefined && typeof value.codexDaybreak !== 'boolean') throw new HttpError('Codex Daybreak preference must be true or false');
  const bedrockRegion = value.bedrockRegion === undefined ? '' : value.bedrockRegion;
  if (typeof bedrockRegion !== 'string' || bedrockRegion.length > 64
      || (bedrockRegion.trim() && !/^[a-z]{2,5}(?:-[a-z0-9]+)+-\d{1,2}$/.test(bedrockRegion.trim()))) throw new HttpError('Enter a valid AWS region');
  if (value.lmstudioUrl !== undefined && (typeof value.lmstudioUrl !== 'string' || value.lmstudioUrl.length > 2048)) throw new HttpError('Enter a valid model-server URL');
  let lmstudioUrl;
  try { lmstudioUrl = validateBaseUrl(value.lmstudioUrl); }
  catch { throw new HttpError('Use a model-server URL without credentials, query, or fragment; remote servers require HTTPS'); }
  return { provider: value.provider, models, codexDaybreak: value.codexDaybreak ?? false, bedrockRegion: bedrockRegion.trim(), lmstudioUrl };
}

function createModelPreferences(directory) {
  const filename = directory ? path.join(directory, 'model-preferences.json') : null;
  let memory = null;

  function read() {
    if (!filename) return structuredClone(memory);
    let raw;
    try {
      const stats = fs.lstatSync(filename);
      if (!stats.isFile() || stats.size > MAX_FILE_BYTES) throw new Error('Invalid preferences file');
      raw = fs.readFileSync(filename, 'utf8');
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw new HttpError('Saved model preferences could not be read; the original file was preserved', 500);
    }
    try { return normalizePreferences(JSON.parse(raw)); }
    catch { throw new HttpError('Saved model preferences are invalid; the original file was preserved', 500); }
  }

  function save(value) {
    const normalized = normalizePreferences(value);
    // Never hide a read error by replacing an existing unreadable or damaged file.
    read();
    if (!filename) { memory = normalized; return structuredClone(memory); }
    const temporary = `${filename}.${crypto.randomUUID()}.tmp`;
    try {
      fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
      fs.writeFileSync(temporary, JSON.stringify(normalized, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
      fs.renameSync(temporary, filename);
    } catch {
      try { fs.unlinkSync(temporary); } catch { /* no temporary file may have been created */ }
      throw new HttpError('Model preferences could not be saved; previous preferences were preserved', 500);
    }
    return normalized;
  }

  return { read, save };
}

module.exports = { createModelPreferences, normalizePreferences };
