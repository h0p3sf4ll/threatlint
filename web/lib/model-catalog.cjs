'use strict';

/**
 * Model lists for the settings dropdown, and provider credentials resolved from where each tool
 * normally keeps them. Resolution order: the key typed for this session, then the process
 * environment, then that tool's own configuration:
 *   Anthropic: ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN (and ANTHROPIC_BASE_URL for a gateway), then the `env` block of ~/.claude/settings.json
 *              (%USERPROFILE%\.claude\settings.json on Windows). Claude Code's subscription OAuth login
 *              (macOS Keychain / ~/.claude/.credentials.json) is never read.
 *   OpenAI:    OPENAI_API_KEY.
 *   Copilot:   COPILOT_GITHUB_TOKEN / GH_TOKEN / GITHUB_TOKEN, then `gh auth token` (the GitHub CLI sign-in).
 * Keys never leave this process except to the provider's own API; the UI only learns which source exists.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { HttpError } = require('./http.cjs');

const execFileAsync = promisify(execFile);
const LIST_TIMEOUT_MS = 8000;
const COPILOT_API = 'https://api.githubcopilot.com';
const ANTHROPIC_API = 'https://api.anthropic.com';
const OPENAI_API = 'https://api.openai.com/v1';
// Copilot requires an editor identity on every request.
const COPILOT_HEADERS = { 'Copilot-Integration-Id': 'vscode-chat', 'Editor-Version': 'Threatlint/1.0' };

function claudeSettingsEnv(home = os.homedir()) {
  try {
    const env = JSON.parse(fs.readFileSync(path.join(home, '.claude', 'settings.json'), 'utf8')).env;
    return env && typeof env === 'object' ? env : {};
  } catch { return {}; }
}

/** ANTHROPIC_BASE_URL as Claude Code sees it (environment, then settings.json); HTTPS or loopback only. */
function anthropicBaseUrl({ env = process.env, home = os.homedir() } = {}) {
  const value = env.ANTHROPIC_BASE_URL || claudeSettingsEnv(home).ANTHROPIC_BASE_URL;
  if (!value) return ANTHROPIC_API;
  let url;
  try { url = new URL(value); } catch { throw new HttpError('ANTHROPIC_BASE_URL is not a valid URL', 500); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.username || url.password || url.search || url.hash || !(url.protocol === 'https:' || (url.protocol === 'http:' && loopback))) throw new HttpError('ANTHROPIC_BASE_URL must be HTTPS (or loopback HTTP) without credentials', 500);
  return url.toString().replace(/\/$/, '');
}

async function ghToken(run = execFileAsync) {
  try { return (await run('gh', ['auth', 'token'], { timeout: LIST_TIMEOUT_MS, windowsHide: true })).stdout.trim() || ''; } catch { return ''; }
}

// Last GitHub CLI token seen; refreshed whenever Copilot models are listed so providerRequest can stay synchronous.
let cachedGhToken = '';

/** Keys known without running a process: session, environment, ~/.claude/settings.json, and the cached gh token. */
function configuredKey(provider, sessionKey, { env = process.env, home = os.homedir() } = {}) {
  if (typeof sessionKey === 'string' && sessionKey.trim()) return { key: sessionKey.trim(), source: 'session', ...(provider === 'claude' ? { baseUrl: anthropicBaseUrl({ env, home }) } : {}) };
  if (provider === 'claude') {
    const baseUrl = anthropicBaseUrl({ env, home });
    const gateway = baseUrl === ANTHROPIC_API ? '' : ` via ${new URL(baseUrl).host}`;
    if (env.ANTHROPIC_API_KEY) return { key: env.ANTHROPIC_API_KEY, source: `ANTHROPIC_API_KEY${gateway}`, baseUrl };
    const settings = claudeSettingsEnv(home);
    for (const name of ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN']) {
      if (typeof settings[name] === 'string' && settings[name]) return { key: settings[name], source: `~/.claude/settings.json (${name})${gateway}`, bearer: name === 'ANTHROPIC_AUTH_TOKEN', baseUrl };
    }
    if (env.ANTHROPIC_AUTH_TOKEN) return { key: env.ANTHROPIC_AUTH_TOKEN, source: `ANTHROPIC_AUTH_TOKEN${gateway}`, bearer: true, baseUrl };
  }
  if (provider === 'openai' && env.OPENAI_API_KEY) return { key: env.OPENAI_API_KEY, source: 'OPENAI_API_KEY' };
  if (provider === 'copilot') {
    for (const name of ['COPILOT_GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN']) if (env[name]) return { key: env[name], source: name };
    if (cachedGhToken) return { key: cachedGhToken, source: 'GitHub CLI (gh auth token)' };
  }
  return { key: '', source: null };
}

/** { key, source } for a provider; key is '' when nothing is configured. */
async function resolveKey(provider, sessionKey, { env = process.env, home = os.homedir(), run } = {}) {
  const known = configuredKey(provider, sessionKey, { env, home });
  if (known.key || provider !== 'copilot') return known;
  cachedGhToken = await ghToken(run);
  return cachedGhToken ? { key: cachedGhToken, source: 'GitHub CLI (gh auth token)' } : known;
}

/** Which providers have a credential outside the session, by source label, for the settings UI. */
async function credentialSources(options = {}) {
  const entries = await Promise.all(['claude', 'openai', 'copilot'].map(async provider => [provider, (await resolveKey(provider, '', options)).source]));
  return Object.fromEntries(entries);
}

async function listJson(fetchImpl, url, headers) {
  let response;
  try { response = await fetchImpl(url, { headers: { Accept: 'application/json', ...headers }, redirect: 'error', signal: AbortSignal.timeout(LIST_TIMEOUT_MS) }); }
  catch (error) { throw new HttpError(`Model list request failed: ${error.cause?.message || error.message}`, 502); }
  if (!response.ok) throw new HttpError(`The provider refused to list models (HTTP ${response.status}). ${response.status === 401 || response.status === 403 ? 'Check the key or token.' : ''}`.trim(), 502);
  return response.json();
}

/** [{ id, name }] the credential can use. */
async function listModels(provider, credential, { fetchImpl = fetch } = {}) {
  if (!credential.key) throw new HttpError(`No ${provider === 'copilot' ? 'GitHub token' : 'API key'} is configured. Enter one, or set it in the environment.`, 401);
  if (provider === 'claude') {
    const headers = { 'anthropic-version': '2023-06-01', ...(credential.bearer ? { Authorization: `Bearer ${credential.key}` } : { 'x-api-key': credential.key }) };
    const models = [];
    let after = '';
    for (let page = 0; page < 5; page++) {
      const data = await listJson(fetchImpl, `${credential.baseUrl || ANTHROPIC_API}/v1/models?limit=100${after ? `&after_id=${encodeURIComponent(after)}` : ''}`, headers);
      for (const model of data.data || []) if (typeof model.id === 'string') models.push({ id: model.id, name: model.display_name || model.id });
      if (!data.has_more || !data.last_id) break;
      after = data.last_id;
    }
    return models;
  }
  if (provider === 'openai') {
    const data = await listJson(fetchImpl, `${OPENAI_API}/models`, { Authorization: `Bearer ${credential.key}` });
    // Only chat-capable families; embeddings, audio, image, and moderation models cannot run a review.
    return (data.data || []).map(model => model.id).filter(id => typeof id === 'string' && /^(gpt-|o\d|chatgpt-)/.test(id) && !/(audio|realtime|transcribe|tts|image|search|embedding)/.test(id))
      .sort().map(id => ({ id, name: id }));
  }
  if (provider === 'copilot') {
    const data = await listJson(fetchImpl, `${COPILOT_API}/models`, { Authorization: `Bearer ${credential.key}`, ...COPILOT_HEADERS });
    // Reviews need streaming /chat/completions with tool calls (some models are /responses-only);
    // picker-enabled models are the ones the user's plan allows.
    return (data.data || []).filter(model => typeof model.id === 'string' && (model.capabilities?.type ?? 'chat') === 'chat'
      && (!Array.isArray(model.supported_endpoints) || model.supported_endpoints.includes('/chat/completions'))
      && model.capabilities?.supports?.tool_calls !== false && model.model_picker_enabled !== false && model.policy?.state !== 'disabled')
      .map(model => ({ id: model.id, name: model.name || model.id }));
  }
  throw new HttpError('Unknown model provider');
}

module.exports = { anthropicBaseUrl, resolveKey, configuredKey, credentialSources, listModels, claudeSettingsEnv, COPILOT_API, COPILOT_HEADERS };
