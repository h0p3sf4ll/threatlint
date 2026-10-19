'use strict';

// Claude model discovery from the user's existing local configuration. No VS Code API here, so it is unit-testable.
// Only sanctioned credentials are used: ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN from the environment or from the
// `env` block of ~/.claude/settings.json. Claude Code OAuth (subscription) credentials are never read; those users
// are served through the `claude` CLI, which authenticates itself.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');

const CLAUDE_ENV_KEYS = ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL'];
const DEFAULT_BASE_URL = 'https://api.anthropic.com';
// Aliases the Claude CLI resolves to the latest model in each family; used when no API key is available to list models.
const CLI_ALIASES = [
  { id: 'fable', name: 'Fable (latest)' }, { id: 'opus', name: 'Opus (latest)' },
  { id: 'sonnet', name: 'Sonnet (latest)' }, { id: 'haiku', name: 'Haiku (latest)' },
];
const REQUEST_TIMEOUT_MS = 10_000;
const CLI_TIMEOUT_MS = 300_000;
const MAX_MODEL_PAGES = 5;

function validateBaseUrl(value) {
  const url = new URL(value || DEFAULT_BASE_URL);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error('ANTHROPIC_BASE_URL must be an HTTP(S) URL without credentials or query parameters');
  if (url.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) throw new Error('ANTHROPIC_BASE_URL must use HTTPS for non-loopback hosts');
  return url.toString().replace(/\/$/, '');
}

function readSettingsEnv(home) {
  try {
    const env = JSON.parse(fs.readFileSync(path.join(home, '.claude', 'settings.json'), 'utf8')).env;
    return env && typeof env === 'object' ? env : {};
  } catch { return {}; }
}

/** Claude configuration as Claude Code would see it: settings.json `env` overrides the process environment. */
function readClaudeConfig({ env = process.env, home = os.homedir() } = {}) {
  const settings = readSettingsEnv(home);
  const pick = key => (typeof settings[key] === 'string' && settings[key]) || env[key] || '';
  const [apiKey, authToken, baseUrl] = CLAUDE_ENV_KEYS.map(pick);
  return { apiKey, authToken, baseUrl: validateBaseUrl(baseUrl), configured: !!(apiKey || authToken) || fs.existsSync(path.join(home, '.claude')) };
}

function authHeaders(config) {
  return { 'anthropic-version': '2023-06-01', ...(config.apiKey ? { 'x-api-key': config.apiKey } : { Authorization: `Bearer ${config.authToken}` }) };
}

async function listClaudeApiModels(config, fetchImpl = fetch) {
  const models = [];
  let after = '';
  for (let page = 0; page < MAX_MODEL_PAGES; page++) {
    const response = await fetchImpl(`${config.baseUrl}/v1/models?limit=100${after ? `&after_id=${encodeURIComponent(after)}` : ''}`,
      { headers: authHeaders(config), redirect: 'error', signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    if (!response.ok) throw new Error(`Claude model list failed (HTTP ${response.status}). Check the configured key and base URL.`);
    const data = await response.json();
    for (const model of data.data || []) if (typeof model.id === 'string') models.push({ id: model.id, name: model.display_name || model.id });
    if (!data.has_more || !data.last_id) break;
    after = data.last_id;
  }
  return models;
}

function runFile(file, args, { input, cwd, timeout } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(file, args, { cwd, timeout, windowsHide: true, maxBuffer: 8 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error) reject(Object.assign(new Error((stderr || error.message).trim()), { code: error.code })); else resolve(stdout);
    });
    if (input !== undefined) child.stdin.end(input);
  });
}

async function claudeCliAvailable(executable = 'claude') {
  try { await runFile(executable, ['--version'], { timeout: REQUEST_TIMEOUT_MS }); return true; } catch { return false; }
}

/**
 * Models for the locally configured Claude: listed from the API when a key is configured, otherwise the CLI aliases
 * when the `claude` CLI is installed. Returns { source: 'api' | 'cli' | null, models, error? }.
 */
async function discoverClaudeModels({ config = readClaudeConfig(), executable = 'claude', fetchImpl = fetch, cliCheck = claudeCliAvailable } = {}) {
  let error;
  if (config.apiKey || config.authToken) {
    try { return { source: 'api', models: await listClaudeApiModels(config, fetchImpl) }; } catch (failure) { error = failure.message; }
  }
  if (await cliCheck(executable)) return { source: 'cli', models: CLI_ALIASES, error };
  return { source: null, models: [], error };
}

/** One prompt, no tools: the Claude CLI when installed (it owns authentication), otherwise the Messages API. */
async function askClaude({ model, prompt, config = readClaudeConfig(), executable = 'claude', cwd, fetchImpl = fetch, cliCheck = claudeCliAvailable }) {
  if (await cliCheck(executable)) {
    return runFile(executable, ['-p', '--model', model, '--tools', '', '--no-session-persistence', '--output-format', 'text'],
      { input: prompt, cwd, timeout: CLI_TIMEOUT_MS });
  }
  if (!config.apiKey && !config.authToken) throw new Error('Claude is not configured. Install Claude Code or set ANTHROPIC_API_KEY.');
  const response = await fetchImpl(`${config.baseUrl}/v1/messages`, {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(CLI_TIMEOUT_MS),
    headers: { 'Content-Type': 'application/json', ...authHeaders(config) },
    body: JSON.stringify({ model, max_tokens: 4096, messages: [{ role: 'user', content: prompt }] }),
  });
  if (!response.ok) throw new Error(`Claude request failed (HTTP ${response.status}).`);
  const data = await response.json();
  return (data.content || []).filter(block => block.type === 'text').map(block => block.text).join('\n');
}

module.exports = { readClaudeConfig, discoverClaudeModels, listClaudeApiModels, askClaude, validateBaseUrl, CLI_ALIASES };
