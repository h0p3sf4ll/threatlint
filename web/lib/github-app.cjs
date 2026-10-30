'use strict';

/**
 * GitHub App source for the Workbench, shared with `threatlint github login`.
 *
 * Settings live in ~/.threatlint/github-app.json (THREATLINT_HOME relocates it; the THREATLINT_GITHUB_APP_ID,
 * THREATLINT_GITHUB_APP_INSTALLATION_ID, THREATLINT_GITHUB_APP_PRIVATE_KEY_FILE, and THREATLINT_GITHUB_API_URL
 * environment variables override it), readable only by the current user:
 *   { "appId": "...", "installationId": "...", "privateKeyFile": "/path/to/app.pem", "apiUrl": "https://api.github.com" }
 * Only the key's path is stored. The key is read from that file when a token is minted, the App JWT is signed
 * here with node:crypto (RS256), and the installation token is cached in memory until five minutes before it
 * expires. Neither the key, the JWT, nor the token is ever returned to the browser; the settings page only
 * learns which values are set.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const DEFAULT_API_URL = 'https://api.github.com';
const REFRESH_MARGIN_MS = 5 * 60_000;
const JWT_BACKDATE_S = 60;
const JWT_LIFETIME_S = 540;
const TIMEOUT_MS = 15_000;
const APP_ID = /^[A-Za-z0-9.]{1,64}$/;
const INSTALLATION_ID = /^[0-9]{1,20}$/;
const ENV = { appId: 'THREATLINT_GITHUB_APP_ID', installationId: 'THREATLINT_GITHUB_APP_INSTALLATION_ID',
  privateKeyFile: 'THREATLINT_GITHUB_APP_PRIVATE_KEY_FILE', apiUrl: 'THREATLINT_GITHUB_API_URL' };
const PERMISSIONS = 'Metadata: read; Contents: read (Pull requests and Issues: read & write only for PR comments and issues)';

class GitHubAppError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}

function configPath() {
  return path.join(process.env.THREATLINT_HOME || path.join(os.homedir(), '.threatlint'), 'github-app.json');
}

function readSaved() {
  try {
    const value = JSON.parse(fs.readFileSync(configPath(), 'utf8'));
    return Object.fromEntries(Object.keys(ENV).map(key => [key, String(value?.[key] || '').trim()]));
  } catch { return { appId: '', installationId: '', privateKeyFile: '', apiUrl: '' }; }
}

/** Environment over the saved file; null when no App is configured. */
function readConfig() {
  const saved = readSaved();
  const config = Object.fromEntries(Object.entries(ENV).map(([key, name]) => [key, (process.env[name] || '').trim() || saved[key]]));
  config.apiUrl ||= DEFAULT_API_URL;
  return config.appId && config.installationId && config.privateKeyFile ? config : null;
}

function validateApiUrl(value) {
  let url;
  try { url = new URL(String(value || '').trim()); } catch { throw new GitHubAppError('The GitHub API URL must be an https:// URL'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new GitHubAppError('The GitHub API URL must be an https:// URL without credentials, query, or fragment');
  return `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
}

function validate(config) {
  if (!APP_ID.test(config.appId || '')) throw new GitHubAppError('The GitHub App ID is not valid (digits, or the App\'s client ID)');
  if (!INSTALLATION_ID.test(config.installationId || '')) throw new GitHubAppError('The installation ID must be digits');
  if (!path.isAbsolute(config.privateKeyFile || '')) throw new GitHubAppError('Enter the absolute path to the App\'s private key (.pem)');
  return { ...config, apiUrl: validateApiUrl(config.apiUrl || DEFAULT_API_URL) };
}

function base64url(value) { return Buffer.from(value).toString('base64url'); }

/** RS256 App JWT: iat = now - 60 s, exp = now + 9 min, iss = App ID. */
function appJwt(config, nowMs = Date.now()) {
  let key;
  try { key = fs.readFileSync(config.privateKeyFile, 'utf8'); } catch { throw new GitHubAppError('The GitHub App private key file is set but cannot be read'); }
  const issued = Math.floor(nowMs / 1000);
  const input = `${base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))}.${base64url(JSON.stringify({ iat: issued - JWT_BACKDATE_S, exp: issued + JWT_LIFETIME_S, iss: config.appId }))}`;
  try {
    return `${input}.${crypto.createSign('RSA-SHA256').update(input).sign(key, 'base64url')}`;
  } catch { throw new GitHubAppError('The GitHub App private key could not sign the JWT; use the App\'s PEM key'); }
}

function createGitHubApp({ fetch: fetchImpl = globalThis.fetch, now = Date.now } = {}) {
  const cache = new Map();

  async function request(method, url, authorization) {
    let response;
    try {
      response = await fetchImpl(url, { method, redirect: 'error', signal: AbortSignal.timeout(TIMEOUT_MS),
        headers: { Authorization: authorization, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'threatlint-workbench' } });
    } catch { throw new GitHubAppError('GitHub could not be reached (redirects are refused)', 502); }
    if (!response.ok) {
      const hint = { 401: ' (the App ID or private key was rejected)', 403: ' (the App lacks permission)', 404: ' (the installation was not found)' }[response.status] || '';
      throw new GitHubAppError(`GitHub API request failed: HTTP ${response.status}${hint}`, response.status === 401 || response.status === 404 ? 400 : 502);
    }
    try { return await response.json(); } catch { throw new GitHubAppError('GitHub returned a response that is not JSON', 502); }
  }

  /** { token, expiresAt } for the configured (or given) App; cached until five minutes before expiry. Server-side only. */
  async function installationToken(input = readConfig()) {
    if (!input) throw new GitHubAppError('No GitHub App is configured', 404);
    const config = validate(input);
    const key = `${config.apiUrl}\n${config.appId}\n${config.installationId}\n${config.privateKeyFile}`;
    const cached = cache.get(key);
    if (cached && cached.expiresAt - REFRESH_MARGIN_MS > now()) return cached;
    const data = await request('POST', `${config.apiUrl}/app/installations/${config.installationId}/access_tokens`, `Bearer ${appJwt(config, now())}`);
    if (typeof data?.token !== 'string' || !data.token) throw new GitHubAppError('GitHub did not return an installation token', 502);
    const expiresAt = Date.parse(data.expires_at) || now() + 3_600_000;
    const entry = { token: data.token, expiresAt };
    cache.set(key, entry);
    return entry;
  }

  /** Repositories visible to the installation (count and first owner), to validate settings. */
  async function check(input = readConfig()) {
    const config = validate(input || {});
    const { token } = await installationToken(config);
    const data = await request('GET', `${config.apiUrl}/installation/repositories?per_page=1`, `Bearer ${token}`);
    const owner = Array.isArray(data?.repositories) ? String(data.repositories[0]?.owner?.login || '') : '';
    return { repositories: Number(data?.total_count) || 0, owner };
  }

  /** What the settings page may see: which values are set, never the IDs' use, the key, or a token. */
  function publicStatus() {
    const config = readConfig();
    const saved = readSaved();
    return { configured: !!config, appIdSet: !!config?.appId, installationIdSet: !!config?.installationId, privateKeyFileSet: !!config?.privateKeyFile,
      apiUrl: config?.apiUrl || saved.apiUrl || DEFAULT_API_URL, fromEnvironment: Object.values(ENV).some(name => !!process.env[name]),
      path: configPath(), permissions: PERMISSIONS };
  }

  /** Validate (by minting a token and listing one repository), then save. Blank fields keep the saved values. */
  async function save(body = {}) {
    const saved = readSaved();
    const field = name => (typeof body[name] === 'string' && body[name].trim() ? body[name].trim() : saved[name]);
    const config = validate({ appId: field('appId'), installationId: field('installationId'),
      privateKeyFile: (field('privateKeyFile') || '').replace(/^~(?=\/|$)/, os.homedir()), apiUrl: field('apiUrl') || DEFAULT_API_URL });
    if (!fs.existsSync(config.privateKeyFile)) throw new GitHubAppError('The private key file does not exist');
    const result = await check(config);
    const file = configPath();
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const temp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(temp, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(temp, file);
    if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
    return { ...publicStatus(), ...result };
  }

  function clear() {
    cache.clear();
    try { fs.unlinkSync(configPath()); return true; } catch { return false; }
  }

  return { installationToken, check, publicStatus, save, clear, configured: () => !!readConfig() };
}

module.exports = { createGitHubApp, appJwt, readConfig, configPath, validateApiUrl, GitHubAppError, DEFAULT_API_URL };
