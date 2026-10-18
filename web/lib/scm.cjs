'use strict';

/**
 * Cloud-only, read-only source managers. No routes, persistence, or token refresh.
 * Export: createSourceManagers({ fetch?, execFile?, lookup? }) and frozen
 * SOURCE_MANAGER_CAPABILITIES. Dependencies are trusted transport/process seams:
 * fetch follows the Fetch/Response contract (including a streaming body);
 * execFile and lookup accept either Node callbacks or promise-returning functions.
 * The default HTTPS transport pins validated public DNS answers without a proxy.
 *
 * connect({ provider, token, organization? }) -> Promise<connection summary>
 * list() -> connection summaries; disconnect(id) -> boolean (idempotent).
 * repositories(id, { search?, page? }) / branches(id, repositoryId, { page? })
 *   -> Promise<{ repositories|branches, page, hasMore }>, at most 100 items.
 * IDs are opaque strings returned by discovery, scoped to one connection.
 * Search is a case-insensitive literal match across accessible name/fullName.
 * Branches are short names, not tags, revisions, or refs/heads-prefixed strings.
 * checkout(id, { repositoryId, branch? }) -> Promise<{ repoPath, tempDir,
 *   provenance: { provider, repository: fullName, branch, commit, webUrl } }>.
 * Failed/in-flight checkouts are removed on failure/disconnect. Successful
 * checkouts survive disconnect; the caller MUST remove tempDir after session use.
 * Errors expose only static message/code/status/statusCode, never a raw cause.
 *
 * Supply a GitHub fine-grained PAT or installation token with Contents: read and
 * Metadata: read, or an Azure DevOps PAT with Code: Read (vso.code). Providers do
 * not expose a universal token-permission introspection API: provisioning a
 * least-privilege token remains the caller's responsibility. All API calls here
 * are GET; no push, submodules, LFS downloads, custom hosts, or credential store.
 * ADO organization is a slug, NOT a URL; GitHub organization optionally filters
 * discovered owners. GitHub Enterprise and Azure DevOps Server are unsupported.
 */

const { randomUUID } = require('node:crypto');
const { execFile: nativeExecFile } = require('node:child_process');
const { lookup: nativeLookup } = require('node:dns');
const fs = require('node:fs/promises');
const https = require('node:https');
const { isIP } = require('node:net');
const os = require('node:os');
const path = require('node:path');

const PAGE_SIZE = 100;
const MAX_PAGE = 100;
const MAX_REPOSITORIES = PAGE_SIZE * MAX_PAGE;
const API_TIMEOUT_MS = 15_000;
const LIST_TIMEOUT_MS = 30_000;
const API_MAX_BYTES = 4 * 1024 * 1024;
const GIT_TIMEOUT_MS = 120_000;
const GIT_MAX_BUFFER = 1024 * 1024;
const MAX_CONNECTIONS = 16;
const MAX_CHECKOUTS = 4;
const CONTROLS = /[\p{Cc}\p{Cf}]/u;

const SOURCE_MANAGER_CAPABILITIES = Object.freeze({
  providers: Object.freeze({
    github: Object.freeze({ apiOrigin: 'https://api.github.com', gitOrigin: 'https://github.com', tokenPermissions: 'Contents: read; Metadata: read' }),
    'azure-devops': Object.freeze({ apiOrigin: 'https://dev.azure.com', gitOrigin: 'https://dev.azure.com', tokenPermissions: 'Code: Read (vso.code)', organizationRequired: true }),
  }),
  pageSize: PAGE_SIZE, maxPage: MAX_PAGE, maxRepositories: MAX_REPOSITORIES,
  apiTimeoutMs: API_TIMEOUT_MS, listTimeoutMs: LIST_TIMEOUT_MS, apiMaxBytes: API_MAX_BYTES,
  gitTimeoutMs: GIT_TIMEOUT_MS, gitMaxBuffer: GIT_MAX_BUFFER,
  customHosts: false, readOnly: true, credentials: 'session-memory-only',
  successfulCheckoutCleanup: 'caller',
});

const ERRORS = Object.freeze({
  SCM_INVALID_INPUT: [400, 'Invalid source manager input.'],
  SCM_INVALID_PROVIDER: [400, 'Choose GitHub or Azure DevOps cloud.'],
  SCM_INVALID_TOKEN: [400, 'A nonempty API token without whitespace or control characters is required.'],
  SCM_INVALID_ORGANIZATION: [400, 'Use an organization slug, not a URL. Azure DevOps requires an organization.'],
  SCM_INVALID_PAGE: [400, 'Page must be an integer between 1 and 100.'],
  SCM_INVALID_BRANCH: [400, 'Use a valid short branch name, not a tag or revision expression.'],
  SCM_CONNECTION_NOT_FOUND: [404, 'Source connection not found or disconnected.'],
  SCM_REPOSITORY_NOT_FOUND: [400, 'Select a repository discovered by this connection first.'],
  SCM_BRANCH_NOT_FOUND: [400, 'The selected branch is unavailable. Refresh the repository and branch lists.'],
  SCM_AUTHORIZATION_FAILED: [403, 'Source provider authentication or repository access failed. Check the token and read permissions.'],
  SCM_PROVIDER_FAILED: [502, 'Source provider request failed. Check read access and service availability.'],
  SCM_INVALID_RESPONSE: [502, 'Source provider returned an unsupported response.'],
  SCM_RESPONSE_TOO_LARGE: [502, 'Source provider response exceeded the supported size limit.'],
  SCM_LIMIT: [429, 'Source manager resource or inventory limit reached.'],
  SCM_TIMEOUT: [504, 'Source manager operation timed out.'],
  SCM_CHECKOUT_FAILED: [400, 'Repository checkout failed. Check the selected branch, read permissions, and Git availability.'],
});

class SourceManagerError extends Error {
  constructor(code, statusCode) {
    const [status, message] = ERRORS[code] || ERRORS.SCM_PROVIDER_FAILED;
    super(message);
    this.name = 'SourceManagerError';
    this.code = ERRORS[code] ? code : 'SCM_PROVIDER_FAILED';
    this.status = this.statusCode = statusCode || status;
  }
}

function failure(code, statusCode) { return new SourceManagerError(code, statusCode); }
function objectInput(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Object.keys(value).some(key => !keys.includes(key))) throw failure('SCM_INVALID_INPUT');
  return value;
}
function pageNumber(value = 1) {
  if (typeof value === 'string' && /^[1-9]\d{0,2}$/.test(value)) value = Number(value);
  if (!Number.isInteger(value) || value < 1 || value > MAX_PAGE) throw failure('SCM_INVALID_PAGE');
  return value;
}
function text(value, max = 255) {
  if (typeof value !== 'string' || !value.length || value.length > max || CONTROLS.test(value)
      || !value.isWellFormed()) throw failure('SCM_INVALID_RESPONSE');
  return value;
}
function segment(value) {
  text(value);
  if (value.trim() !== value || ['.', '..'].includes(value) || /[\\/]/.test(value)) throw failure('SCM_INVALID_RESPONSE');
  return value;
}
function encode(value) { return encodeURIComponent(value).replace(/[!'()*]/g, char => `%${char.codePointAt(0).toString(16).toUpperCase()}`); }
function githubOwner(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(value)) throw failure('SCM_INVALID_RESPONSE');
  return value;
}
function branchName(value, code = 'SCM_INVALID_BRANCH') {
  if (typeof value !== 'string' || !value.length || value.length > 255 || !value.isWellFormed()
      || CONTROLS.test(value) || /[\s~^:?*[\\]/u.test(value) || /^[-/]/.test(value)
      || /[/.]$/.test(value) || value === '@' || value === 'HEAD' || value.startsWith('refs/')
      || value.includes('..') || value.includes('@{') || value.includes('//')
      || value.split('/').some(part => part.startsWith('.') || /\.lock$/i.test(part))) throw failure(code);
  return value;
}
function repositoryKey(value) {
  if (Number.isSafeInteger(value) && value > 0) value = String(value);
  if (typeof value !== 'string' || !value.length || value.length > 255 || CONTROLS.test(value)) throw failure('SCM_REPOSITORY_NOT_FOUND');
  return value;
}
function publicRepository(repo) {
  const { id, name, fullName, defaultBranch, webUrl } = repo;
  return { id, name, fullName, defaultBranch, webUrl };
}
function summary(connection) {
  const { id, provider, label, account, host } = connection;
  return { id, provider, label, account, host };
}
function assertActive(connection) {
  if (connection.closed) throw failure('SCM_CONNECTION_NOT_FOUND');
}
function assertNonsecret(connection, value) {
  const token = connection.token;
  if (token && [token, encode(token), Buffer.from(`:${token}`).toString('base64'), Buffer.from(`x-access-token:${token}`).toString('base64')]
    .some(secret => value.includes(secret))) throw failure('SCM_INVALID_RESPONSE');
  return value;
}
function header(response, name) {
  if (typeof response.headers?.get === 'function') return response.headers.get(name);
  const key = Object.keys(response.headers || {}).find(key => key.toLowerCase() === name);
  const value = key === undefined ? null : response.headers[key];
  return Array.isArray(value) ? value.join(',') : value;
}
function discardBody(response) {
  try {
    if (typeof response?.body?.destroy === 'function') response.body.destroy();
    else response?.body?.cancel?.().catch(() => {});
  } catch { /* Do not propagate transport errors or credentials. */ }
}

async function deadline(connection, timeoutMs, work, parentSignal) {
  assertActive(connection);
  const controller = new AbortController();
  const signal = AbortSignal.any([connection.controller.signal, controller.signal, ...(parentSignal ? [parentSignal] : [])]);
  let onAbort;
  const aborted = new Promise((resolve, reject) => {
    onAbort = () => reject(failure(connection.closed ? 'SCM_CONNECTION_NOT_FOUND' : 'SCM_TIMEOUT'));
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) onAbort();
  });
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await Promise.race([aborted, Promise.resolve().then(() => {
      signal.throwIfAborted();
      return work(signal);
    })]);
  } finally {
    clearTimeout(timer);
    signal.removeEventListener('abort', onAbort);
  }
}

// Support both standard Node callback functions and async injected test seams.
function invoke(fn, args) {
  return new Promise((resolve, reject) => {
    const done = (error, ...values) => {
      if (error) reject(error);
      else resolve(values.length > 1 ? values : values[0]);
    };
    try {
      if (fn.length > args.length) fn(...args, done);
      else Promise.resolve(fn(...args)).then(resolve, reject);
    } catch (error) { reject(error); }
  });
}
function publicAddress(address) {
  if (isIP(address) === 4) {
    const [a, b, c] = address.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99)))
      || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113));
  }
  if (isIP(address) !== 6) return false;
  const [first, second] = address.split(':').map(part => Number.parseInt(part || '0', 16));
  return first >= 0x2000 && first <= 0x3fff && first !== 0x2002 && first !== 0x3fff
    && !(first === 0x2001 && (second < 0x200 || second === 0xdb8));
}
async function resolveHost(lookup, host, signal) {
  signal.throwIfAborted();
  const results = await invoke(lookup, [host, { all: true, verbatim: true }]);
  signal.throwIfAborted();
  if (!Array.isArray(results) || !results.length || results.length > 32
      || results.some(result => !result || !publicAddress(result.address) || result.family !== isIP(result.address))) throw failure('SCM_PROVIDER_FAILED');
  return [...new Map(results.map(result => [result.address, { address: result.address, family: result.family }])).values()];
}

// Unlike global fetch, HTTPS request supports a pinned lookup without undici or
// another dependency. No redirect handling, proxy, cookies, or automatic unzip.
async function httpsFetch(lookup, urlString, init) {
  const url = new URL(urlString);
  const addresses = await resolveHost(lookup, url.hostname, init.signal);
  return new Promise((resolve, reject) => {
    const request = https.request(url, {
      method: 'GET', headers: init.headers, signal: init.signal, agent: false, maxHeaderSize: 16 * 1024,
      lookup(host, options, callback) {
        if (host !== url.hostname) return callback(failure('SCM_PROVIDER_FAILED'));
        if (options?.all) callback(null, addresses);
        else callback(null, addresses[0].address, addresses[0].family);
      },
    }, response => resolve({ status: response.statusCode, headers: response.headers, body: response, url: urlString, redirected: false }));
    request.once('error', reject);
    request.end();
  });
}

function apiUrl(connection, pathname, query = {}) {
  const origin = SOURCE_MANAGER_CAPABILITIES.providers[connection.provider].apiOrigin;
  const url = new URL(`${origin}${pathname}`);
  if (url.origin !== origin || url.username || url.password || url.hash
      || (connection.provider === 'azure-devops' && !url.pathname.startsWith(`/${encode(connection.organization)}/`))) throw failure('SCM_INVALID_INPUT');
  for (const [key, value] of Object.entries(query)) url.searchParams.set(key, String(value));
  return url.toString();
}

function githubRepository(connection, raw) {
  const id = typeof raw.id === 'number' && Number.isSafeInteger(raw.id) ? String(raw.id) : raw.id;
  if (typeof id !== 'string' || !/^[1-9]\d{0,19}$/.test(id)) throw failure('SCM_INVALID_RESPONSE');
  const owner = githubOwner(raw.owner?.login);
  const name = segment(raw.name);
  if (!/^[A-Za-z0-9_.-]{1,100}$/.test(name)) throw failure('SCM_INVALID_RESPONSE');
  const webUrl = `https://github.com/${encode(owner)}/${encode(name)}`;
  const defaultBranch = raw.default_branch ? branchName(raw.default_branch, 'SCM_INVALID_RESPONSE') : '';
  const repo = { id, name, fullName: `${owner}/${name}`, defaultBranch, webUrl, cloneUrl: `${webUrl}.git`, owner };
  const excluded = raw.disabled === true || (connection.organization && owner.toLowerCase() !== connection.organization);
  return excluded ? null : repo;
}
function azureRepository(connection, raw) {
  const id = segment(raw.id);
  const projectId = segment(raw.project?.id);
  const name = segment(raw.name);
  const projectName = segment(raw.project?.name);
  if (raw.defaultBranch && !raw.defaultBranch.startsWith('refs/heads/')) throw failure('SCM_INVALID_RESPONSE');
  const defaultBranch = raw.defaultBranch ? branchName(raw.defaultBranch.slice(11), 'SCM_INVALID_RESPONSE') : '';
  const webUrl = `https://dev.azure.com/${encode(connection.organization)}/${encode(projectId)}/_git/${encode(id)}`;
  const repo = { id, name, fullName: `${connection.organization}/${projectName}/${name}`, defaultBranch, webUrl, cloneUrl: webUrl, projectId };
  return raw.isDisabled === true ? null : repo;
}
// Validation errors are raised before the disabled/filtered check, as in a single combined pass.
function normalizeRepository(connection, raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw failure('SCM_INVALID_RESPONSE');
  const repo = connection.provider === 'github' ? githubRepository(connection, raw) : azureRepository(connection, raw);
  if (!repo) return null;
  for (const value of Object.values(repo)) assertNonsecret(connection, value);
  return Object.freeze(repo);
}
function remember(connection, repositories) {
  assertActive(connection);
  const fresh = repositories.filter(repo => repo && !connection.repositories.has(repo.id));
  if (connection.repositories.size + fresh.length > MAX_REPOSITORIES) throw failure('SCM_LIMIT');
  for (const repo of repositories.filter(Boolean)) {
    const existing = connection.repositories.get(repo.id);
    if (existing && existing.fullName !== repo.fullName) throw failure('SCM_INVALID_RESPONSE');
  }
  for (const repo of fresh) {
    if (connection.repositories.has(repo.id)) continue;
    connection.repositories.set(repo.id, repo);
    connection.inventory.push(repo);
  }
}
function arrayBody(data, field, max = PAGE_SIZE) {
  const items = field ? data?.[field] : data;
  if (!Array.isArray(items) || items.length > max) throw failure('SCM_INVALID_RESPONSE');
  return items;
}
function githubHasMore(response, data, count, page) {
  if (Number.isSafeInteger(data?.total_count) && data.total_count >= 0) return page * PAGE_SIZE < data.total_count;
  const link = header(response, 'link');
  // Only the relation is used. Never visit a provider-supplied Link URL.
  return link ? /(?:^|[,;])\s*rel\s*=\s*"?next(?:"|\s|;|,|$)/i.test(link) : count === PAGE_SIZE;
}

function windowsGitPath() {
  const systemRoot = process.env.SystemRoot || String.raw`C:\Windows`;
  const programFiles = process.env.ProgramFiles || String.raw`C:\Program Files`;
  return [path.win32.join(systemRoot, 'System32'), path.win32.join(programFiles, 'Git', 'cmd')].join(';');
}
function gitEnvironment(tempDir, resolve, cloneUrl, authorization) {
  const env = {
    PATH: process.platform === 'win32'
      ? windowsGitPath()
      : '/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin',
    HOME: tempDir, USERPROFILE: tempDir, XDG_CONFIG_HOME: tempDir, LANG: 'C', LC_ALL: 'C',
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_SYSTEM: os.devNull, GIT_CONFIG_GLOBAL: os.devNull,
    GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: '', SSH_ASKPASS: '', GCM_INTERACTIVE: 'never',
    GIT_ALLOW_PROTOCOL: 'https', GIT_PROTOCOL_FROM_USER: '0', GIT_LFS_SKIP_SMUDGE: '1',
    GIT_ATTR_NOSYSTEM: '1', GIT_NO_REPLACE_OBJECTS: '1',
  };
  if (process.platform === 'win32') env.SystemRoot = process.env.SystemRoot || String.raw`C:\Windows`;
  const config = [
    ['core.hooksPath', os.devNull], ['core.fsmonitor', 'false'], ['core.askPass', ''], ['core.attributesFile', os.devNull],
    ['credential.helper', ''], ['credential.interactive', 'false'], ['credential.useHttpPath', 'true'],
    ['protocol.allow', 'never'], ['protocol.https.allow', 'always'], ['protocol.file.allow', 'never'], ['protocol.ext.allow', 'never'],
    ['http.followRedirects', 'false'], ['http.sslVerify', 'true'], ['http.proxy', ''], ['http.extraHeader', ''],
    ['http.saveCookies', 'false'], ['http.cookieFile', ''], ['http.lowSpeedLimit', '1024'], ['http.lowSpeedTime', '30'],
    ['submodule.recurse', 'false'], ['fetch.recurseSubmodules', 'false'],
    ['filter.lfs.process', ''], ['filter.lfs.smudge', ''], ['filter.lfs.clean', ''], ['filter.lfs.required', 'false'],
    ['gc.auto', '0'], ['maintenance.auto', 'false'], ['transfer.fsckObjects', 'true'], ['transfer.bundleURI', 'false'],
    ['fetch.uriprotocols', ''], ['promisor.acceptFromServer', 'none'], ['init.templateDir', ''],
  ];
  if (resolve) config.push(['http.curloptResolve', resolve]);
  // Command-scope environment config is never written to .git/config. The scope
  // matches only this HTTPS repository path (and its smart-HTTP subpaths).
  if (authorization) config.push([`http.${cloneUrl}.extraHeader`, `Authorization: ${authorization}`]);
  env.GIT_CONFIG_COUNT = String(config.length);
  config.forEach(([key, value], index) => { env[`GIT_CONFIG_KEY_${index}`] = key; env[`GIT_CONFIG_VALUE_${index}`] = value; });
  return env;
}

function repositoryFor(connection, id) {
  const repo = connection.repositories.get(repositoryKey(id));
  if (!repo) throw failure('SCM_REPOSITORY_NOT_FOUND');
  return repo;
}
function publicAsync(work, code = 'SCM_PROVIDER_FAILED') {
  return async (...args) => {
    try { return await work(...args); }
    catch (error) { throw error instanceof SourceManagerError ? error : failure(code); }
  };
}
function serialized(connection, work) {
  const job = connection.queue.then(() => deadline(connection, LIST_TIMEOUT_MS, work));
  connection.queue = job.catch(() => {});
  return job;
}
function basicAuthorization(user, token) {
  const credential = Buffer.from(`${user}:${token}`).toString('base64');
  return `Basic ${credential}`;
}
function apiHeaders(connection) {
  const github = connection.provider === 'github';
  const headers = { Accept: github ? 'application/vnd.github+json' : 'application/json',
    Authorization: github ? `Bearer ${connection.token}` : basicAuthorization('', connection.token),
    'User-Agent': 'threatlint-source-manager', 'Accept-Encoding': 'identity' };
  if (github) headers['X-GitHub-Api-Version'] = '2022-11-28';
  return headers;
}
function validateApiResponse(response, url) {
  if (response?.redirected || (response?.url && response.url !== url) || !Number.isInteger(response?.status)) throw failure('SCM_INVALID_RESPONSE');
  if (response.status === 401 || response.status === 403) throw failure('SCM_AUTHORIZATION_FAILED', response.status);
  if (response.status !== 200) throw failure('SCM_PROVIDER_FAILED');
  const length = header(response, 'content-length');
  if (length && (!/^\d+$/.test(length) || Number(length) > API_MAX_BYTES)) throw failure('SCM_RESPONSE_TOO_LARGE');
  const encoding = header(response, 'content-encoding');
  if (encoding && encoding !== 'identity') throw failure('SCM_INVALID_RESPONSE');
  const type = header(response, 'content-type');
  if (type && !/^application\/(?:[\w.-]+\+)?json(?:;|$)/i.test(type)) throw failure('SCM_INVALID_RESPONSE');
  if (!response.body?.[Symbol.asyncIterator]) throw failure('SCM_INVALID_RESPONSE');
}
async function* readerChunks(reader) {
  const { done, value } = await reader.read();
  if (done) { return; }
  yield value;
  yield* readerChunks(reader);
}
// A stalled body must be cancelled through its reader; a locked stream ignores body.cancel().
async function readBoundedBody(body, signal) {
  const reader = typeof body.getReader === 'function' ? body.getReader() : null;
  const cancelRead = () => reader?.cancel().catch(() => {});
  signal.addEventListener('abort', cancelRead, { once: true });
  if (signal.aborted) cancelRead();
  const chunks = [];
  let bytes = 0;
  try {
    for await (const chunk of reader ? readerChunks(reader) : body) {
      signal.throwIfAborted();
      const buffer = Buffer.from(chunk);
      bytes += buffer.length;
      if (bytes > API_MAX_BYTES) throw failure('SCM_RESPONSE_TOO_LARGE');
      chunks.push(buffer);
    }
  } finally { signal.removeEventListener('abort', cancelRead); }
  return Buffer.concat(chunks);
}
function pinnedResolve(host, addresses) {
  const list = addresses.map(({ address, family }) => (family === 6 ? `[${address}]` : address)).join(',');
  return `${host}:443:${list}`;
}

function createSourceManagers(
options = {}) {
  objectInput(options, ['fetch', 'execFile', 'lookup']);
  for (const value of Object.values(options)) if (value !== undefined && typeof value !== 'function') throw failure('SCM_INVALID_INPUT');
  const lookup = options.lookup || nativeLookup;
  const fetch = options.fetch || ((url, init) => httpsFetch(lookup, url, init));
  const execFile = options.execFile || nativeExecFile;
  const connections = new Map();
  let pendingConnections = 0, activeCheckouts = 0;

  function connectionFor(id) {
    if (typeof id !== 'string' || !/^[0-9a-f-]{36}$/.test(id)) throw failure('SCM_CONNECTION_NOT_FOUND');
    const connection = connections.get(id);
    if (!connection) throw failure('SCM_CONNECTION_NOT_FOUND');
    assertActive(connection);
    return connection;
  }
  async function requestJson(connection, pathname, query, parentSignal) {
    return deadline(connection, API_TIMEOUT_MS, async signal => {
      const url = apiUrl(connection, pathname, query);
      let response;
      try {
        response = await fetch(url, { method: 'GET', redirect: 'manual', signal, credentials: 'omit', cache: 'no-store', headers: apiHeaders(connection) });
        validateApiResponse(response, url);
        const body = await readBoundedBody(response.body, signal);
        const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
        assertActive(connection);
        return { data, response };
      } catch (error) {
        discardBody(response);
        throw error instanceof SourceManagerError ? error : failure('SCM_PROVIDER_FAILED');
      }
    }, parentSignal);
  }
  async function githubPage(connection, page, signal) {
    const installation = connection.kind === 'installation';
    const result = await requestJson(connection, installation ? '/installation/repositories' : '/user/repos', {
      per_page: PAGE_SIZE, page, ...(!installation ? { sort: 'full_name', direction: 'asc' } : {}),
    }, signal);
    const items = arrayBody(result.data, installation ? 'repositories' : null);
    const repositories = items.map(item => normalizeRepository(connection, item));
    const hasMore = githubHasMore(result.response, installation ? result.data : null, items.length, page);
    remember(connection, repositories);
    connection.nextPage = page + 1;
    connection.complete = !hasMore;
    return repositories;
  }
  const connect = publicAsync(async (input = {}) => {
    objectInput(input, ['provider', 'token', 'organization']);
    const { provider, token, organization } = input;
    if (typeof provider !== 'string' || !Object.hasOwn(SOURCE_MANAGER_CAPABILITIES.providers, provider)) throw failure('SCM_INVALID_PROVIDER');
    if (typeof token !== 'string' || token.length < 8 || token.length > 4096 || /[^\x21-\x7e]/.test(token)) throw failure('SCM_INVALID_TOKEN');
    if ((provider === 'azure-devops' || organization !== undefined)
        && (typeof organization !== 'string' || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,48}[A-Za-z0-9])?$/.test(organization)
          || (provider === 'github' && organization.length > 39))) throw failure('SCM_INVALID_ORGANIZATION');
    if (connections.size + pendingConnections >= MAX_CONNECTIONS) throw failure('SCM_LIMIT');
    pendingConnections++;
    const connection = { id: randomUUID(), provider, token, organization: organization?.toLowerCase(),
      host: provider === 'github' ? 'github.com' : 'dev.azure.com', repositories: new Map(), inventory: [],
      branchPages: new Map(), nextPage: 1, complete: false, queue: Promise.resolve(), controller: new AbortController(), closed: false };
    try {
      if (provider === 'github') {
        try {
          const { data } = await requestJson(connection, '/user');
          connection.account = githubOwner(data?.login);
          connection.kind = 'user';
        } catch (error) {
          if (error.code !== 'SCM_AUTHORIZATION_FAILED' || error.statusCode !== 403) throw error;
          connection.kind = 'installation';
          const repositories = await githubPage(connection, 1);
          connection.account = repositories.find(Boolean)?.owner || 'GitHub App installation';
        }
        connection.label = `GitHub · ${connection.organization || connection.account}`;
      } else {
        // ADO Repositories - List has no $top/$skip pagination. Bound the entire
        // snapshot by both bytes and count, then serve stable local 100-item pages.
        const { data } = await requestJson(connection, `/${encode(connection.organization)}/_apis/git/repositories`, { 'api-version': '7.1' });
        remember(connection, arrayBody(data, 'value', MAX_REPOSITORIES).map(item => normalizeRepository(connection, item)));
        connection.complete = true;
        connection.account = connection.organization;
        connection.label = `Azure DevOps · ${connection.organization}`;
      }
      assertNonsecret(connection, connection.account);
      assertNonsecret(connection, connection.label);
      connections.set(connection.id, connection);
      return summary(connection);
    } catch (error) {
      connection.token = '';
      connection.controller.abort();
      throw error;
    } finally { pendingConnections--; }
  });

  const repositories = publicAsync(async (id, input = {}) => {
    objectInput(input, ['search', 'page']);
    const connection = connectionFor(id);
    const page = pageNumber(input.page);
    if (input.search !== undefined && (typeof input.search !== 'string' || input.search.length > 200 || CONTROLS.test(input.search) || !input.search.isWellFormed())) throw failure('SCM_INVALID_INPUT');
    const search = (input.search || '').trim().toLowerCase();
    return serialized(connection, async signal => {
      const matches = () => connection.inventory.filter(repo => repo.fullName.toLowerCase().includes(search) || repo.name.toLowerCase().includes(search));
      const end = page * PAGE_SIZE;
      // One-item lookahead makes hasMore truthful, including filtered searches. Pages load strictly in order.
      const fill = async () => {
        const current = matches();
        if (connection.complete || current.length > end) return current;
        if (connection.nextPage > MAX_PAGE) throw failure('SCM_LIMIT');
        await githubPage(connection, connection.nextPage, signal);
        return fill();
      };
      const filtered = await fill();
      assertActive(connection);
      return { repositories: filtered.slice(end - PAGE_SIZE, end).map(publicRepository), page, hasMore: filtered.length > end };
    });
  });

  async function githubBranchPage(connection, repo, current, signal) {
    const result = await requestJson(connection, `/repos/${encode(repo.owner)}/${encode(repo.name)}/branches`, { per_page: PAGE_SIZE, page: current }, signal);
    const items = arrayBody(result.data);
    return { names: items.map(item => branchName(item?.name, 'SCM_INVALID_RESPONSE')), hasMore: githubHasMore(result.response, null, items.length, current) };
  }
  async function azureBranchPage(connection, repo, state, current, signal) {
    const cursor = state.cursors.get(current);
    const result = await requestJson(connection, `/${encode(connection.organization)}/${encode(repo.projectId)}/_apis/git/repositories/${encode(repo.id)}/refs`, {
      'api-version': '7.1', filter: 'heads/', '$top': PAGE_SIZE, ...(cursor ? { continuationToken: cursor } : {}),
    }, signal);
    const names = arrayBody(result.data, 'value').map(item => text(item?.name)).filter(name => name.startsWith('refs/heads/'))
      .map(name => branchName(name.slice(11), 'SCM_INVALID_RESPONSE'));
    const next = header(result.response, 'x-ms-continuationtoken');
    if (next) {
      assertNonsecret(connection, text(next, 2048));
      if ([...state.cursors.values()].includes(next)) throw failure('SCM_INVALID_RESPONSE');
      state.cursors.set(current + 1, next);
    }
    return { names, hasMore: !!next };
  }
  function branchState(connection, repo) {
    let state = connection.branchPages.get(repo.id);
    if (!state) {
      state = { pages: new Map(), cursors: new Map([[1, '']]) };
      connection.branchPages.set(repo.id, state);
    }
    return state;
  }

  async function fetchBranchPage(connection, repo, state, current, signal) {
    const fetched = connection.provider === 'github' ? githubBranchPage(connection, repo, current, signal) : azureBranchPage(connection, repo, state, current, signal);
    const { names, hasMore } = await fetched;
    names.forEach(name => assertNonsecret(connection, name));
    assertActive(connection);
    state.pages.set(current, { branches: [...new Set(names)].map(name => ({ name })), page: current, hasMore: current < MAX_PAGE && hasMore });
  }
  // Azure continuation tokens chain page to page, so pages load strictly in order (GitHub pages are direct).
  async function loadBranchPages(connection, repo, state, page, signal, current = connection.provider === 'github' ? page : 1) {
    if (current > page) return null;
    if (!state.pages.has(current)) {
      if (connection.provider !== 'github' && !state.cursors.has(current)) return { branches: [], page, hasMore: false };
      await fetchBranchPage(connection, repo, state, current, signal);
    }
    return loadBranchPages(connection, repo, state, page, signal, current + 1);
  }

  const branches = publicAsync(async (id, repositoryId, input = {}) => {
    objectInput(input, ['page']);
    const connection = connectionFor(id), repo = repositoryFor(connection, repositoryId), page = pageNumber(input.page);
    return serialized(connection, async signal => {
      const state = branchState(connection, repo);
      if (state.pages.has(page)) return structuredClone(state.pages.get(page));
      const missing = await loadBranchPages(connection, repo, state, page, signal);
      return missing || structuredClone(state.pages.get(page));
    });
  });

  async function confirmBranch(connection, repo, branch, signal) {
    let commit;
    if (connection.provider === 'github') {
      const { data } = await requestJson(connection, `/repos/${encode(repo.owner)}/${encode(repo.name)}/branches/${encode(branch)}`, {}, signal);
      if (data?.name !== branch) throw failure('SCM_BRANCH_NOT_FOUND');
      commit = data.commit?.sha;
    } else {
      const { data } = await requestJson(connection, `/${encode(connection.organization)}/${encode(repo.projectId)}/_apis/git/repositories/${encode(repo.id)}/refs`, {
        'api-version': '7.1', filter: `heads/${branch}`, '$top': PAGE_SIZE,
      }, signal);
      commit = arrayBody(data, 'value').find(ref => ref?.name === `refs/heads/${branch}`)?.objectId;
    }
    if (typeof commit !== 'string' || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i.test(commit)) throw failure('SCM_BRANCH_NOT_FOUND');
  }

  async function runGit(connection, tempDir, cwd, args, env, timeoutMs = 10_000) {
    try {
      return await deadline(connection, timeoutMs, async signal => {
        const result = await invoke(execFile, ['git', ['--no-pager', '--no-optional-locks', ...args], {
          cwd, env, signal, timeout: timeoutMs, maxBuffer: GIT_MAX_BUFFER, encoding: 'utf8', shell: false, windowsHide: true, killSignal: 'SIGKILL',
        }]);
        const stdout = Array.isArray(result) ? result[0] : result?.stdout;
        return typeof stdout === 'string' ? stdout : '';
      });
    } catch (error) {
      throw error instanceof SourceManagerError && ['SCM_CONNECTION_NOT_FOUND', 'SCM_TIMEOUT'].includes(error.code) ? error : failure('SCM_CHECKOUT_FAILED');
    } finally {
      // Clear secret command-scope values even when an injected executor retains
      // the options object. Never attach executor errors, stderr, or env to errors.
      for (let index = 0; index < Number(env.GIT_CONFIG_COUNT); index++) {
        if (env[`GIT_CONFIG_KEY_${index}`]?.endsWith('.extraHeader')) env[`GIT_CONFIG_VALUE_${index}`] = '';
      }
    }
  }

  const checkout = publicAsync(async (id, input = {}) => {
    objectInput(input, ['repositoryId', 'branch']);
    const connection = connectionFor(id), repo = repositoryFor(connection, input.repositoryId);
    const branch = branchName(input.branch === undefined ? repo.defaultBranch : input.branch);
    assertNonsecret(connection, branch);
    if (activeCheckouts >= MAX_CHECKOUTS) throw failure('SCM_LIMIT');
    activeCheckouts++;
    let tempDir;
    try {
      await confirmBranch(connection, repo, branch);
      const host = new URL(repo.cloneUrl).hostname;
      const addresses = await deadline(connection, API_TIMEOUT_MS, signal => resolveHost(lookup, host, signal));
      const resolve = pinnedResolve(host, addresses);
      assertActive(connection);
      tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'threatlint-scm-'));
      const repoPath = path.join(tempDir, 'repository');
      const authorization = basicAuthorization(connection.provider === 'github' ? 'x-access-token' : '', connection.token);
      const env = gitEnvironment(tempDir, resolve, repo.cloneUrl, authorization);
      await runGit(connection, tempDir, tempDir, ['clone', '--quiet', '--no-progress', '--depth=1', '--single-branch', '--no-tags', '--no-recurse-submodules', '--template=',
        '--branch', branch, '--', repo.cloneUrl, repoPath], env, GIT_TIMEOUT_MS);
      const cleanEnv = gitEnvironment(tempDir);
      const commit = (await runGit(connection, tempDir, repoPath, ['rev-parse', '--verify', 'HEAD^{commit}'], cleanEnv)).trim();
      const actualBranch = (await runGit(connection, tempDir, repoPath, ['symbolic-ref', '--quiet', '--short', 'HEAD'], cleanEnv)).trim();
      if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i.test(commit) || actualBranch !== branch) throw failure('SCM_CHECKOUT_FAILED');
      assertNonsecret(connection, commit);
      assertActive(connection);
      return { repoPath, tempDir, provenance: { provider: connection.provider, repository: repo.fullName, branch, commit, webUrl: repo.webUrl } };
    } catch (error) {
      if (tempDir) await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
      throw error;
    } finally { activeCheckouts--; }
  }, 'SCM_CHECKOUT_FAILED');

  function list() { return [...connections.values()].map(summary); }
  function disconnect(id) {
    const connection = connections.get(id);
    if (!connection) return false;
    connections.delete(id);
    connection.closed = true;
    connection.token = '';
    connection.controller.abort();
    connection.repositories.clear();
    connection.inventory.length = 0;
    connection.branchPages.clear();
    return true;
  }

  return Object.freeze({ connect, list, disconnect, repositories, branches, checkout });
}

module.exports = { createSourceManagers, SOURCE_MANAGER_CAPABILITIES };
