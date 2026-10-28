'use strict';

// Independent of app.js state. The parent owns view navigation and both handoffs.
(() => {
  const $ = id => document.getElementById(id);
  const LIVE_STATES = new Set(['pending', 'queued', 'starting', 'running', 'scanning', 'in-progress', 'cancelling', 'canceling']);
  const TERMINAL_STATES = new Set(['complete', 'completed', 'finished', 'done', 'success', 'succeeded', 'cancelled', 'canceled', 'stopped', 'aborted', 'failed', 'error', 'timeout', 'timed-out']);
  const FAILED_STATES = new Set(['failed', 'error', 'timeout', 'timed-out']);
  const STOPPED_STATES = new Set(['cancelled', 'canceled', 'stopped', 'aborted']);
  const NODE_STATES = new Set(['pending', 'running', 'observed', 'blocked', 'failed', 'not-tested']);
  const STAGES = [
    { label: 'Scope & authority', kinds: ['target'], icon: '◇' },
    { label: 'Identity', kinds: ['identity'], icon: '◎' },
    { label: 'Entrypoint', kinds: ['request'], icon: '↗' },
    { label: 'Response / control', kinds: ['response', 'control'], icon: '⊡' },
    { label: 'Finding observation', kinds: ['finding'], icon: '⌁' },
    { label: 'Impact hypothesis', kinds: ['impact'], icon: '∴' },
  ];
  const AUTH = {
    none: { help: 'No credentials are sent. Requests use the anonymous identity.', fields: [] },
    bearer: { help: 'The runner sends an Authorization: Bearer header. Use a short-lived, narrowly scoped test token.', fields: [
      { key: 'token', label: 'Bearer token', type: 'password', placeholder: 'Short-lived access token', secret: true },
    ] },
    basic: { help: 'HTTP Basic encodes, but does not encrypt, credentials. Use HTTPS beyond an approved loopback environment.', fields: [
      { key: 'username', label: 'Username', placeholder: 'Dedicated test identity', secret: true },
      { key: 'password', label: 'Password', type: 'password', placeholder: 'Test identity password', secret: true },
    ] },
    'api-key': { help: 'Prefer header placement. Query placement deliberately puts the key in the target request URL, where target-side logs may record it.', fields: [
      { key: 'name', label: 'Key name', placeholder: 'X-API-Key' },
      { key: 'value', label: 'Key value', type: 'password', secret: true },
      { key: 'location', label: 'Placement', options: [['header', 'Header · recommended'], ['query', 'Query · may be logged by the target']] },
    ] },
    headers: { help: 'One JSON object of explicit header names and string values. Do not include transport headers such as Host or Content-Length.', fields: [
      { key: 'headers', label: 'Headers · JSON object', textarea: true, placeholder: '{"X-Test-Identity":"test-user","X-API-Key":"value"}', secret: true },
    ] },
    cookie: { help: 'An explicit Cookie header for your authorized test identity. Cookie replay is not a browser or an automated login.', fields: [
      { key: 'cookie', label: 'Cookie header', textarea: true, placeholder: 'session=your-test-session; other=value', secret: true },
    ] },
    'oauth-client-credentials': { help: 'The runner contacts this trusted token endpoint. A client credential represents a service identity, not an end-user role.', fields: [
      { key: 'tokenUrl', label: 'Trusted token endpoint', type: 'url', placeholder: 'https://identity.example.com/oauth2/token' },
      { key: 'clientId', label: 'Client ID', placeholder: 'Dedicated test application' },
      { key: 'clientSecret', label: 'Client secret', type: 'password', secret: true },
      { key: 'scope', label: 'Scope', optional: true, placeholder: 'api.read' },
      { key: 'audience', label: 'Audience', optional: true, placeholder: 'https://api.example.com' },
    ] },
    'oauth-refresh-token': { help: 'The runner exchanges this refresh token at the trusted endpoint. Use a dedicated test identity; refresh tokens are sensitive.', fields: [
      { key: 'tokenUrl', label: 'Trusted token endpoint', type: 'url', placeholder: 'https://identity.example.com/oauth2/token' },
      { key: 'clientId', label: 'Client ID' },
      { key: 'clientSecret', label: 'Client secret', type: 'password', optional: true, secret: true },
      { key: 'refreshToken', label: 'Refresh token', type: 'password', secret: true },
      { key: 'scope', label: 'Scope', optional: true, placeholder: 'api.read' },
    ] },
    'oauth-password': { help: 'Resource-owner password grant for dedicated test identities only. The runner posts username and password to the trusted token endpoint once.', fields: [
      { key: 'tokenUrl', label: 'Trusted token endpoint', type: 'url', placeholder: 'https://identity.example.com/oauth2/token' },
      { key: 'clientId', label: 'Client ID' },
      { key: 'clientSecret', label: 'Client secret', type: 'password', optional: true, secret: true },
      { key: 'username', label: 'Username', secret: true },
      { key: 'password', label: 'Password', type: 'password', secret: true },
      { key: 'scope', label: 'Scope', optional: true },
    ] },
    'form-login': { help: 'The runner POSTs the form once to your login endpoint and replays the session cookie it returns. Use a dedicated test account.', fields: [
      { key: 'loginUrl', label: 'Login endpoint', type: 'url', placeholder: 'https://staging.example.com/login' },
      { key: 'usernameField', label: 'Username field name', optional: true, placeholder: 'username' },
      { key: 'passwordField', label: 'Password field name', optional: true, placeholder: 'password' },
      { key: 'username', label: 'Username', secret: true },
      { key: 'password', label: 'Password', type: 'password', secret: true },
    ] },
    mtls: { help: 'Mutual TLS: the runner presents this client certificate during the TLS handshake. PEM text is held in memory for the scan only.', fields: [
      { key: 'cert', label: 'Client certificate · PEM', textarea: true, placeholder: '-----BEGIN CERTIFICATE-----', secret: true, maxLength: 64000 },
      { key: 'key', label: 'Private key · PEM', textarea: true, placeholder: '-----BEGIN PRIVATE KEY-----', secret: true, maxLength: 64000 },
      { key: 'passphrase', label: 'Key passphrase', type: 'password', optional: true, secret: true },
    ] },
    'browser-state': { help: 'Paste browser storage-state JSON. Only its cookies are submitted. Origins and localStorage are discarded, not converted into tokens.', fields: [
      { key: 'storageState', label: 'Browser storage state · JSON', textarea: true, placeholder: '{"cookies":[{"name":"session","value":"…","domain":"staging.example.com","path":"/","secure":true}]}', secret: true, maxLength: 250000 },
    ] },
    'browser-session': { help: 'Sign in manually in the runner’s own browser, then finish. The resulting cookie session is held by the runner; no SSO password is entered here.', fields: [] },
  };
  const scm = {
    connections: [], connectionId: '', repositories: [], repository: null, branches: [],
    repositoryPage: 0, repositoryHasMore: false, branchPage: 0, branchHasMore: false,
    search: '', initialized: false, connecting: false, refreshing: false, checkout: false,
    repositoryBusy: false, branchBusy: false, connectionBusy: false, repositoryVersion: 0, branchVersion: 0,
    repositoryController: null, branchController: null,
  };
  const runtime = {
    scan: null, scanId: '', demo: false, submitting: false, demoLoading: false,
    polling: false, pollTimer: null, pollController: null, pollVersion: 0, cancelRequested: false,
    browser: null, browserBusy: false, selectedNode: '', graphSignature: '', nodeElements: new Map(),
    graphFrame: null, announcedStatus: '',
  };

  class InputError extends Error {
    constructor(message, field) { super(message); this.field = field; }
  }
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = String(text);
    return node;
  }
  function button(label, className, action, accessibleLabel) {
    const node = el('button', className, label);
    node.type = 'button';
    if (accessibleLabel) node.setAttribute('aria-label', accessibleLabel);
    node.addEventListener('click', action);
    return node;
  }
  function status(id, message, type = '') {
    const node = $(id);
    node.textContent = message;
    node.classList.toggle('error', type === 'error');
    node.classList.toggle('busy', type === 'busy');
  }
  function localError(error, id, fallback) {
    status(id, error instanceof InputError ? error.message : fallback, 'error');
    if (error instanceof InputError && error.field) $(error.field)?.focus();
  }
  async function api(path, { method = 'GET', body, signal } = {}) {
    // No credentials in URLs, storage, logs, or error messages. Do not follow a redirect with a secret-bearing body.
    const response = await fetch(path, {
      method, signal, cache: 'no-store', credentials: 'same-origin', redirect: 'error', referrerPolicy: 'no-referrer',
      headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!response.ok) {
      const error = new Error('The local runner could not complete this operation.');
      error.status = response.status;
      throw error;
    }
    if (response.status === 204) return null;
    return response.json();
  }
  function idOf(value) {
    return (typeof value === 'string' || typeof value === 'number') && String(value).length <= 2000 ? String(value) : '';
  }
  function text(value, fallback = '') {
    return typeof value === 'string' || typeof value === 'number' ? String(value) : fallback;
  }
  // Credential-bearing labels, each a simple pattern so redaction stays readable and fast.
  const SECRET_LABELS = [/\b(proxy-authorization|authorization)\s*[:=]\s*[^\r\n,}]+/gi, /\b(set-cookie|cookie)\s*[:=]\s*[^\r\n,}]+/gi, /\b(password)\s*[:=]\s*[^\r\n,}]+/gi,
    /\b(client[_-]?secret)\s*[:=]\s*[^\r\n,}]+/gi, /\b(access[_-]?token|refresh[_-]?token)\s*[:=]\s*[^\r\n,}]+/gi, /\b(api[_-]?key)\s*[:=]\s*[^\r\n,}]+/gi];
  const SENSITIVE_KEYS = [/auth|cookie|token|password|secret|credential/i, /api.?key|storage.?state/i, /local.?storage|session.?storage|session.?id/i, /headers|body/i];
  function redactText(value) {
    let result = text(value).slice(0, 32000).replace(/\b(Bearer|Basic)\s+[\w.~+/=-]+/gi, '$1 [redacted]');
    for (const pattern of SECRET_LABELS) result = result.replace(pattern, '$1: [redacted]');
    return result
      .replace(/https?:\/\/[^\s<>"']+/gi, raw => {
        try {
          const url = new URL(raw);
          url.username = ''; url.password = ''; url.search = ''; url.hash = '';
          return url.href;
        } catch { return '[redacted URL]'; }
      });
  }
  function safeValue(value, depth = 0) {
    if (depth > 10) return '[detail omitted]';
    if (typeof value === 'string') return redactText(value);
    if (value == null || typeof value === 'boolean') return value;
    if (typeof value === 'number') return Number.isFinite(value) ? value : null;
    if (Array.isArray(value)) return value.slice(0, 2000).map(item => safeValue(item, depth + 1));
    if (typeof value !== 'object') return null;
    const entries = Object.entries(value).slice(0, 100);
    return Object.fromEntries(entries.filter(([key]) => !['__proto__', 'constructor', 'prototype'].includes(key)).map(([key, item]) => [
      redactText(key), SENSITIVE_KEYS.some(pattern => pattern.test(key)) ? '[redacted]' : safeValue(item, depth + 1),
    ]));
  }
  function safeScan(payload) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('Invalid scan state.');
    // Never spread the API object: auth profiles, browser handles, and provider material are not evidence.
    const snapshot = {};
    for (const key of ['id', 'status', 'target', 'startedAt', 'finishedAt', 'requests', 'findings', 'nodes', 'edges', 'events', 'coverage']) {
      if (Object.hasOwn(payload, key)) snapshot[key] = safeValue(payload[key]);
    }
    snapshot.id = idOf(snapshot.id);
    snapshot.status = text(snapshot.status, 'unknown').toLowerCase();
    for (const key of ['findings', 'nodes', 'edges', 'events']) if (!Array.isArray(snapshot[key])) snapshot[key] = [];
    snapshot.coverage = snapshot.coverage && typeof snapshot.coverage === 'object' ? snapshot.coverage : {};
    return snapshot;
  }
  function pretty(value) { return typeof value === 'string' ? value : JSON.stringify(value, null, 2); }
  function externalUrl(value) {
    try {
      const url = new URL(value);
      if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) return '';
      return url.href;
    } catch { return ''; }
  }

  // Source connections and repository browsing.
  function connection(value) {
    if (!value || !idOf(value.id)) return null;
    return {
      id: idOf(value.id), provider: text(value.provider), label: redactText(value.label),
      account: redactText(value.account), host: redactText(value.host),
    };
  }
  function sourceLocked() { return scm.checkout || scm.connecting || scm.connectionBusy; }
  function syncSourceControls() {
    const locked = sourceLocked();
    $('scm-connection-fields').disabled = locked;
    $('scm-refresh-connections').disabled = locked || scm.refreshing;
    $('scm-repository-search').disabled = locked || !scm.connectionId;
    $('scm-search').disabled = locked || !scm.connectionId;
    $('scm-repositories-more').hidden = !scm.repositoryHasMore;
    $('scm-repositories-more').disabled = locked || scm.repositoryBusy;
    $('scm-branches-more').hidden = !scm.branchHasMore;
    $('scm-branches-more').disabled = locked || scm.branchBusy;
    $('scm-branch').disabled = locked || scm.branchBusy || !scm.branches.length;
    $('scm-checkout').disabled = locked || scm.branchBusy || !scm.repository || !$('scm-branch').value;
    $('scm-checkout').textContent = scm.checkout ? 'Preparing checkout…' : 'Check out & open workspace →';
    $('scm-connect').textContent = scm.connecting ? 'Connecting…' : 'Connect source ↗';
    $('scm-repositories').setAttribute('aria-busy', String(scm.repositoryBusy));
    $('scm-connections').setAttribute('aria-busy', String(scm.refreshing || scm.connectionBusy));
    for (const node of $('scm-connections').querySelectorAll('button')) node.disabled = locked;
    for (const node of $('scm-repositories').querySelectorAll('button')) node.disabled = locked;
  }
  function providerChanged() {
    const azure = $('scm-provider').value === 'azure-devops';
    $('scm-organization-field').hidden = !azure;
    $('scm-organization').disabled = !azure;
    $('scm-organization').required = azure;
    $('scm-token').value = '';
  }
  function renderConnections() {
    const list = $('scm-connections');
    list.replaceChildren();
    for (const item of scm.connections) {
      const row = el('li', `scm-connection${item.id === scm.connectionId ? ' selected' : ''}`);
      const select = button('', 'scm-connection-select', () => selectConnection(item.id));
      select.setAttribute('aria-pressed', String(item.id === scm.connectionId));
      const azure = item.provider !== 'github';
      const copy = el('span', 'scm-connection-copy');
      copy.append(el('strong', '', item.label || (azure ? 'Azure DevOps' : 'GitHub')), el('small', '', [item.account, item.host].filter(Boolean).join(' · ') || 'Session connection'));
      select.append(el('span', `scm-provider-mark${azure ? ' azure' : ''}`, azure ? 'AZ' : 'GH'), copy);
      row.append(select, button('×', 'icon-button', () => disconnect(item.id), `Disconnect ${item.label || item.account || 'source connection'}`));
      list.append(row);
    }
    if (!scm.connections.length) list.append(el('li', 'operations-empty-note', 'No connected accounts. Add a repository-read token above, or save an Azure DevOps PAT in Settings → Azure DevOps.'));
    syncSourceControls();
  }
  async function refreshConnections() {
    if (scm.refreshing || sourceLocked()) return;
    scm.refreshing = true;
    syncSourceControls();
    status('scm-status', 'Loading session connections…', 'busy');
    try {
      const payload = await api('/api/scm/connections');
      if (!Array.isArray(payload)) throw new Error('Invalid connections.');
      scm.connections = payload.map(connection).filter(Boolean);
      scm.initialized = true;
      const selected = scm.connections.some(item => item.id === scm.connectionId);
      renderConnections();
      if (!selected) selectConnection(scm.connections[0]?.id || '');
      else status('scm-status', 'Session connections refreshed. Select a repository to continue.');
      if (!scm.connections.length) status('scm-status', 'No source connections yet. Connect an account above, or save an Azure DevOps PAT in Settings to connect it automatically.');
    } catch {
      status('scm-status', 'Source connections could not be loaded. The local runner may not support source connections yet; use Refresh to retry.', 'error');
    } finally { scm.refreshing = false; syncSourceControls(); }
  }
  async function connectSource(event) {
    event.preventDefault();
    if (sourceLocked()) return;
    const provider = $('scm-provider').value;
    const token = $('scm-token').value.trim();
    const organization = $('scm-organization').value.trim();
    if (!token) { localError(new InputError('Enter a repository-read token.', 'scm-token'), 'scm-status'); return; }
    if (provider === 'azure-devops' && !/^[a-z0-9][a-z0-9-]{0,99}$/i.test(organization)) {
      localError(new InputError('Enter an Azure DevOps organization name, not a URL.', 'scm-organization'), 'scm-status'); return;
    }
    scm.connecting = true;
    $('scm-token').value = '';
    syncSourceControls();
    status('scm-status', 'Connecting to the selected source provider…', 'busy');
    try {
      const payload = await api('/api/scm/connections', { method: 'POST', body: { provider, token, ...(provider === 'azure-devops' ? { organization } : {}) } });
      const item = connection(payload);
      if (!item) throw new Error('Invalid connection.');
      scm.connections = [...scm.connections.filter(existing => existing.id !== item.id), item];
      scm.initialized = true;
      scm.connecting = false;
      renderConnections();
      selectConnection(item.id);
    } catch {
      status('scm-status', 'The source connection was not accepted. Check the provider, organization, token permissions, and runner availability before retrying.', 'error');
    } finally { $('scm-token').value = ''; scm.connecting = false; syncSourceControls(); }
  }
  async function disconnect(id) {
    if (sourceLocked()) return;
    scm.connectionBusy = true;
    syncSourceControls();
    try {
      await api(`/api/scm/connections/${encodeURIComponent(id)}`, { method: 'DELETE' });
      scm.connections = scm.connections.filter(item => item.id !== id);
      scm.connectionBusy = false;
      if (scm.connectionId === id) selectConnection(scm.connections[0]?.id || '');
      renderConnections();
      status('scm-status', 'Source disconnected. Its existing checkout, if any, was not removed.');
    } catch {
      status('scm-status', 'The source could not be disconnected. Refresh the connections and try again.', 'error');
    } finally { scm.connectionBusy = false; syncSourceControls(); }
  }
  function clearBranches() {
    scm.branchController?.abort();
    scm.branchVersion += 1;
    scm.branchBusy = false; scm.branches = []; scm.branchPage = 0; scm.branchHasMore = false;
    const option = el('option', '', 'Choose a repository first'); option.value = '';
    $('scm-branch').replaceChildren(option);
    $('scm-selection').textContent = 'Select a repository to load its branches.';
  }
  function selectConnection(id) {
    if (sourceLocked()) return;
    scm.repositoryController?.abort();
    scm.repositoryVersion += 1;
    scm.repositoryBusy = false; scm.connectionId = id; scm.repositories = []; scm.repository = null;
    scm.repositoryPage = 0; scm.repositoryHasMore = false; scm.search = '';
    $('scm-repository-search').value = '';
    clearBranches(); renderConnections(); renderRepositories();
    if (id) void loadRepositories(false);
    else syncSourceControls();
  }
  function repositoryLink(repository) {
    const href = externalUrl(repository.webUrl);
    if (!href) return null;
    const link = el('a', 'scm-repository-link', '↗'); link.href = href; link.target = '_blank';
    link.rel = 'noopener noreferrer'; link.referrerPolicy = 'no-referrer';
    link.setAttribute('aria-label', `Open ${repository.fullName || repository.name} on its source provider`);
    return link;
  }
  function repositoryRow(repository) {
    const selected = repository.id === scm.repository?.id;
    const row = el('li', `scm-repository${selected ? ' selected' : ''}`);
    const choose = button('', 'scm-repository-select', () => selectRepository(repository));
    choose.setAttribute('aria-pressed', String(selected));
    const copy = el('span', 'scm-repository-copy');
    copy.append(el('strong', '', repository.name), el('small', '', repository.fullName));
    choose.append(el('span', 'scm-repository-symbol', '⑂'), copy, el('span', 'scm-repository-check', selected ? '✓' : '→'));
    row.append(choose);
    const link = repositoryLink(repository);
    if (link) row.append(link);
    return row;
  }
  function repositoriesEmptyState() {
    let heading = 'Source, without the copy-paste.';
    if (scm.repositoryBusy) heading = 'Loading connected source…';
    else if (scm.connectionId) heading = 'No repositories in this view.';
    const empty = el('li', 'operations-empty-state');
    empty.append(el('span', 'operations-empty-symbol', '⑂'), el('h3', '', heading),
      el('p', '', scm.connectionId ? 'Search by repository name. Access is limited to the selected connection’s permissions.' : 'Select a connected account to browse its repositories and branches.'));
    return empty;
  }
  function renderRepositories() {
    const list = $('scm-repositories');
    list.replaceChildren(...scm.repositories.map(repositoryRow));
    if (!scm.repositories.length) list.append(repositoriesEmptyState());
    $('scm-repository-count').textContent = scm.connectionId ? `${scm.repositories.length} LOADED` : 'NO CONNECTION';
    syncSourceControls();
  }
  function repositoryItem(item) {
    return { id: idOf(item.id), name: redactText(item.name), fullName: redactText(item.fullName), defaultBranch: text(item.defaultBranch), webUrl: text(item.webUrl) };
  }
  function pageOf(payload, requested) { return Number.isInteger(payload.page) && payload.page >= 1 ? payload.page : requested; }
  function preferredBranch(previous, defaultBranch) {
    if (scm.branches.includes(previous)) return previous;
    if (scm.branches.includes(defaultBranch)) return defaultBranch;
    return scm.branches[0] || '';
  }
  function branchOptions() {
    const options = scm.branches.map(name => { const option = el('option', '', name); option.value = name; return option; });
    if (!options.length) { const option = el('option', '', 'No branches returned'); option.value = ''; options.push(option); }
    return options;
  }
  function resetRepositories() {
    scm.repositories = []; scm.repository = null; scm.repositoryHasMore = false;
    clearBranches();
  }
  function applyRepositoryPage(payload, append, page) {
    if (!Array.isArray(payload?.repositories)) throw new Error('Invalid repositories.');
    const items = payload.repositories.filter(item => item && idOf(item.id)).map(repositoryItem);
    const existing = append ? scm.repositories : [];
    scm.repositories = [...new Map([...existing, ...items].map(item => [item.id, item])).values()];
    scm.repositoryPage = pageOf(payload, page);
    scm.repositoryHasMore = payload.hasMore === true;
  }
  function applyBranchPage(payload, append, page) {
    if (!Array.isArray(payload?.branches)) throw new Error('Invalid branches.');
    const existing = append ? scm.branches : [];
    scm.branches = [...new Set([...existing, ...payload.branches.map(item => text(item?.name)).filter(Boolean)])];
    scm.branchPage = pageOf(payload, page);
    scm.branchHasMore = payload.hasMore === true;
  }
  async function loadRepositories(append) {
    if (!scm.connectionId || sourceLocked()) return;
    scm.repositoryController?.abort();
    const controller = new AbortController(); scm.repositoryController = controller;
    const version = ++scm.repositoryVersion;
    const connectionId = scm.connectionId;
    const page = append ? scm.repositoryPage + 1 : 1;
    scm.repositoryBusy = true;
    if (!append) resetRepositories();
    renderRepositories();
    status('scm-status', 'Loading repositories from the selected connection…', 'busy');
    try {
      const query = new URLSearchParams({ search: scm.search, page: String(page) });
      const payload = await api(`/api/scm/connections/${encodeURIComponent(connectionId)}/repositories?${query}`, { signal: controller.signal });
      if (version !== scm.repositoryVersion) return;
      applyRepositoryPage(payload, append, page);
      renderRepositories();
      status('scm-status', scm.repositories.length ? 'Repositories loaded. Select one to inspect its branches.' : 'No repositories matched. Try a different search or connection.');
    } catch (error) {
      if (error.name !== 'AbortError' && version === scm.repositoryVersion) status('scm-status', 'Repositories could not be loaded. Check the connection or search again.', 'error');
    } finally {
      if (version === scm.repositoryVersion) { scm.repositoryBusy = false; renderRepositories(); }
    }
  }
  function selectRepository(repository) {
    if (sourceLocked()) return;
    scm.repository = repository;
    clearBranches(); renderRepositories();
    $('scm-selection').textContent = repository.fullName || repository.name;
    void loadBranches(false);
  }
  async function loadBranches(append) {
    if (!scm.connectionId || !scm.repository || sourceLocked()) return;
    scm.branchController?.abort();
    const controller = new AbortController(); scm.branchController = controller;
    const version = ++scm.branchVersion;
    const connectionId = scm.connectionId, repository = scm.repository;
    const page = append ? scm.branchPage + 1 : 1;
    const previous = append ? $('scm-branch').value : '';
    scm.branchBusy = true;
    syncSourceControls();
    status('scm-status', 'Loading repository branches…', 'busy');
    try {
      const query = new URLSearchParams({ repositoryId: repository.id, page: String(page) });
      const payload = await api(`/api/scm/connections/${encodeURIComponent(connectionId)}/branches?${query}`, { signal: controller.signal });
      if (version !== scm.branchVersion) return;
      applyBranchPage(payload, append, page);
      $('scm-branch').replaceChildren(...branchOptions());
      $('scm-branch').value = preferredBranch(previous, repository.defaultBranch);
      status('scm-status', scm.branches.length ? 'Branch selection ready. Checkout happens only when you choose to open the workspace.' : 'No branches returned for this repository.');
    } catch (error) {
      if (error.name !== 'AbortError' && version === scm.branchVersion) status('scm-status', 'Branches could not be loaded. Select the repository again to retry.', 'error');
    } finally {
      if (version === scm.branchVersion) { scm.branchBusy = false; syncSourceControls(); }
    }
  }
  async function checkout() {
    if (sourceLocked() || !scm.repository || !$('scm-branch').value) return;
    const body = { connectionId: scm.connectionId, repositoryId: scm.repository.id, branch: $('scm-branch').value };
    scm.checkout = true;
    syncSourceControls();
    status('scm-status', 'Preparing a local checkout. This can take a moment…', 'busy');
    try {
      const payload = await api('/api/scm/checkout', { method: 'POST', body });
      if (!idOf(payload?.sessionId) || typeof payload.repoPath !== 'string' || !payload.repoPath) throw new Error('Invalid checkout.');
      $('scm-checkout-detail').textContent = `Checkout ready · ${redactText(payload.repoPath)} · branch ${body.branch}`;
      // Bubbles to both document and window listeners; the parent opens the shared session.
      document.dispatchEvent(new CustomEvent('threatlint:workspace', { bubbles: true, detail: { sessionId: payload.sessionId, repoPath: payload.repoPath } }));
      status('scm-status', 'Checkout ready. A shared-workspace handoff was requested; specialist reviews still require an explicit run.');
    } catch {
      status('scm-status', 'The checkout was not acknowledged. Check repository access and the local runner before retrying.', 'error');
    } finally { scm.checkout = false; syncSourceControls(); }
  }

  // Authentication editors are ephemeral DOM fields, never saved profiles.
  function authFieldId(key) { return `runtime-auth-${key}`; }
  function authControl(field) {
    if (field.options) {
      const select = el('select');
      for (const [value, caption] of field.options) { const option = el('option', '', caption); option.value = value; select.append(option); }
      return select;
    }
    const input = field.textarea ? el('textarea', 'operations-code-input') : el('input');
    if (field.textarea) input.rows = field.key === 'storageState' ? 6 : 4;
    else input.type = field.type || 'text';
    input.placeholder = field.placeholder || '';
    input.maxLength = field.maxLength || (field.textarea ? 32000 : 10000);
    input.spellcheck = false; input.setAttribute('autocapitalize', 'off');
    return input;
  }
  function authField(field) {
    const wrapper = el('div', 'operations-field');
    const label = el('label', '', field.label); label.htmlFor = authFieldId(field.key);
    if (field.optional) label.append(el('span', 'subtle', 'optional'));
    const input = authControl(field);
    input.id = authFieldId(field.key); input.name = `runtimeAuth${field.key}`;
    input.required = !field.optional; input.autocomplete = 'off';
    if (field.secret) input.dataset.operationsSecret = 'true';
    input.setAttribute('aria-describedby', 'runtime-auth-help');
    wrapper.append(label, input);
    return wrapper;
  }
  function renderAuthFields() {
    const type = $('runtime-auth-type').value;
    const definition = AUTH[type] || AUTH.none;
    $('runtime-auth-help').textContent = definition.help;
    $('runtime-auth-fields').replaceChildren(...definition.fields.map(authField));
    $('runtime-browser-auth').hidden = type !== 'browser-session';
    if (type === 'none') $('runtime-compare-anonymous').checked = false;
    syncRuntimeControls();
  }
  function clearAuthInputs(resetBrowser = true) {
    for (const input of $('runtime-auth-fields').querySelectorAll('input, textarea')) input.value = '';
    if (resetBrowser) {
      runtime.browser = null;
      $('runtime-browser-status').textContent = 'Browser session cleared from this form. Runner-held sessions expire separately; close any sign-in window you no longer need.';
    }
  }
  function privateHost(hostname) {
    const host = hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true;
    if (host.includes(':')) return host === '::' || host === '::1' || /^(?:f[cd]|fe[89ab]|::ffff:)/i.test(host);
    if (!host.includes('.')) return true;
    const octets = host.split('.').map(Number);
    if (octets.length !== 4 || !octets.every(Number.isInteger)) return false;
    return octets[0] === 0 || octets[0] === 10 || octets[0] === 127 ||
      (octets[0] === 169 && octets[1] === 254) || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168) || (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127);
  }
  function checkedUrl(raw, field, tokenEndpoint = false) {
    let url;
    try { url = new URL(raw); } catch { throw new InputError('Enter a complete HTTP(S) URL.', field); }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
      throw new InputError('Use an HTTP(S) URL without embedded credentials, query strings, or fragments.', field);
    }
    if (privateHost(url.hostname) && !$('runtime-allow-private').checked) {
      throw new InputError('This address requires the explicit private-network / loopback opt-in.', 'runtime-allow-private');
    }
    if (tokenEndpoint && url.protocol !== 'https:' && !privateHost(url.hostname)) {
      throw new InputError('A remote token endpoint must use HTTPS.', field);
    }
    return url.href;
  }
  function authorization() {
    if (!$('runtime-authorized').checked) throw new InputError('Explicitly authorize this target and scope before continuing.', 'runtime-authorized');
    const target = checkedUrl($('runtime-target').value.trim(), 'runtime-target');
    const reason = $('runtime-authorization-reason').value.trim();
    if (!reason) throw new InputError('Describe the authorization context for this environment.', 'runtime-authorization-reason');
    return { target, authorization: { confirmed: true, allowPrivate: $('runtime-allow-private').checked, reason } };
  }
  function browserScope(config) { return JSON.stringify([config.target, config.authorization.allowPrivate, config.authorization.reason]); }
  function parseJson(raw, field, message) {
    try { return JSON.parse(raw); } catch { throw new InputError(message, field); }
  }
  function originPath(value, field) {
    if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || /[\\?#\s]/.test(value) || hasControl(value) || value.length > 2048 || /%(?:2f|5c|3f|23|0[0-9a-f]|1[0-9a-f]|7f)/i.test(value)) {
      throw new InputError('Use origin-relative paths beginning with /, without query strings, fragments, whitespace, or encoded separators.', field);
    }
    const url = new URL(value, 'https://scope.invalid');
    if (url.origin !== 'https://scope.invalid' || url.pathname !== value) throw new InputError('Use normalized paths without dot-segment traversal or URL encoding changes.', field);
    return value;
  }
  function authValue(key, preserveSpace = false) {
    const value = $(authFieldId(key))?.value || '';
    return preserveSpace ? value : value.trim();
  }
  // Control characters (C0 and DEL) are rejected without embedding them in a regex.
  function hasControl(value) {
    for (const char of value) {
      const code = char.codePointAt(0);
      if (code < 0x20 || code === 0x7f) return true;
    }
    return false;
  }
  // Header and cookie values may contain tabs; only line breaks and NUL are rejected, as before.
  function hasBreakOrNul(value) { return value.includes('\r') || value.includes('\n') || value.includes(String.fromCodePoint(0)); }
  const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9a-z-]+$/i;
  const FORBIDDEN_HEADERS = new Set(['__proto__', 'constructor', 'prototype', 'host', 'connection', 'content-length', 'transfer-encoding', 'proxy-authorization', 'proxy-connection']);
  const COOKIE_FIELDS = ['name', 'value', 'domain', 'path', 'expires', 'httpOnly', 'secure', 'sameSite', 'url', 'partitionKey'];
  const OAUTH_FIELDS = { 'oauth-client-credentials': ['clientSecret', 'scope', 'audience'], 'oauth-refresh-token': ['clientSecret', 'refreshToken', 'scope'], 'oauth-password': ['clientSecret', 'username', 'password', 'scope'] };
  const PRESERVED_SPACE = new Set(['clientSecret', 'refreshToken', 'password']);

  function apiKeyAuth(type) {
    const name = authValue('name'), location = authValue('location');
    if (!HEADER_NAME.test(name) || !['header', 'query'].includes(location)) throw new InputError('Use a valid API key name and placement.', authFieldId('name'));
    return { type, name, value: authValue('value', true), location };
  }
  function cookieAuth(type) {
    const cookie = authValue('cookie');
    if (/[\r\n]/.test(cookie)) throw new InputError('Enter a single Cookie header without line breaks.', authFieldId('cookie'));
    return { type, cookie };
  }
  function validHeader(name, value, seen) {
    const lower = name.toLowerCase();
    return HEADER_NAME.test(name) && typeof value === 'string' && !hasBreakOrNul(value) && !seen.has(lower) && !FORBIDDEN_HEADERS.has(lower);
  }
  function headersAuth(type) {
    const field = authFieldId('headers');
    const headers = parseJson(authValue('headers'), field, 'Headers must be a JSON object of header names and string values.');
    const count = headers && typeof headers === 'object' && !Array.isArray(headers) ? Object.keys(headers).length : 0;
    if (count < 1 || count > 30) throw new InputError('Provide between 1 and 30 explicit headers in a JSON object.', field);
    const seen = new Set();
    for (const [name, value] of Object.entries(headers)) {
      if (!validHeader(name, value, seen)) throw new InputError('Use distinct valid header names, string values without line breaks, and no transport or proxy headers.', field);
      seen.add(name.toLowerCase());
    }
    return { type, headers };
  }
  function formLoginAuth(type) {
    const result = { type, loginUrl: checkedUrl(authValue('loginUrl'), authFieldId('loginUrl')), username: authValue('username'), password: authValue('password', true) };
    for (const key of ['usernameField', 'passwordField']) if (authValue(key)) result[key] = authValue(key);
    return result;
  }
  function mtlsAuth(type) {
    const result = { type, cert: authValue('cert', true), key: authValue('key', true) };
    if (authValue('passphrase', true)) result.passphrase = authValue('passphrase', true);
    return result;
  }
  function oauthAuth(type) {
    const result = { type, tokenUrl: checkedUrl(authValue('tokenUrl'), authFieldId('tokenUrl'), true), clientId: authValue('clientId') };
    for (const key of OAUTH_FIELDS[type]) {
      const value = authValue(key, PRESERVED_SPACE.has(key));
      if (value) result[key] = value;
    }
    return result;
  }
  function browserCookie(cookie, field) {
    const valid = cookie && typeof cookie === 'object' && typeof cookie.name === 'string' && typeof cookie.value === 'string' && !hasBreakOrNul(cookie.name + cookie.value);
    if (!valid) throw new InputError('Every browser cookie needs a name and value without control characters.', field);
    return Object.fromEntries(COOKIE_FIELDS.filter(key => Object.hasOwn(cookie, key)).map(key => [key, cookie[key]]));
  }
  function browserStateAuth(type) {
    const field = authFieldId('storageState');
    const storageState = parseJson(authValue('storageState'), field, 'Browser state must be valid JSON with a cookies array.');
    if (!storageState || !Array.isArray(storageState.cookies) || storageState.cookies.length > 200) throw new InputError('Browser state must include a cookies array with at most 200 cookies.', field);
    return { type, storageState: { cookies: storageState.cookies.map(cookie => browserCookie(cookie, field)) } };
  }
  function browserSessionAuth(type, config) {
    if (!runtime.browser?.ready || runtime.browser.scope !== browserScope(config)) throw new InputError('Finish manual browser sign-in for this exact target and authorization first.', 'runtime-browser-start');
    return { type, sessionId: runtime.browser.id };
  }
  const AUTH_BUILDERS = {
    none: type => ({ type }),
    bearer: type => ({ type, token: authValue('token') }),
    basic: type => ({ type, username: authValue('username'), password: authValue('password', true) }),
    'api-key': apiKeyAuth, cookie: cookieAuth, headers: headersAuth, 'form-login': formLoginAuth, mtls: mtlsAuth,
    'oauth-client-credentials': oauthAuth, 'oauth-refresh-token': oauthAuth, 'oauth-password': oauthAuth,
    'browser-state': browserStateAuth, 'browser-session': browserSessionAuth,
  };
  function primaryAuth(config) {
    const type = $('runtime-auth-type').value;
    if (!Object.hasOwn(AUTH, type) || !Object.hasOwn(AUTH_BUILDERS, type)) throw new InputError('Choose a supported authentication type.', 'runtime-auth-type');
    const missing = AUTH[type].fields.find(field => !field.optional && !authValue(field.key, field.key === 'password'));
    if (missing) throw new InputError('Complete the required authentication fields.', authFieldId(missing.key));
    return AUTH_BUILDERS[type](type, config);
  }
  function scanPaths() {
    const rawPaths = parseJson($('runtime-paths').value, 'runtime-paths', 'Paths must be a JSON array, for example ["/", "/api/private"].');
    if (!Array.isArray(rawPaths) || !rawPaths.length || rawPaths.length > 100) throw new InputError('Provide between 1 and 100 explicit paths in a JSON array.', 'runtime-paths');
    return [...new Set(rawPaths.map(path => originPath(path, 'runtime-paths')))];
  }
  const validStatus = code => Number.isInteger(code) && code >= 100 && code <= 599;
  function scanAssertion(assertion, paths) {
    const path = originPath(assertion?.path, 'runtime-assertions');
    const statuses = assertion.expectedAnonymousStatus;
    const valid = paths.includes(path) && Array.isArray(statuses) && statuses.length > 0 && statuses.every(validStatus);
    if (!valid) throw new InputError('Each assertion needs an in-scope path and an array of numeric HTTP statuses, such as [401,403].', 'runtime-assertions');
    return { path, expectedAnonymousStatus: [...new Set(statuses)] };
  }
  function scanAssertions(paths) {
    const rawAssertions = $('runtime-assertions').value.trim();
    const parsed = rawAssertions ? parseJson(rawAssertions, 'runtime-assertions', 'Assertions must be a JSON array of paths and expectedAnonymousStatus arrays.') : [];
    if (!Array.isArray(parsed) || parsed.length > 100) throw new InputError('Assertions must be a JSON array with at most 100 entries.', 'runtime-assertions');
    return parsed.map(assertion => scanAssertion(assertion, paths));
  }
  const LIMIT_FIELDS = [['maxRequests', 'runtime-max-requests', 1, 100], ['timeoutMs', 'runtime-timeout', 500, 30000], ['delayMs', 'runtime-delay', 0, 10000]];
  function scanLimits() {
    const limits = {};
    for (const [key, field, min, max] of LIMIT_FIELDS) {
      const value = Number($(field).value);
      if (!Number.isInteger(value) || value < min || value > max) throw new InputError('Choose a request budget and timing within the displayed limits.', field);
      limits[key] = value;
    }
    return limits;
  }
  function scanRequest() {
    const config = authorization();
    const paths = scanPaths();
    const assertions = scanAssertions(paths);
    const type = $('runtime-auth-type').value;
    const compareAnonymous = type !== 'none' && $('runtime-compare-anonymous').checked;
    if (assertions.length && type !== 'none' && !compareAnonymous) throw new InputError('Enable anonymous comparison to evaluate anonymous assertions with a primary authenticated identity.', 'runtime-compare-anonymous');
    const limits = scanLimits();
    return { ...config, paths, auth: primaryAuth(config), roles: roleProfiles(), checks: { compareAnonymous }, assertions, limits };
  }
  // Additional roles use simple token-style workflows so each row stays compact.
  const ROLE_TYPES = [['bearer', 'Bearer token'], ['basic', 'HTTP Basic'], ['cookie', 'Cookie header'], ['api-key', 'API key header']];
  function addRole() {
    const list = $('runtime-roles');
    if (list.children.length >= 4) { status('runtime-status', 'Compare at most four additional roles.', 'error'); return; }
    const index = list.children.length;
    const row = el('li', 'runtime-role');
    const label = el('input'); label.placeholder = 'Role label · e.g. viewer'; label.maxLength = 60; label.setAttribute('aria-label', `Role ${index + 1} label`); label.dataset.role = 'label';
    const type = el('select'); type.setAttribute('aria-label', `Role ${index + 1} authentication`); type.dataset.role = 'type';
    for (const [value, caption] of ROLE_TYPES) { const option = el('option', '', caption); option.value = value; type.append(option); }
    const secret = el('input'); secret.type = 'password'; secret.autocomplete = 'off'; secret.placeholder = 'token · user:password · cookie · Header=value'; secret.dataset.role = 'secret'; secret.dataset.operationsSecret = 'true';
    secret.setAttribute('aria-label', `Role ${index + 1} credential`);
    row.append(label, type, secret, button('×', 'icon-button', () => { row.remove(); }, `Remove role ${index + 1}`));
    list.append(row); label.focus();
  }
  function roleProfiles() {
    return [...$('runtime-roles').children].map((row, index) => {
      const value = field => row.querySelector(`[data-role="${field}"]`).value;
      const label = value('label').trim(), type = value('type'), secret = value('secret');
      if (!label || !secret) throw new InputError(`Complete role ${index + 1} or remove it.`, null);
      if (type === 'bearer') return { label, auth: { type, token: secret.trim() } };
      if (type === 'cookie') return { label, auth: { type, cookie: secret.trim() } };
      if (type === 'basic') {
        const colon = secret.indexOf(':');
        if (colon < 1) throw new InputError(`Role ${index + 1}: use user:password for HTTP Basic.`, null);
        return { label, auth: { type, username: secret.slice(0, colon), password: secret.slice(colon + 1) } };
      }
      const equals = secret.indexOf('=');
      if (equals < 1) throw new InputError(`Role ${index + 1}: use Header-Name=value for an API key.`, null);
      return { label, auth: { type: 'api-key', name: secret.slice(0, equals).trim(), value: secret.slice(equals + 1), location: 'header' } };
    });
  }
  function clearRoleSecrets() { for (const input of $('runtime-roles').querySelectorAll('[data-role="secret"]')) input.value = ''; }

  function running() { return !runtime.demo && !!runtime.scan && LIVE_STATES.has(runtime.scan.status); }
  function runtimeLocked() { return runtime.submitting || runtime.demoLoading || runtime.browserBusy || running() || (!!runtime.scanId && !runtime.scan); }
  function syncRuntimeControls() {
    const locked = runtimeLocked();
    $('runtime-configuration').disabled = locked;
    $('runtime-start').disabled = locked || !$('runtime-authorized').checked || ($('runtime-auth-type').value === 'browser-session' && !runtime.browser?.ready);
    $('runtime-start').textContent = runtime.submitting ? 'Starting authorized scan…' : '▶ Start authorized scan';
    $('runtime-demo').disabled = locked;
    $('runtime-clear-auth').disabled = locked;
    $('runtime-compare-anonymous').disabled = locked || $('runtime-auth-type').value === 'none';
    $('runtime-browser-start').disabled = locked || !$('runtime-authorized').checked || !$('runtime-target').value.trim();
    $('runtime-browser-finish').disabled = locked || !runtime.browser || runtime.browser.ready || !$('runtime-authorized').checked;
    $('runtime-refresh').disabled = !runtime.scanId || runtime.demo || runtime.polling || runtime.submitting;
    $('runtime-cancel').disabled = !running() || runtime.cancelRequested;
    const transferable = !!runtime.scan && !runtime.demo && TERMINAL_STATES.has(runtime.scan.status);
    $('runtime-review-evidence').disabled = !transferable || runtime.polling;
    $('runtime-ask').disabled = !transferable;
    syncExportLinks(transferable);
  }
  function syncExportLinks(transferable) {
    const scan = encodeURIComponent(runtime.scanId);
    for (const format of ['json', 'md', 'html']) {
      const link = $(`runtime-export-${format}`);
      link.setAttribute('aria-disabled', String(!transferable)); link.tabIndex = transferable ? 0 : -1;
      if (transferable) {
        link.href = `/api/runtime/scans/${scan}/export?format=${format}`;
        link.download = `runtime-evidence.${format}`; link.referrerPolicy = 'no-referrer';
      } else link.removeAttribute('href');
    }
  }
  function scopeEdited(event) {
    if (event.target.id !== 'runtime-authorized') $('runtime-authorized').checked = false;
    if (runtime.browser) {
      let matches = false;
      try {
        const target = new URL($('runtime-target').value).href;
        matches = runtime.browser.scope === JSON.stringify([target, $('runtime-allow-private').checked, $('runtime-authorization-reason').value.trim()]);
      } catch { /* An incomplete target is not the signed-in scope. */ }
      if (!matches) {
        runtime.browser = null;
        $('runtime-browser-status').textContent = 'The target or authorization changed. Complete manual sign-in again for the new scope.';
      }
    }
    syncRuntimeControls();
  }
  async function startBrowser() {
    if (runtimeLocked()) return;
    let config;
    try { config = authorization(); } catch (error) { localError(error, 'runtime-status', 'Check the authorized target.'); return; }
    runtime.browserBusy = true; runtime.browser = null; syncRuntimeControls();
    $('runtime-browser-status').textContent = 'Asking the local runner to open its sign-in browser…';
    try {
      const payload = await api('/api/runtime/auth/browser/start', { method: 'POST', body: config });
      if (!idOf(payload?.id) || payload.mode !== 'interactive') throw new Error('Invalid browser response.');
      runtime.browser = { id: idOf(payload.id), scope: browserScope(config), ready: false };
      $('runtime-browser-status').textContent = 'Complete sign-in manually in the runner-opened browser, including any SSO, MFA, passkey, or SAML steps. Then choose Finish sign-in.';
      status('runtime-status', 'Manual sign-in requested. No scan has started and authentication is not yet established.');
    } catch (error) {
      const unavailable = error.status === 501 || error.status === 503;
      $('runtime-browser-status').textContent = unavailable ? 'Interactive sign-in is unavailable on this runner. Use imported cookies or an explicit token / header instead.' : 'The runner could not open a sign-in browser. Check local browser automation availability or use another explicit authentication method.';
      status('runtime-status', 'Manual browser sign-in could not be started. No authentication bypass or automatic SSO fallback was attempted.', 'error');
    } finally { runtime.browserBusy = false; syncRuntimeControls(); }
  }
  async function finishBrowser() {
    if (runtimeLocked() || !runtime.browser || runtime.browser.ready) return;
    let config;
    try {
      config = authorization();
      if (runtime.browser.scope !== browserScope(config)) throw new InputError('The target changed. Start a new manual sign-in for this scope.', 'runtime-browser-start');
    } catch (error) { localError(error, 'runtime-status', 'Check the authorized target.'); return; }
    runtime.browserBusy = true; syncRuntimeControls();
    $('runtime-browser-status').textContent = 'Finishing the manually completed sign-in…';
    try {
      const payload = await api(`/api/runtime/auth/browser/${encodeURIComponent(runtime.browser.id)}/finish`, { method: 'POST', body: {} });
      if (!idOf(payload?.id) || payload.type !== 'browser-session') throw new Error('Invalid browser session.');
      runtime.browser = { id: idOf(payload.id), scope: browserScope(config), ready: true };
      $('runtime-browser-status').textContent = 'Cookie session ready in runner memory. This does not automate client JavaScript or replay localStorage tokens. Start the authorized scan when ready.';
      status('runtime-status', 'Manual browser session is ready for this target. Authentication effectiveness will be observed, not assumed.');
    } catch {
      $('runtime-browser-status').textContent = 'Sign-in could not be finished. Complete the manual steps in the runner browser, then retry Finish sign-in. No session has been marked ready.';
      status('runtime-status', 'The browser session was not acknowledged. No scan has started.', 'error');
    } finally { runtime.browserBusy = false; syncRuntimeControls(); }
  }

  // Poll once at a time, schedule only after the response, and stop at a terminal state.
  function stopPolling() {
    clearTimeout(runtime.pollTimer); runtime.pollTimer = null;
    runtime.pollController?.abort(); runtime.pollController = null;
    runtime.pollVersion += 1; runtime.polling = false;
  }
  async function startScan(event) {
    event.preventDefault();
    if (runtimeLocked()) return;
    let body;
    try { body = scanRequest(); } catch (error) { localError(error, 'runtime-status', 'Check the scan configuration before continuing.'); return; }
    stopPolling();
    runtime.submitting = true; runtime.demo = false; runtime.scan = null; runtime.scanId = '';
    runtime.selectedNode = ''; runtime.announcedStatus = ''; runtime.cancelRequested = false;
    clearAuthInputs(); clearRoleSecrets(); renderScan(); syncRuntimeControls();
    status('runtime-status', 'Submitting the explicitly authorized scope to the local runner…', 'busy');
    $('runtime-scan-status').textContent = 'STARTING REQUEST';
    try {
      const payload = await api('/api/runtime/scans', { method: 'POST', body });
      if (!idOf(payload?.id)) throw new Error('Invalid scan response.');
      runtime.scanId = idOf(payload.id);
      $('runtime-scan-status').textContent = 'AWAITING STATE';
      status('runtime-status', 'Scan accepted. Waiting for runner-returned execution evidence…', 'busy');
      runtime.submitting = false;
      void refreshScan();
    } catch {
      status('runtime-status', 'The runner did not acknowledge the scan. Auth fields have been cleared. Check runner state before trying again.', 'error');
      $('runtime-scan-status').textContent = 'NOT ACKNOWLEDGED';
    } finally { runtime.submitting = false; syncRuntimeControls(); }
  }
  async function refreshScan() {
    if (!runtime.scanId || runtime.demo || runtime.polling || runtime.submitting) return;
    clearTimeout(runtime.pollTimer); runtime.pollTimer = null;
    const id = runtime.scanId, version = runtime.pollVersion;
    const controller = new AbortController(); runtime.pollController = controller;
    runtime.polling = true; syncRuntimeControls();
    let again = false;
    try {
      const payload = await api(`/api/runtime/scans/${encodeURIComponent(id)}`, { signal: controller.signal });
      if (version !== runtime.pollVersion || id !== runtime.scanId) return;
      const snapshot = safeScan(payload);
      if (snapshot.id !== id) throw new Error('Mismatched scan state.');
      runtime.scan = snapshot;
      if (TERMINAL_STATES.has(snapshot.status)) runtime.cancelRequested = false;
      renderScan();
      again = LIVE_STATES.has(snapshot.status);
      announceScanStatus(snapshot.status);
    } catch (error) {
      if (error.name !== 'AbortError' && version === runtime.pollVersion) {
        runtime.announcedStatus = '';
        status('runtime-status', 'Scan state could not be refreshed. Automatic polling is paused to avoid repeated requests. Use Refresh to resume; the runner may still be active.', 'error');
      }
    } finally {
      if (version === runtime.pollVersion) finishPoll(again);
    }
  }
  function finishPoll(again) {
    runtime.polling = false; runtime.pollController = null; syncRuntimeControls();
    if (again) runtime.pollTimer = setTimeout(() => { runtime.pollTimer = null; void refreshScan(); }, 1200);
  }
  function scanStatusMessage(state) {
    if (LIVE_STATES.has(state)) return ['The runner is observing the authorized scope. Only returned observations appear below.', 'busy'];
    if (FAILED_STATES.has(state)) return ['The runner reports a failed scan. Any displayed observations are partial; review coverage before drawing conclusions.', 'error'];
    if (TERMINAL_STATES.has(state)) return ['Scan ended. Review observations and untested coverage; neither completion nor zero findings is a security approval.', ''];
    return ['The runner returned an unrecognized state. Automatic polling is paused; use Refresh to check it.', ''];
  }
  function announceScanStatus(state) {
    if (runtime.announcedStatus === state) return;
    runtime.announcedStatus = state;
    status('runtime-status', ...scanStatusMessage(state));
  }
  async function cancelScan() {
    if (!running() || runtime.cancelRequested) return;
    runtime.cancelRequested = true; syncRuntimeControls();
    status('runtime-status', 'Requesting a stop. Waiting for the runner to acknowledge its final state…', 'busy');
    try {
      await api(`/api/runtime/scans/${encodeURIComponent(runtime.scanId)}/cancel`, { method: 'POST', body: {} });
      status('runtime-status', 'Stop requested. Only a runner-returned terminal state confirms the scan has ended.', 'busy');
      if (!runtime.polling) void refreshScan();
    } catch {
      runtime.cancelRequested = false;
      status('runtime-status', 'The stop request was not acknowledged. The scan may still be active; refresh its state or retry Stop scan.', 'error');
    } finally { syncRuntimeControls(); }
  }
  async function loadDemo() {
    if (runtimeLocked()) return;
    runtime.demoLoading = true; syncRuntimeControls();
    status('runtime-status', 'Loading a synthetic demonstration from the local runner. No target request is being made.', 'busy');
    try {
      const payload = await api('/api/examples/runtime');
      const snapshot = safeScan(payload?.scan || payload);
      snapshot.example = true; snapshot.synthetic = true;
      stopPolling(); runtime.scan = snapshot; runtime.scanId = ''; runtime.demo = true; runtime.selectedNode = '';
      runtime.cancelRequested = false; renderScan();
      status('runtime-status', 'SYNTHETIC DEMONSTRATION. All displayed evidence is illustrative; no target was contacted. Configure and authorize your own scope to run a real scan.');
    } catch {
      status('runtime-status', 'The demonstration is unavailable on this runner. No sample results were invented and no target was contacted.', 'error');
    } finally { runtime.demoLoading = false; syncRuntimeControls(); }
  }

  // Structured execution evidence only. No HTML report fragments or invented graph edges.
  function requestRecords(scan) {
    if (Array.isArray(scan?.requests)) return scan.requests;
    if (Array.isArray(scan?.requests?.items)) return scan.requests.items;
    if (Array.isArray(scan?.requests?.records)) return scan.requests.records;
    return [];
  }
  function count(value) { return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null; }
  function httpStatus(request) {
    const value = request?.statusCode ?? request?.status ?? request?.response?.statusCode ?? request?.response?.status;
    const code = Number(value);
    return Number.isInteger(code) && code >= 100 && code <= 599 ? code : null;
  }
  function timeLabel(value, fallback = 'Time not supplied') {
    if (!value) return fallback;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? fallback : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
  function renderScanLabels() {
    $('runtime-demo-banner').hidden = !runtime.demo;
    $('runtime-chain-title').textContent = runtime.demo ? 'The demonstration evidence chain' : 'The live evidence chain';
    $('runtime-events-title').textContent = runtime.demo ? 'Demonstration events' : 'Observed events';
    $('runtime-requests-label').textContent = runtime.demo ? 'Simulated requests' : 'Requests executed';
  }
  function scanBadgeText(scan) {
    if (runtime.demo) return 'DEMONSTRATION';
    return scan ? scan.status.toUpperCase().replaceAll('-', ' ') : 'NOT RUN';
  }
  function renderScanBadge(scan) {
    const badge = $('runtime-scan-status');
    badge.textContent = scanBadgeText(scan);
    badge.className = 'operations-pill';
    if (running()) badge.classList.add('is-running');
    if (!runtime.demo && FAILED_STATES.has(scan?.status)) badge.classList.add('is-failed');
    if (!runtime.demo && STOPPED_STATES.has(scan?.status)) badge.classList.add('is-stopped');
  }
  function targetSummary(scan) {
    if (!scan) return 'No target contacted by this view. No execution evidence yet.';
    const target = text(scan.target, 'Target not supplied');
    if (runtime.demo) return `Synthetic fixture · ${target} · no target contacted`;
    const finished = scan.finishedAt ? ' → ' + timeLabel(scan.finishedAt) : '';
    return `${target} · ${timeLabel(scan.startedAt, 'Start time not supplied')}${finished}`;
  }
  function totalRequests(scan) {
    const direct = count(scan.requests);
    if (direct !== null) return direct;
    if (Array.isArray(scan.requests)) return scan.requests.length;
    return count(scan.requests?.total) ?? count(scan.requests?.count);
  }
  // Counts from per-request records when present, otherwise from runner-supplied coverage totals.
  function scanMetrics(scan) {
    if (!scan) return { total: null, responses: null, denied: null, findings: null };
    const records = requestRecords(scan), responded = records.filter(record => httpStatus(record) !== null);
    const fromRecords = records.length > 0;
    return {
      total: totalRequests(scan),
      responses: fromRecords ? responded.length : count(scan.coverage?.responseCount),
      denied: fromRecords ? responded.filter(record => [401, 403].includes(httpStatus(record))).length : count(scan.coverage?.deniedResponses),
      findings: scan.findings.length,
    };
  }
  function renderScan() {
    const scan = runtime.scan;
    renderScanLabels();
    renderScanBadge(scan);
    $('runtime-target-summary').textContent = targetSummary(scan);
    const metrics = scanMetrics(scan);
    $('runtime-metric-requests').textContent = metrics.total ?? '—';
    $('runtime-metric-responses').textContent = metrics.responses ?? '—';
    $('runtime-metric-denied').textContent = metrics.denied ?? '—';
    $('runtime-metric-findings').textContent = metrics.findings ?? '—';
    renderGraph(); renderEvents(); renderFindings(); renderRequests(); renderCoverage(); syncRuntimeControls();
  }
  function graphData() {
    const nodes = (runtime.scan?.nodes || []).filter(node => node && typeof node === 'object' && idOf(node.id) && STAGES.some(stage => stage.kinds.includes(node.kind)))
      .map(node => ({ ...node, id: idOf(node.id), status: NODE_STATES.has(node.status) ? node.status : 'not-tested', label: text(node.label, 'Unlabelled observation') }));
    const unique = [...new Map(nodes.map(node => [node.id, node])).values()];
    const ids = new Set(unique.map(node => node.id));
    const edges = (runtime.scan?.edges || []).filter(edge => edge && ids.has(idOf(edge.from)) && ids.has(idOf(edge.to))).map(edge => ({ from: idOf(edge.from), to: idOf(edge.to), label: text(edge.label) }));
    if (!$('runtime-chain-only')?.checked) return { nodes: unique, edges };
    // Keep only nodes on a path that reaches a finding: ancestors and descendants of every finding.
    const keep = new Set();
    for (const node of unique.filter(item => item.kind === 'finding')) for (const id of chainOf(node.id, edges)) keep.add(id);
    return { nodes: unique.filter(node => keep.has(node.id)), edges: edges.filter(edge => keep.has(edge.from) && keep.has(edge.to)) };
  }
  function chainOf(id, edges) {
    const result = new Set([id]);
    for (const [forward, backward] of [['from', 'to'], ['to', 'from']]) {
      const queue = [id];
      while (queue.length) {
        const current = queue.shift();
        for (const edge of edges) if (edge[forward] === current && !result.has(edge[backward])) { result.add(edge[backward]); queue.push(edge[backward]); }
      }
    }
    return result;
  }
  function markChain() {
    const { edges } = graphData();
    const chain = runtime.selectedNode ? chainOf(runtime.selectedNode, edges) : new Set();
    for (const [nodeId, element] of runtime.nodeElements) {
      element.classList.toggle('in-chain', chain.has(nodeId) && nodeId !== runtime.selectedNode);
      element.classList.toggle('out-of-chain', chain.size > 1 && !chain.has(nodeId));
    }
    return chain;
  }
  function nodeCard(node, stage) {
    const hypothesis = node.kind === 'impact';
    const card = button('', `runtime-node is-${node.status}${hypothesis ? ' is-hypothesis' : ''}`, () => selectNode(node.id));
    card.dataset.runtimeNodeId = node.id;
    card.setAttribute('aria-pressed', String(runtime.selectedNode === node.id));
    const prefix = runtime.demo ? 'Synthetic demonstration · ' : '';
    const state = hypothesis ? 'impact hypothesis, not validated' : node.status;
    card.setAttribute('aria-label', `${prefix}${stage.label} · ${node.label} · ${state}`);
    const kind = el('span', 'runtime-node-type'); kind.append(el('b', '', stage.icon), document.createTextNode(hypothesis ? 'Hypothesis' : node.kind));
    card.append(kind, el('strong', '', node.label));
    const detail = typeof node.detail === 'string' ? node.detail : '';
    if (detail) card.append(el('small', '', detail.length > 110 ? detail.slice(0, 110) + '…' : detail));
    card.append(el('span', 'runtime-node-status', hypothesis ? 'Not validated' : node.status.replaceAll('-', ' ')));
    runtime.nodeElements.set(node.id, card);
    return card;
  }
  function emptyStage(index) {
    const empty = el('div', 'runtime-stage-empty');
    empty.append(el('span', '', 'NOT TESTED'), document.createTextNode(index === 5 ? 'No validated impact evidence. No impact is inferred.' : 'No execution observation returned for this stage.'));
    return empty;
  }
  function stageSection(stage, index, nodes) {
    const section = el('section', 'runtime-stage');
    const heading = el('h3', 'runtime-stage-heading'); heading.id = `runtime-stage-${index}`;
    heading.append(el('span', '', String(index + 1).padStart(2, '0')), document.createTextNode(stage.label));
    section.setAttribute('aria-labelledby', heading.id);
    const list = el('div', 'runtime-stage-nodes');
    const members = nodes.filter(node => stage.kinds.includes(node.kind));
    list.append(...members.map(node => nodeCard(node, stage)));
    if (!members.length) list.append(emptyStage(index));
    section.append(heading, list);
    return section;
  }
  function renderGraph() {
    const data = graphData();
    const signature = JSON.stringify([runtime.demo, data.nodes, data.edges]);
    if (signature === runtime.graphSignature) { scheduleEdges(); return; }
    runtime.graphSignature = signature;
    const focusedId = document.activeElement?.dataset?.runtimeNodeId;
    runtime.nodeElements.clear();
    if (!data.nodes.some(node => node.id === runtime.selectedNode)) runtime.selectedNode = data.nodes[0]?.id || '';
    $('runtime-graph-stages').replaceChildren(...STAGES.map((stage, index) => stageSection(stage, index, data.nodes)));
    renderNodeDetail(); markChain();
    if (focusedId) runtime.nodeElements.get(focusedId)?.focus({ preventScroll: true });
    scheduleEdges();
  }
  function selectNode(id) {
    runtime.selectedNode = id;
    for (const [nodeId, element] of runtime.nodeElements) element.setAttribute('aria-pressed', String(id === nodeId));
    renderNodeDetail(); markChain(); scheduleEdges();
  }
  function nodePill(node) {
    if (node.kind === 'impact') return 'IMPACT HYPOTHESIS / NOT VALIDATED';
    return `${node.kind.toUpperCase()} / ${node.status.toUpperCase().replaceAll('-', ' ')}`;
  }
  function nodeEvidence(node) {
    const parts = [el('span', 'operations-pill', nodePill(node))];
    if (node.detail) parts.push(el('p', 'small subtle', pretty(node.detail)));
    if (node.kind === 'impact') parts.push(el('p', 'small subtle', 'A connected impact node is a hypothesis. This observer does not establish exploit success or business impact.'));
    if (node.evidence == null) parts.push(el('p', 'small subtle', 'No supporting evidence was returned for this node. Its label or graph position alone does not establish a finding.'));
    else parts.push(el('pre', '', pretty(node.evidence)));
    return parts;
  }
  function chainPath(node, nodes, edges) {
    const chainNodes = nodes.filter(item => chainOf(node.id, edges).has(item.id));
    if (chainNodes.length < 2) return [];
    const path = el('ol', 'runtime-chain-path');
    for (const stage of STAGES) {
      for (const item of chainNodes.filter(candidate => stage.kinds.includes(candidate.kind))) {
        const step = el('li', `is-${item.status}${item.id === node.id ? ' current' : ''}`);
        step.append(el('b', '', stage.label), document.createTextNode(item.label));
        path.append(step);
      }
    }
    return [el('p', 'runtime-node-link-label', 'FULL ATTACK CHAIN'), path];
  }
  function connectionRow(edge, node, nodes) {
    const outgoing = edge.from === node.id;
    const otherId = outgoing ? edge.to : edge.from;
    const other = nodes.find(item => item.id === otherId);
    const row = el('li');
    row.append(button(`${outgoing ? '→' : '←'} ${other?.label || otherId}`, 'text-button', () => selectNode(otherId)));
    if (edge.label) row.append(el('span', '', `· ${edge.label}`));
    return row;
  }
  function connectionList(node, nodes, edges) {
    const connections = edges.filter(edge => edge.from === node.id || edge.to === node.id);
    if (!connections.length) return [];
    const list = el('ul', 'runtime-node-links');
    list.append(...connections.map(edge => connectionRow(edge, node, nodes)));
    return [el('p', 'runtime-node-link-label', 'RUNNER-RETURNED CONNECTIONS'), list];
  }
  function renderNodeDetail() {
    const { nodes, edges } = graphData();
    const node = nodes.find(item => item.id === runtime.selectedNode);
    const detail = $('runtime-node-detail'); detail.replaceChildren();
    detail.append(el('div', 'eyebrow', runtime.demo ? 'SYNTHETIC DEMONSTRATION NODE' : 'NODE INSPECTOR'));
    const title = el('h3', '', node ? node.label : 'Evidence has a context.'); title.id = 'runtime-node-detail-title';
    detail.append(title);
    if (!node) { detail.append(el('p', 'small subtle', 'Select a returned node to inspect its evidence and connected steps. No graph results have been invented.')); return; }
    detail.append(...nodeEvidence(node), ...chainPath(node, nodes, edges), ...connectionList(node, nodes, edges));
  }
  function scheduleEdges() {
    if (runtime.graphFrame !== null) return;
    runtime.graphFrame = requestAnimationFrame(() => { runtime.graphFrame = null; drawEdges(); });
  }
  const roundTenth = number => Math.round(number * 10) / 10;
  // Side-by-side cards connect horizontally; stacked or distant cards connect vertically.
  function edgeGeometry(from, to, bounds) {
    if (to.left > from.right + 8 && Math.abs(to.top - from.top) < Math.max(from.height, to.height) + 50) {
      const start = [from.right - bounds.left + 2, from.top - bounds.top + from.height / 2];
      const end = [to.left - bounds.left - 2, to.top - bounds.top + to.height / 2];
      const middle = (start[0] + end[0]) / 2;
      return { end, controls: [[middle, start[1]], [middle, end[1]]], start };
    }
    const down = to.top >= from.top;
    const start = [from.left - bounds.left + from.width / 2, (down ? from.bottom + 2 : from.top - 2) - bounds.top];
    const end = [to.left - bounds.left + to.width / 2, (down ? to.top - 2 : to.bottom + 2) - bounds.top];
    const middle = (start[1] + end[1]) / 2;
    return { end, controls: [[start[0], middle], [end[0], middle]], start };
  }
  function edgePath({ start, controls, end }) {
    const point = ([x, y]) => `${roundTenth(x)} ${roundTenth(y)}`;
    return `M${point(start)} C${point(controls[0])} ${point(controls[1])} ${point(end)}`;
  }
  function edgeElements(edge, geometry, flags) {
    const hypothesisClass = flags.hypothesis ? ' hypothesis' : '';
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('class', `runtime-edge${hypothesisClass}${flags.selected ? ' selected' : ''}`); path.setAttribute('d', edgePath(geometry));
    const end = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    end.setAttribute('class', `runtime-edge-end${hypothesisClass}`);
    end.setAttribute('cx', String(roundTenth(geometry.end[0]))); end.setAttribute('cy', String(roundTenth(geometry.end[1]))); end.setAttribute('r', '2.4');
    return [path, end];
  }
  function drawEdges() {
    const board = $('runtime-graph-board'), svg = $('runtime-graph-edges');
    if (!board.clientWidth || !board.clientHeight || $('view-runtime').hidden) return;
    const bounds = board.getBoundingClientRect();
    svg.setAttribute('viewBox', `0 0 ${board.clientWidth} ${board.clientHeight}`);
    svg.replaceChildren();
    const data = graphData(), byId = new Map(data.nodes.map(node => [node.id, node]));
    const chain = runtime.selectedNode ? chainOf(runtime.selectedNode, data.edges) : new Set();
    const isImpact = id => byId.get(id)?.kind === 'impact';
    for (const edge of data.edges) {
      const from = runtime.nodeElements.get(edge.from)?.getBoundingClientRect();
      const to = runtime.nodeElements.get(edge.to)?.getBoundingClientRect();
      if (!from || !to) continue;
      const flags = { hypothesis: isImpact(edge.from) || isImpact(edge.to), selected: chain.size > 1 && chain.has(edge.from) && chain.has(edge.to) };
      svg.append(...edgeElements(edge, edgeGeometry(from, to, bounds), flags));
    }
  }
  function eventMessage(event) {
    if (typeof event === 'string') return event;
    return text(event?.message || event?.label || event?.title || event?.type, 'Event returned without a description.');
  }
  function eventRow(event) {
    const row = el('li', `runtime-event${event?.status === 'failed' ? ' is-failed' : ''}`);
    row.append(el('span', 'runtime-event-time', timeLabel(event?.timestamp || event?.at || event?.time)), el('p', '', eventMessage(event)));
    const hasEvidence = event && typeof event === 'object' && (event.detail != null || event.evidence != null);
    if (hasEvidence) {
      const details = el('details'); details.append(el('summary', '', 'Inspect event evidence'), el('pre', 'runtime-evidence-pre', pretty(event.evidence ?? event.detail))); row.append(details);
    }
    return row;
  }
  function eventCountLabel(events) {
    if (!runtime.scan) return 'NOT RUN';
    return `${events.length} ${runtime.demo ? 'SYNTHETIC' : 'RETURNED'}`;
  }
  function renderEvents() {
    const events = runtime.scan?.events || [], list = $('runtime-events');
    $('runtime-event-count').textContent = eventCountLabel(events);
    list.replaceChildren(...events.slice(-200).map(eventRow));
    if (!events.length) list.append(el('li', 'operations-empty-note', runtime.scan ? 'No event observations were returned.' : 'Events appear only after the runner returns them.'));
    if (events.length > 200) list.prepend(el('li', 'operations-empty-note', 'Showing the latest 200 returned events. The export contains the available snapshot.'));
  }
  const KNOWN_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'INFORMATIONAL']);
  function findingCard(finding) {
    const item = typeof finding === 'object' && finding !== null ? finding : { description: text(finding) };
    const card = el('article', 'runtime-finding'), heading = el('div', 'runtime-finding-head');
    const severity = text(item.severity).toUpperCase();
    heading.append(el('h3', '', text(item.title || item.label || item.id, 'Returned observation')), el('span', 'runtime-finding-severity', KNOWN_SEVERITIES.has(severity) ? severity : 'REVIEW'));
    card.append(heading, el('p', '', text(item.description || item.detail || item.summary || item.message, 'Review the returned evidence and scope before assigning significance.')),
      el('p', '', runtime.demo ? 'Synthetic observation. Not evidence from your environment.' : 'Runner-returned observation. Not an independently confirmed exploit.'));
    const details = el('details'); details.append(el('summary', '', 'Inspect returned evidence'), el('pre', 'runtime-evidence-pre', pretty(item))); card.append(details);
    return card;
  }
  function renderFindings() {
    const findings = runtime.scan?.findings || [], container = $('runtime-findings');
    $('runtime-findings-count').textContent = runtime.scan ? findings.length : '—';
    container.replaceChildren(...findings.map(findingCard));
    if (!findings.length) container.append(el('p', 'operations-empty-note', runtime.scan ? 'No finding observations returned within this scope. Untested paths, identities, and impacts remain unknown.' : 'No evidence loaded. This is not a clean bill of health.'));
  }
  function identityLabel(record) {
    if (typeof record?.identity === 'object') return text(record.identity?.label || record.identity?.name || record.identity?.type, 'Not supplied');
    return text(record?.identity || record?.profile, 'Not supplied');
  }
  function requestRow(record) {
    const row = el('tr'), code = httpStatus(record);
    const milliseconds = count(record?.durationMs ?? record?.elapsedMs);
    row.append(el('td', '', identityLabel(record)), el('td', '', text(record?.path || record?.url, 'Not supplied')),
      el('td', [401, 403].includes(code) ? 'http-denied' : '', code ?? '—'), el('td', '', milliseconds === null ? '—' : `${milliseconds} ms`));
    return row;
  }
  function renderRequests() {
    const records = requestRecords(runtime.scan);
    $('runtime-requests').replaceChildren(...records.map(requestRow));
    const source = runtime.demo ? 'synthetic' : 'returned';
    $('runtime-request-summary').textContent = records.length ? `${records.length} ${source} request records. A denial or success status alone does not prove correct authorization.` : 'No per-request records returned. Aggregate counts, if supplied, do not establish per-path coverage.';
  }
  function renderCoverage() {
    const coverage = runtime.scan?.coverage || {}, container = $('runtime-coverage'); container.replaceChildren();
    const entries = Object.entries(coverage);
    if (!entries.length) { container.append(el('p', 'small subtle', 'The runner has not supplied coverage details. Do not infer that absent paths or checks were tested.')); return; }
    if (runtime.demo) container.append(el('p', 'operations-notice', 'Illustrative coverage only. No real environment has been observed.'));
    const list = el('dl');
    for (const [key, value] of entries) {
      const row = el('div', 'runtime-coverage-pair');
      const label = key.replace(/([a-z])([A-Z])/g, '$1 $2').replaceAll('_', ' ');
      row.append(el('dt', '', label), el('dd', '', value == null ? 'Not supplied' : pretty(value))); list.append(row);
    }
    container.append(list);
  }
  function reviewEvidence() {
    if (!runtime.scan || runtime.demo || !TERMINAL_STATES.has(runtime.scan.status)) return;
    const content = JSON.stringify(safeScan(runtime.scan));
    if (new TextEncoder().encode(content).length > 5 * 1024 * 1024) {
      status('runtime-status', 'The evidence snapshot exceeds the shared attachment limit. Download the export and select a narrower scope for specialist review.', 'error'); return;
    }
    // Parent integration accepts this attachment; credentials never enter this event.
    document.dispatchEvent(new CustomEvent('threatlint:runtime-evidence', { bubbles: true, detail: { name: 'runtime-evidence.json', content } }));
    status('runtime-status', 'Evidence handoff requested. The shared Workbench integration must accept the attachment; specialist review requires an explicit run.');
  }

  function wireSources() {
    $('scm-provider').addEventListener('change', providerChanged);
    $('scm-connection-form').addEventListener('submit', connectSource);
    $('scm-refresh-connections').addEventListener('click', refreshConnections);
    $('scm-repository-search-form').addEventListener('submit', event => {
      event.preventDefault(); scm.search = $('scm-repository-search').value.trim(); void loadRepositories(false);
    });
    $('scm-repositories-more').addEventListener('click', () => { if (!scm.repositoryBusy) void loadRepositories(true); });
    $('scm-branches-more').addEventListener('click', () => { if (!scm.branchBusy) void loadBranches(true); });
    $('scm-branch').addEventListener('change', syncSourceControls);
    $('scm-checkout').addEventListener('click', checkout);
  }
  function askAboutScan() {
    if (!runtime.scanId || runtime.demo) return;
    const context = { type: 'scan', scanId: runtime.scanId, label: `Runtime scan · ${text(runtime.scan?.target)}` };
    document.dispatchEvent(new CustomEvent('threatlint:navigate', { detail: { view: 'chat' } }));
    document.dispatchEvent(new CustomEvent('threatlint:ask', { detail: { context, question: 'Which runtime finding is most serious, and which source file causes it?' } }));
  }
  function guardDisabledLink(event) {
    if (event.currentTarget.getAttribute('aria-disabled') === 'true') event.preventDefault();
  }
  function wireRuntime() {
    $('runtime-scan-form').addEventListener('submit', startScan);
    $('runtime-auth-type').addEventListener('change', () => { clearAuthInputs(); renderAuthFields(); });
    $('runtime-clear-auth').addEventListener('click', () => { clearAuthInputs(); syncRuntimeControls(); status('runtime-status', 'Authentication inputs and the form’s browser-session handle were cleared. Runner-held sessions expire separately.'); });
    $('runtime-browser-start').addEventListener('click', startBrowser);
    $('runtime-browser-finish').addEventListener('click', finishBrowser);
    $('runtime-demo').addEventListener('click', loadDemo);
    $('runtime-add-role').addEventListener('click', addRole);
    $('runtime-chain-only').addEventListener('change', () => { runtime.graphSignature = ''; renderGraph(); });
    $('runtime-cancel').addEventListener('click', cancelScan);
    $('runtime-refresh').addEventListener('click', () => { void refreshScan(); });
    $('runtime-review-evidence').addEventListener('click', reviewEvidence);
    $('runtime-ask').addEventListener('click', askAboutScan);
    for (const id of ['runtime-target', 'runtime-paths', 'runtime-authorization-reason']) $(id).addEventListener('input', scopeEdited);
    for (const id of ['runtime-authorized', 'runtime-allow-private']) $(id).addEventListener('change', scopeEdited);
    for (const id of ['runtime-export-json', 'runtime-export-md', 'runtime-export-html']) $(id).addEventListener('click', guardDisabledLink);
  }
  function viewActivated() {
    if (!$('view-sources').hidden && !scm.initialized && !scm.refreshing) void refreshConnections();
    if (!$('view-runtime').hidden) scheduleEdges();
  }
  function wireLifecycle() {
    const views = new MutationObserver(viewActivated);
    for (const id of ['view-sources', 'view-runtime']) views.observe($(id), { attributes: true, attributeFilter: ['hidden', 'class'] });
    if (typeof ResizeObserver !== 'undefined') new ResizeObserver(scheduleEdges).observe($('runtime-graph-board'));
    window.addEventListener('resize', scheduleEdges);
    window.addEventListener('pagehide', () => {
      stopPolling(); scm.repositoryController?.abort(); scm.branchController?.abort();
      $('scm-token').value = ''; clearAuthInputs();
    });
    window.addEventListener('pageshow', event => { if (event.persisted && runtime.scanId && !runtime.demo) void refreshScan(); });
  }
  function initialize() {
    if (!$('view-sources') || !$('view-runtime') || $('runtime-scan-form').dataset.operationsReady) return;
    $('runtime-scan-form').dataset.operationsReady = 'true';
    wireSources(); wireRuntime(); wireLifecycle();
    providerChanged(); renderAuthFields(); renderScan(); syncSourceControls(); viewActivated();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize, { once: true });
  else initialize();
})();
