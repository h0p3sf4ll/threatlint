'use strict';

/**
 * Authorized, bounded, non-destructive runtime observer.
 *
 * createRuntimeScanner({ request?, lookup?, now?, browserFactory? }) ->
 *   { start(config) -> { id }, get(id) -> snapshot, cancel(id) -> boolean,
 *     startBrowser(config) -> { id, mode }, finishBrowser(id) -> { id, type },
 *     exportScan(id, format) -> { contentType, body }, close() }
 *
 * Only GET/HEAD requests are sent to the target. The only non-GET requests are
 * the explicitly configured OAuth token endpoint and form-login endpoint.
 * DNS answers are validated and pinned per request; private, loopback, and
 * link-local addresses require an explicit allowPrivate opt-in. Redirects are
 * never followed. Credentials are held in memory for the scan only and are
 * never included in snapshots, events, or exports.
 *
 * Snapshot: { id, status, target, startedAt, finishedAt, requests[], findings[],
 *   nodes[], edges[], events[], coverage{} }. Node kinds are target, identity,
 *   request, response, control, finding, and impact (always a hypothesis).
 */

const crypto = require('node:crypto');
const dns = require('node:dns');
const http = require('node:http');
const https = require('node:https');
const { isIP } = require('node:net');

const LIMITS = Object.freeze({ maxRequests: 100, maxPaths: 100, timeoutMs: 30_000, delayMs: 10_000, bodyBytes: 256 * 1024, scans: 25, browserTtlMs: 15 * 60_000 });
const TOKEN = /^[!#$%&'*+.^_`|~0-9a-z-]+$/i;
const FORBIDDEN_HEADERS = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'proxy-authorization', 'proxy-connection', 'upgrade', 'te', 'trailer', 'keep-alive']);
const PROBE_ORIGIN = 'https://threatlint-cors-probe.invalid';
const AUTH_TYPES = ['none', 'bearer', 'basic', 'api-key', 'headers', 'cookie', 'oauth-client-credentials', 'oauth-refresh-token', 'oauth-password', 'form-login', 'mtls', 'browser-state', 'browser-session'];

class RuntimeError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}
const fail = (message, status) => { throw new RuntimeError(message, status); };

function privateAddress(address) {
  const family = isIP(address);
  if (family === 4) {
    const [a, b] = address.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224 || (a === 198 && (b === 18 || b === 19));
  }
  if (family === 6) {
    const lower = address.toLowerCase();
    if (lower.startsWith('::ffff:')) return privateAddress(lower.slice(7)) || !isIP(lower.slice(7));
    return lower === '::' || lower === '::1' || /^(?:f[cd]|fe[89ab]|ff)/.test(lower);
  }
  return true;
}

function checkedUrl(raw, allowPrivate, label = 'target') {
  let url;
  try { url = new URL(raw); } catch { fail(`Enter a complete HTTP(S) ${label} URL`); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) fail(`The ${label} must be HTTP(S) without embedded credentials or fragments`);
  if (label === 'target' && url.search) fail('The target must not include a query string');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!allowPrivate && (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || (isIP(host) && privateAddress(host)))) {
    fail(`The ${label} is private or loopback. Explicitly allow private-network targets for an approved environment`);
  }
  return url;
}

function originPath(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.length > 2048 || /[\\?#\s\u0000-\u001f]/u.test(value)
    || /%(?:2f|5c|3f|23|0[0-9a-f]|1[0-9a-f]|7f)/i.test(value)) fail('Use origin-relative paths without query strings, fragments, whitespace, or encoded separators');
  const url = new URL(value, 'https://scope.invalid');
  if (url.pathname !== value) fail('Use normalized paths without dot segments');
  return value;
}

function boundedInteger(value, fallback, min, max, name) {
  const number = value === undefined ? fallback : value;
  if (!Number.isInteger(number) || number < min || number > max) fail(`${name} must be an integer between ${min} and ${max}`);
  return number;
}

function stringField(object, key, { optional = false, max = 10_000, preserve = false } = {}) {
  const value = object?.[key];
  if (value === undefined || value === '') { if (optional) return undefined; fail(`Authentication field ${key} is required`); }
  if (typeof value !== 'string' || value.length > max || /[\r\n\u0000]/u.test(value)) fail(`Authentication field ${key} is invalid`);
  return preserve ? value : value.trim();
}

function validateAuth(auth, allowPrivate) {
  if (!auth || typeof auth !== 'object' || Array.isArray(auth) || !AUTH_TYPES.includes(auth.type)) fail('Choose a supported authentication type');
  const type = auth.type;
  switch (type) {
    case 'none': return { type };
    case 'bearer': return { type, token: stringField(auth, 'token') };
    case 'basic': return { type, username: stringField(auth, 'username'), password: stringField(auth, 'password', { preserve: true }) };
    case 'api-key': {
      const name = stringField(auth, 'name', { max: 200 });
      if (!TOKEN.test(name) || !['header', 'query'].includes(auth.location)) fail('Use a valid API key name and placement');
      return { type, name, value: stringField(auth, 'value', { preserve: true }), location: auth.location };
    }
    case 'headers': {
      if (!auth.headers || typeof auth.headers !== 'object' || Array.isArray(auth.headers)) fail('Headers must be a JSON object');
      const entries = Object.entries(auth.headers);
      if (!entries.length || entries.length > 30) fail('Provide between 1 and 30 headers');
      const headers = {};
      for (const [name, value] of entries) {
        if (!TOKEN.test(name) || FORBIDDEN_HEADERS.has(name.toLowerCase()) || typeof value !== 'string' || /[\r\n\u0000]/u.test(value) || value.length > 10_000) fail('Headers must use valid names and single-line string values');
        headers[name] = value;
      }
      return { type, headers };
    }
    case 'cookie': return { type, cookie: stringField(auth, 'cookie', { max: 32_000 }) };
    case 'oauth-client-credentials':
    case 'oauth-refresh-token':
    case 'oauth-password': {
      const tokenUrl = checkedUrl(stringField(auth, 'tokenUrl'), allowPrivate, 'token endpoint');
      if (tokenUrl.protocol !== 'https:' && !allowPrivate) fail('A remote token endpoint must use HTTPS');
      const result = { type, tokenUrl: tokenUrl.href, clientId: stringField(auth, 'clientId'), clientSecret: stringField(auth, 'clientSecret', { optional: type !== 'oauth-client-credentials', preserve: true }),
        scope: stringField(auth, 'scope', { optional: true }), audience: stringField(auth, 'audience', { optional: true }) };
      if (type === 'oauth-refresh-token') result.refreshToken = stringField(auth, 'refreshToken', { preserve: true });
      if (type === 'oauth-password') { result.username = stringField(auth, 'username'); result.password = stringField(auth, 'password', { preserve: true }); }
      return result;
    }
    case 'form-login': {
      const loginUrl = checkedUrl(stringField(auth, 'loginUrl'), allowPrivate, 'login');
      const usernameField = stringField(auth, 'usernameField', { optional: true, max: 100 }) || 'username';
      const passwordField = stringField(auth, 'passwordField', { optional: true, max: 100 }) || 'password';
      if (!TOKEN.test(usernameField) || !TOKEN.test(passwordField)) fail('Use simple form field names');
      return { type, loginUrl: loginUrl.href, usernameField, passwordField, username: stringField(auth, 'username'), password: stringField(auth, 'password', { preserve: true }) };
    }
    case 'mtls': {
      // PEM is multi-line, so it is validated by shape rather than the single-line field rule.
      const pem = (value, pattern) => (typeof value === 'string' && value.length <= 64_000 && !value.includes('\u0000') && pattern.test(value) ? value : fail('Provide a PEM client certificate and private key'));
      const cert = pem(auth.cert, /-----BEGIN CERTIFICATE-----/);
      const key = pem(auth.key, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
      return { type, cert, key, passphrase: stringField(auth, 'passphrase', { optional: true, preserve: true }) };
    }
    case 'browser-state': {
      const cookies = auth.storageState?.cookies;
      if (!Array.isArray(cookies) || !cookies.length || cookies.length > 200) fail('Browser state needs a cookies array with 1 to 200 cookies');
      return { type, cookies: cookies.map(cookie => {
        if (!cookie || typeof cookie.name !== 'string' || typeof cookie.value !== 'string' || !TOKEN.test(cookie.name) || /[\r\n;\u0000]/u.test(cookie.value)) fail('Every browser cookie needs a valid name and value');
        return { name: cookie.name, value: cookie.value, domain: typeof cookie.domain === 'string' ? cookie.domain : '' };
      }) };
    }
    case 'browser-session': {
      if (typeof auth.sessionId !== 'string' || !/^[0-9a-f-]{36}$/.test(auth.sessionId)) fail('Finish manual browser sign-in first');
      return { type, sessionId: auth.sessionId };
    }
    default: return fail('Choose a supported authentication type');
  }
}

function validateAuthorization(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) fail('A scan configuration object is required');
  if (config.authorization?.confirmed !== true) fail('Explicitly confirm authorization for this target');
  const reason = config.authorization.reason;
  if (typeof reason !== 'string' || !reason.trim() || reason.length > 300) fail('Describe the authorization context');
  const allowPrivate = config.authorization.allowPrivate === true;
  const target = checkedUrl(config.target, allowPrivate);
  return { target, allowPrivate, reason: reason.trim() };
}

function validateConfig(config) {
  const scope = validateAuthorization(config);
  if (!Array.isArray(config.paths) || !config.paths.length || config.paths.length > LIMITS.maxPaths) fail(`Provide between 1 and ${LIMITS.maxPaths} paths`);
  const paths = [...new Set(config.paths.map(originPath))];
  const assertions = (config.assertions || []).map(assertion => {
    const path = originPath(assertion?.path);
    const statuses = assertion.expectedAnonymousStatus;
    if (!paths.includes(path) || !Array.isArray(statuses) || !statuses.length || !statuses.every(code => Number.isInteger(code) && code >= 100 && code <= 599)) fail('Each assertion needs an in-scope path and HTTP status array');
    return { path, expected: [...new Set(statuses)] };
  });
  if (!Array.isArray(config.assertions ?? [])) fail('Assertions must be an array');
  const auth = validateAuth(config.auth || { type: 'none' }, scope.allowPrivate);
  const roles = (config.roles || []).map((role, index) => {
    if (!role || typeof role.label !== 'string' || !role.label.trim() || role.label.length > 60) fail(`Role ${index + 1} needs a label`);
    return { label: role.label.trim(), auth: validateAuth(role.auth, scope.allowPrivate) };
  });
  if (roles.length > 4) fail('Compare at most four additional roles');
  const limits = config.limits || {};
  return { ...scope, paths, assertions, auth, roles,
    compareAnonymous: auth.type !== 'none' && config.checks?.compareAnonymous === true,
    limits: { maxRequests: boundedInteger(limits.maxRequests, 20, 1, LIMITS.maxRequests, 'maxRequests'),
      timeoutMs: boundedInteger(limits.timeoutMs, 10_000, 500, LIMITS.timeoutMs, 'timeoutMs'),
      delayMs: boundedInteger(limits.delayMs, 150, 0, LIMITS.delayMs, 'delayMs') } };
}

// ── Passive response checks ───────────────────────────────────────────────────

const HEADER_CHECKS = [
  { id: 'RT-HDR-HSTS', header: 'strict-transport-security', https: true, severity: 'MEDIUM', title: 'Missing Strict-Transport-Security', fix: 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains from the HTTPS edge.', cwe: 'CWE-319' },
  { id: 'RT-HDR-CSP', header: 'content-security-policy', html: true, severity: 'MEDIUM', title: 'Missing Content-Security-Policy on HTML', fix: "Add a restrictive CSP (default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none').", cwe: 'CWE-1021' },
  { id: 'RT-HDR-XCTO', header: 'x-content-type-options', severity: 'LOW', title: 'Missing X-Content-Type-Options: nosniff', fix: 'Send X-Content-Type-Options: nosniff on every response.', cwe: 'CWE-693' },
  { id: 'RT-HDR-FRAME', header: 'x-frame-options', html: true, alt: /frame-ancestors/i, severity: 'LOW', title: 'HTML can be framed (no X-Frame-Options or frame-ancestors)', fix: "Send X-Frame-Options: DENY or CSP frame-ancestors 'none'.", cwe: 'CWE-1021' },
];
const DEBUG_SIGNATURES = [/Traceback \(most recent call last\)/, /at [\w$.]+\([\w./-]+\.java:\d+\)/, /Werkzeug Debugger/i, /Whoops! There was an error/i, /DEBUG\s*=\s*True/, /at Object\.<anonymous> \(/, /System\.NullReferenceException/, /Microsoft\.AspNetCore\.Diagnostics/];

function analyzeResponse(record, response, scope) {
  const findings = [];
  const headers = response.headers;
  const type = String(headers['content-type'] || '');
  const html = /text\/html/i.test(type);
  for (const check of HEADER_CHECKS) {
    if (check.https && scope.target.protocol !== 'https:') continue;
    if (check.html && !html) continue;
    if (headers[check.header]) continue;
    if (check.alt && check.alt.test(String(headers['content-security-policy'] || ''))) continue;
    findings.push({ rule: check.id, severity: check.severity, title: check.title, cwe: check.cwe, path: record.path, identity: record.identity,
      description: `${record.path} returned ${record.statusCode} without ${check.header}.`, fix: check.fix, evidence: { header: check.header, present: false, contentType: type.slice(0, 80) } });
  }
  const cookies = [].concat(headers['set-cookie'] || []);
  for (const cookie of cookies) {
    const name = cookie.split('=')[0].trim().slice(0, 80);
    const flags = cookie.toLowerCase();
    const missing = [!flags.includes('httponly') && 'HttpOnly', scope.target.protocol === 'https:' && !flags.includes('secure') && 'Secure', !flags.includes('samesite') && 'SameSite'].filter(Boolean);
    if (missing.length) findings.push({ rule: 'RT-COOKIE-FLAGS', severity: missing.includes('HttpOnly') && /sess|auth|token|sid/i.test(name) ? 'MEDIUM' : 'LOW', title: `Cookie ${name} is missing ${missing.join(', ')}`,
      cwe: 'CWE-1004', path: record.path, identity: record.identity, description: `Set-Cookie for ${name} lacks ${missing.join(', ')}.`, fix: `Set ${missing.join('; ')} on ${name} (e.g. HttpOnly; Secure; SameSite=Lax).`, evidence: { cookie: name, missing } });
  }
  const acao = headers['access-control-allow-origin'];
  if (acao && (acao === PROBE_ORIGIN || (acao === '*' && String(headers['access-control-allow-credentials']).toLowerCase() === 'true'))) {
    findings.push({ rule: 'RT-CORS-REFLECT', severity: String(headers['access-control-allow-credentials']).toLowerCase() === 'true' ? 'HIGH' : 'MEDIUM', title: 'CORS reflects an untrusted origin',
      cwe: 'CWE-942', path: record.path, identity: record.identity, description: `An Origin of ${PROBE_ORIGIN} was echoed in Access-Control-Allow-Origin${headers['access-control-allow-credentials'] ? ' with credentials allowed' : ''}.`,
      fix: 'Compare Origin against an explicit allowlist; never reflect arbitrary origins with credentials.', evidence: { allowOrigin: acao, allowCredentials: headers['access-control-allow-credentials'] || null } });
  }
  for (const name of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']) {
    if (headers[name] && /\d/.test(String(headers[name]))) {
      findings.push({ rule: 'RT-DISCLOSE-VERSION', severity: 'INFO', title: `Version disclosed in ${name}`, cwe: 'CWE-200', path: record.path, identity: record.identity,
        description: `${name}: ${String(headers[name]).slice(0, 80)}`, fix: `Remove or genericize the ${name} header at the server or proxy.`, evidence: { header: name, value: String(headers[name]).slice(0, 80) } });
    }
  }
  const body = response.body || '';
  const signature = DEBUG_SIGNATURES.find(pattern => pattern.test(body));
  if (signature) findings.push({ rule: 'RT-DEBUG-LEAK', severity: 'MEDIUM', title: 'Stack trace or debug output in response', cwe: 'CWE-209', path: record.path, identity: record.identity,
    description: `${record.path} returned content matching a debug/stack-trace signature.`, fix: 'Disable debug mode in deployed environments and return generic error pages.', evidence: { signature: signature.source.slice(0, 60) } });
  return findings;
}

// ── HTML report rendering (escaped) ──────────────────────────────────────────

const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));

function markdownExport(scan) {
  const lines = [`# Runtime evidence — ${scan.target}`, '', `- Status: ${scan.status}`, `- Started: ${new Date(scan.startedAt).toISOString()}`,
    scan.finishedAt ? `- Finished: ${new Date(scan.finishedAt).toISOString()}` : '- Finished: not finished', `- Requests: ${scan.requests.length}`, `- Authorization context: ${scan.coverage.authorization}`, '',
    '> Runtime observations are evidence, not exploit confirmation. Untested paths, identities, and impacts remain unknown.', '', '## Findings', ''];
  if (!scan.findings.length) lines.push('No finding observations within this scope. This is not a clean bill of health.', '');
  for (const finding of scan.findings) {
    lines.push(`### ${finding.id}: ${finding.title}`, '', `**Severity:** ${finding.severity}  `, `**Rule:** ${finding.rule}${finding.cwe ? ` (${finding.cwe})` : ''}  `, `**Location:** ${finding.path} as ${finding.identity}  `,
      `**Validation status:** OBSERVED, NOT EXPLOITED`, '', finding.description, '', `**Proposed fix:** ${finding.fix}`, '');
  }
  lines.push('## Request log', '', '| Identity | Method | Path | HTTP | ms |', '| --- | --- | --- | --- | --- |');
  for (const record of scan.requests) lines.push(`| ${record.identity} | ${record.method} | ${record.path} | ${record.statusCode ?? record.error ?? '—'} | ${record.durationMs ?? '—'} |`);
  lines.push('', '## Coverage', '');
  for (const [key, value] of Object.entries(scan.coverage)) lines.push(`- ${key}: ${typeof value === 'object' ? JSON.stringify(value) : value}`);
  return `${lines.join('\n')}\n`;
}

function htmlExport(scan) {
  const rows = scan.findings.map(finding => `<tr><td>${escapeHtml(finding.severity)}</td><td>${escapeHtml(finding.title)}</td><td>${escapeHtml(finding.path)}</td><td>${escapeHtml(finding.fix)}</td></tr>`).join('');
  const chain = scan.nodes.map(node => `<li><b>${escapeHtml(node.kind)}</b> ${escapeHtml(node.label)} <i>${escapeHtml(node.status)}</i></li>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Threatlint runtime evidence</title><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>body{font:14px system-ui;margin:32px;color:#111}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:6px;text-align:left}</style></head><body>
<h1>Runtime evidence — ${escapeHtml(scan.target)}</h1><p>Status ${escapeHtml(scan.status)} · ${scan.requests.length} requests · observations are not exploit confirmation.</p>
<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>Path</th><th>Proposed fix</th></tr></thead><tbody>${rows || '<tr><td colspan="4">No observations in scope.</td></tr>'}</tbody></table>
<h2>Attack chain</h2><ol>${chain}</ol></body></html>`;
}

// ── Scanner ──────────────────────────────────────────────────────────────────

function createRuntimeScanner(options = {}) {
  const lookup = options.lookup || dns.lookup;
  const transport = options.request || null;
  const browserFactory = options.browserFactory || (async () => require('playwright').chromium.launch({ headless: false }));
  const scans = new Map();
  const browsers = new Map();

  async function resolveTarget(url, allowPrivate) {
    const host = url.hostname.replace(/^\[|\]$/g, '');
    const answers = isIP(host) ? [{ address: host, family: isIP(host) }] : await new Promise((resolve, reject) => lookup(host, { all: true, verbatim: true }, (error, results) => error ? reject(error) : resolve(results)));
    if (!answers.length) fail('The target host did not resolve', 502);
    if (!allowPrivate && answers.some(answer => privateAddress(answer.address))) fail('The target resolved to a private address. Explicitly allow private-network targets for an approved environment');
    return answers[0];
  }

  async function send(url, { method = 'GET', headers = {}, body, allowPrivate, timeoutMs, tls, signal }) {
    const pinned = await resolveTarget(url, allowPrivate);
    if (transport) return transport({ url: url.href, method, headers, body, address: pinned.address, timeoutMs, tls, signal });
    return new Promise((resolve, reject) => {
      const client = url.protocol === 'https:' ? https : http;
      const started = Date.now();
      const req = client.request(url, {
        method, headers: { 'User-Agent': 'threatlint-runtime-observer/1.0', Accept: '*/*', ...headers, ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}) },
        lookup: (_host, _opts, callback) => _opts?.all ? callback(null, [{ address: pinned.address, family: pinned.family }]) : callback(null, pinned.address, pinned.family),
        timeout: timeoutMs, signal, agent: false, ...(tls ? { cert: tls.cert, key: tls.key, passphrase: tls.passphrase } : {}),
      }, response => {
        const chunks = []; let bytes = 0;
        response.on('data', chunk => { bytes += chunk.length; if (bytes <= LIMITS.bodyBytes) chunks.push(chunk); else response.destroy(); });
        response.on('close', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString('utf8'), durationMs: Date.now() - started, bytes }));
        response.on('error', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString('utf8'), durationMs: Date.now() - started, bytes }));
      });
      req.on('timeout', () => req.destroy(new RuntimeError('Request timed out', 504)));
      req.on('error', reject);
      if (body) req.write(body);
      req.end();
    });
  }

  async function establishIdentity(scan, auth, label, scope) {
    const identity = { label, type: auth.type, headers: {}, query: {}, tls: null };
    const common = { allowPrivate: scope.allowPrivate, timeoutMs: scope.limits.timeoutMs, signal: scan.controller.signal };
    switch (auth.type) {
      case 'none': break;
      case 'bearer': identity.headers.Authorization = `Bearer ${auth.token}`; break;
      case 'basic': identity.headers.Authorization = `Basic ${Buffer.from(`${auth.username}:${auth.password}`).toString('base64')}`; break;
      case 'api-key': if (auth.location === 'header') identity.headers[auth.name] = auth.value; else identity.query[auth.name] = auth.value; break;
      case 'headers': Object.assign(identity.headers, auth.headers); break;
      case 'cookie': identity.headers.Cookie = auth.cookie; break;
      case 'browser-state': {
        const host = scope.target.hostname;
        const cookies = auth.cookies.filter(cookie => !cookie.domain || host === cookie.domain.replace(/^\./, '') || host.endsWith(cookie.domain.startsWith('.') ? cookie.domain : `.${cookie.domain}`));
        if (!cookies.length) fail('No imported cookie applies to the target host');
        identity.headers.Cookie = cookies.map(cookie => `${cookie.name}=${cookie.value}`).join('; ');
        break;
      }
      case 'browser-session': {
        const session = browsers.get(auth.sessionId);
        if (!session?.cookie || session.scope !== scope.target.origin || session.expires < Date.now()) fail('The manual browser session is missing, expired, or for another target');
        identity.headers.Cookie = session.cookie;
        break;
      }
      case 'mtls': identity.tls = { cert: auth.cert, key: auth.key, passphrase: auth.passphrase }; break;
      case 'oauth-client-credentials':
      case 'oauth-refresh-token':
      case 'oauth-password': {
        const form = new URLSearchParams({ grant_type: { 'oauth-client-credentials': 'client_credentials', 'oauth-refresh-token': 'refresh_token', 'oauth-password': 'password' }[auth.type], client_id: auth.clientId });
        if (auth.clientSecret) form.set('client_secret', auth.clientSecret);
        if (auth.scope) form.set('scope', auth.scope);
        if (auth.audience) form.set('audience', auth.audience);
        if (auth.refreshToken) form.set('refresh_token', auth.refreshToken);
        if (auth.username) { form.set('username', auth.username); form.set('password', auth.password); }
        const response = await send(new URL(auth.tokenUrl), { ...common, method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: form.toString() });
        let token;
        try { token = JSON.parse(response.body).access_token; } catch { token = null; }
        if (response.status !== 200 || typeof token !== 'string' || !token) fail(`The token endpoint did not issue an access token (HTTP ${response.status})`, 502);
        identity.headers.Authorization = `Bearer ${token}`;
        break;
      }
      case 'form-login': {
        const body = new URLSearchParams({ [auth.usernameField]: auth.username, [auth.passwordField]: auth.password }).toString();
        const response = await send(new URL(auth.loginUrl), { ...common, method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
        const cookies = [].concat(response.headers['set-cookie'] || []).map(cookie => cookie.split(';')[0]).filter(Boolean);
        if (!cookies.length) fail(`The login endpoint returned HTTP ${response.status} without a session cookie`, 502);
        identity.headers.Cookie = cookies.join('; ');
        identity.login = { path: new URL(auth.loginUrl).pathname, response };
        break;
      }
      default: fail('Unsupported authentication type');
    }
    return identity;
  }

  function snapshot(scan) {
    return { id: scan.id, status: scan.status, target: scan.target, startedAt: scan.startedAt, finishedAt: scan.finishedAt,
      requests: scan.requests.map(record => ({ ...record })), findings: scan.findings.map(finding => ({ ...finding })),
      nodes: scan.nodes.map(node => ({ ...node })), edges: scan.edges.map(edge => ({ ...edge })), events: scan.events.slice(-500), coverage: { ...scan.coverage } };
  }

  function addNode(scan, node) { scan.nodes.push(node); return node.id; }
  function addEdge(scan, from, to, label = '') { if (from && to && !scan.edges.some(edge => edge.from === from && edge.to === to)) scan.edges.push({ from, to, label }); }
  function event(scan, message, extra = {}) { scan.events.push({ timestamp: new Date().toISOString(), message, ...extra }); }
  const sleep = (ms, signal) => new Promise(resolve => { const timer = setTimeout(resolve, ms); signal.addEventListener('abort', () => { clearTimeout(timer); resolve(); }, { once: true }); });

  const IMPACTS = {
    'RT-CORS-REFLECT': 'A malicious site could read authenticated responses cross-origin',
    'RT-AUTHZ-ASSERT': 'Unauthenticated users could reach a protected resource',
    'RT-AUTHZ-ANON-EQUAL': 'Protected data may be readable without authentication',
    'RT-AUTHZ-ROLE-EQUAL': 'A lower-privilege role may access a higher-privilege resource',
    'RT-COOKIE-FLAGS': 'Session theft via XSS or network interception becomes easier',
    'RT-DEBUG-LEAK': 'Internal paths and versions aid targeted exploitation',
    'RT-HDR-CSP': 'Injected script would execute without a CSP backstop',
    'RT-HDR-FRAME': 'Clickjacking of authenticated actions',
    'RT-HDR-HSTS': 'TLS stripping on first visit',
  };

  async function run(scan, scope) {
    const signal = scan.controller.signal;
    const targetNode = addNode(scan, { id: 'target', kind: 'target', label: scope.target.origin, status: 'observed', detail: `Authorized: ${scope.reason}`, evidence: { paths: scope.paths.length, allowPrivate: scope.allowPrivate } });
    const profiles = [{ label: scope.auth.type === 'none' ? 'anonymous' : `primary (${scope.auth.type})`, auth: scope.auth, primary: true }];
    for (const role of scope.roles) profiles.push({ label: role.label, auth: role.auth });
    if (scope.compareAnonymous && scope.auth.type !== 'none') profiles.push({ label: 'anonymous', auth: { type: 'none' }, anonymous: true });
    const identities = [];
    for (const [index, profile] of profiles.entries()) {
      const nodeId = `identity-${index}`;
      try {
        const identity = await establishIdentity(scan, profile.auth, profile.label, scope);
        identities.push({ ...identity, nodeId, primary: profile.primary, anonymous: profile.anonymous || profile.auth.type === 'none' });
        addNode(scan, { id: nodeId, kind: 'identity', label: profile.label, status: 'observed', detail: `Authentication workflow: ${profile.auth.type}`, evidence: { type: profile.auth.type, established: true } });
        event(scan, `Identity established · ${profile.label}`);
        if (identity.login) {
          // The session cookie is issued by the login response, so its flags are checked there.
          const record = { path: identity.login.path, identity: profile.label, statusCode: identity.login.response.status };
          const cookieFindings = analyzeResponse(record, { headers: { 'set-cookie': identity.login.response.headers['set-cookie'], 'x-content-type-options': 'n/a' }, body: '' }, scope).filter(finding => finding.rule === 'RT-COOKIE-FLAGS');
          for (const finding of cookieFindings) recordFinding(scan, finding, nodeId);
          delete identity.login;
        }
      } catch (error) {
        addNode(scan, { id: nodeId, kind: 'identity', label: profile.label, status: 'failed', detail: error.message, evidence: { type: profile.auth.type, established: false } });
        event(scan, `Identity failed · ${profile.label}: ${error.message}`, { status: 'failed' });
      }
      addEdge(scan, targetNode, nodeId, 'acts as');
      if (signal.aborted) return;
    }
    if (!identities.length) throw new RuntimeError('No identity could be established', 502);

    const results = new Map();
    let budget = scope.limits.maxRequests;
    const tested = new Set();
    for (const path of scope.paths) {
      for (const identity of identities) {
        if (signal.aborted) return;
        if (budget <= 0) { event(scan, 'Request budget exhausted; remaining paths are NOT TESTED'); break; }
        budget -= 1;
        const url = new URL(path, scope.target);
        for (const [key, value] of Object.entries(identity.query)) url.searchParams.set(key, value);
        const record = { identity: identity.label, method: 'GET', path, statusCode: null, durationMs: null };
        const requestNode = `req-${scan.requests.length}`;
        try {
          const response = await send(url, { headers: { ...identity.headers, Origin: PROBE_ORIGIN }, allowPrivate: scope.allowPrivate, timeoutMs: scope.limits.timeoutMs, tls: identity.tls, signal });
          Object.assign(record, { statusCode: response.status, durationMs: response.durationMs, bytes: response.bytes, contentType: String(response.headers['content-type'] || '').slice(0, 80) });
          results.set(`${identity.label}|${path}`, { status: response.status, bytes: response.bytes, hash: crypto.createHash('sha256').update(response.body || '').digest('hex'), identity });
          tested.add(path);
          addNode(scan, { id: requestNode, kind: 'request', label: `GET ${path}`, status: 'observed', detail: `as ${identity.label}`, evidence: { identity: identity.label } });
          addEdge(scan, identity.nodeId, requestNode, 'requests');
          const responseNode = `${requestNode}-res`;
          const denied = [401, 403].includes(response.status);
          addNode(scan, { id: responseNode, kind: denied ? 'control' : 'response', label: `HTTP ${response.status}${denied ? ' · access control' : ''}`, status: denied ? 'blocked' : 'observed', detail: `${response.durationMs} ms · ${record.contentType || 'no content-type'}`, evidence: { status: response.status, bytes: response.bytes } });
          addEdge(scan, requestNode, responseNode, denied ? 'denied' : 'responds');
          for (const finding of analyzeResponse(record, response, scope)) recordFinding(scan, finding, responseNode);
          event(scan, `GET ${path} as ${identity.label} → ${response.status}`);
        } catch (error) {
          if (signal.aborted) return;
          record.error = error.message.slice(0, 120);
          addNode(scan, { id: requestNode, kind: 'request', label: `GET ${path}`, status: 'failed', detail: record.error, evidence: { identity: identity.label } });
          addEdge(scan, identity.nodeId, requestNode, 'requests');
          event(scan, `GET ${path} as ${identity.label} failed: ${record.error}`, { status: 'failed' });
        }
        scan.requests.push(record);
        if (scope.limits.delayMs) await sleep(scope.limits.delayMs, signal);
      }
    }

    // Cross-identity authorization comparisons.
    const primary = identities.find(identity => identity.primary);
    const anonymous = identities.find(identity => identity.anonymous);
    for (const path of tested) {
      const anon = anonymous && results.get(`${anonymous.label}|${path}`);
      for (const assertion of scope.assertions.filter(item => item.path === path)) {
        if (!anon) continue;
        if (!assertion.expected.includes(anon.status)) {
          recordFinding(scan, { rule: 'RT-AUTHZ-ASSERT', severity: anon.status < 300 ? 'HIGH' : 'MEDIUM', title: `Access-control assertion failed for ${path}`, cwe: 'CWE-862', path, identity: anonymous.label,
            description: `Anonymous GET ${path} returned ${anon.status}; expected ${assertion.expected.join(' or ')}.`, fix: 'Enforce authentication middleware on this route server-side and add a regression test asserting 401/403 for anonymous callers.',
            evidence: { expected: assertion.expected, observed: anon.status } }, findResponseNode(scan, anonymous.label, path));
        }
      }
      const main = primary && !primary.anonymous && results.get(`${primary.label}|${path}`);
      const sensitive = /api|admin|account|user|private|profile|order|billing|settings/i.test(path) && !/health|status|ping|version|public/i.test(path);
      if (main && anon && sensitive && main.status < 300 && anon.status < 300 && main.hash === anon.hash && main.bytes > 0 && !scope.assertions.some(item => item.path === path)) {
        recordFinding(scan, { rule: 'RT-AUTHZ-ANON-EQUAL', severity: 'MEDIUM', title: `${path} returns identical content with and without credentials`, cwe: 'CWE-306', path, identity: anonymous.label,
          description: `Authenticated and anonymous GET ${path} both returned ${main.status} with byte-identical bodies. Confirm the route is intended to be public.`, fix: 'If the route is protected, require authentication; otherwise add it to an explicit public-route allowlist.',
          evidence: { authenticated: main.status, anonymous: anon.status, bytes: main.bytes } }, findResponseNode(scan, anonymous.label, path));
      }
      // A role seeing the primary identity's exact content is only notable where anonymous access is denied.
      const protectedPath = !anonymous || (anon && [401, 403].includes(anon.status));
      for (const role of identities.filter(identity => !identity.primary && !identity.anonymous)) {
        const other = results.get(`${role.label}|${path}`);
        if (main && other && protectedPath && main.status < 300 && other.status < 300 && main.hash === other.hash) {
          recordFinding(scan, { rule: 'RT-AUTHZ-ROLE-EQUAL', severity: /admin/i.test(path) ? 'HIGH' : 'MEDIUM', title: `${role.label} receives the primary identity's ${path} content`, cwe: 'CWE-639', path, identity: role.label,
            description: `${role.label} received ${other.status} with a body identical to the primary identity on a route that denies anonymous callers. Verify whether this role should have access.`, fix: 'Enforce function- and object-level authorization for each role server-side; add role-matrix regression tests.',
            evidence: { primary: main.status, role: other.status, identical: true } }, findResponseNode(scan, role.label, path));
        }
      }
    }
    scan.coverage = { ...scan.coverage, pathsTested: tested.size, pathsInScope: scope.paths.length, pathsNotTested: scope.paths.filter(path => !tested.has(path)),
      identities: identities.map(identity => identity.label), requestBudgetUsed: scope.limits.maxRequests - budget, responseCount: scan.requests.filter(record => record.statusCode).length,
      deniedResponses: scan.requests.filter(record => [401, 403].includes(record.statusCode)).length, checks: ['security headers', 'cookie flags', 'CORS origin reflection', 'version disclosure', 'debug output', 'anonymous/role comparison', 'status assertions'] };
  }

  function findResponseNode(scan, identity, path) {
    const index = scan.requests.findIndex(record => record.identity === identity && record.path === path);
    return index >= 0 ? `req-${index}-res` : null;
  }

  function recordFinding(scan, finding, responseNode) {
    const duplicate = scan.findings.find(item => item.rule === finding.rule && item.title === finding.title);
    if (duplicate) { duplicate.occurrences = (duplicate.occurrences || 1) + 1; return; }
    const id = `RT-${String(scan.findings.length + 1).padStart(3, '0')}`;
    scan.findings.push({ id, ...finding });
    const nodeId = `finding-${id}`;
    addNode(scan, { id: nodeId, kind: 'finding', label: finding.title, status: 'observed', detail: `${finding.severity} · ${finding.rule}`, evidence: finding.evidence });
    addEdge(scan, responseNode, nodeId, 'reveals');
    const impact = IMPACTS[finding.rule];
    if (impact) {
      const impactId = `impact-${finding.rule}`;
      if (!scan.nodes.some(node => node.id === impactId)) addNode(scan, { id: impactId, kind: 'impact', label: impact, status: 'not-tested', detail: 'Hypothesis. Not validated.' });
      addEdge(scan, nodeId, impactId, 'could enable');
    }
  }

  function start(config) {
    const scope = validateConfig(config);
    if ([...scans.values()].filter(scan => scan.status === 'running').length >= 2) fail('Two runtime scans are already running', 429);
    if (scans.size >= LIMITS.scans) scans.delete(scans.keys().next().value);
    const scan = { id: crypto.randomUUID(), status: 'running', target: scope.target.origin, startedAt: Date.now(), finishedAt: null, requests: [], findings: [], nodes: [], edges: [], events: [],
      coverage: { authorization: scope.reason, authType: scope.auth.type, maxRequests: scope.limits.maxRequests }, controller: new AbortController() };
    scans.set(scan.id, scan);
    event(scan, `Scan started · ${scope.paths.length} paths · budget ${scope.limits.maxRequests}`);
    run(scan, scope).then(() => { scan.status = scan.controller.signal.aborted ? 'cancelled' : 'complete'; }, error => {
      scan.status = scan.controller.signal.aborted ? 'cancelled' : 'failed';
      event(scan, `Scan stopped: ${error.message}`, { status: 'failed' });
    }).finally(() => { scan.finishedAt = Date.now(); event(scan, `Scan ${scan.status}`); });
    return { id: scan.id };
  }

  function get(id) {
    const scan = scans.get(id);
    if (!scan) fail('Scan not found', 404);
    return snapshot(scan);
  }
  function cancel(id) {
    const scan = scans.get(id);
    if (!scan) fail('Scan not found', 404);
    scan.controller.abort();
    return true;
  }
  function exportScan(id, format) {
    const scan = get(id);
    if (format === 'json') return { contentType: 'application/json', body: JSON.stringify(scan, null, 2) };
    if (format === 'md') return { contentType: 'text/markdown; charset=utf-8', body: markdownExport(scan) };
    if (format === 'html') return { contentType: 'text/html; charset=utf-8', body: htmlExport(scan) };
    return fail('Choose json, md, or html');
  }

  async function startBrowser(config) {
    const scope = validateAuthorization(config);
    for (const [key, session] of browsers) if (session.expires < Date.now()) { session.browser?.close().catch(() => {}); browsers.delete(key); }
    if (browsers.size >= 3) fail('Too many pending browser sessions', 429);
    let browser;
    try { browser = await browserFactory(); } catch { fail('Interactive browser sign-in is unavailable on this runner. Install Playwright browsers (npx playwright install chromium)', 501); }
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(scope.target.href).catch(() => {});
    const id = crypto.randomUUID();
    browsers.set(id, { browser, context, scope: scope.target.origin, cookie: null, expires: Date.now() + LIMITS.browserTtlMs });
    return { id, mode: 'interactive' };
  }

  async function finishBrowser(id) {
    const session = browsers.get(id);
    if (!session || session.expires < Date.now()) fail('Browser session not found or expired', 404);
    const cookies = await session.context.cookies(session.scope);
    await session.browser.close().catch(() => {});
    session.browser = null; session.context = null;
    if (!cookies.length) { browsers.delete(id); fail('No cookies were set for the target. Complete sign-in before finishing', 409); }
    session.cookie = cookies.map(cookie => `${cookie.name}=${cookie.value}`).join('; ');
    return { id, type: 'browser-session' };
  }

  async function close() {
    for (const scan of scans.values()) scan.controller.abort();
    for (const session of browsers.values()) await session.browser?.close().catch(() => {});
    browsers.clear();
  }

  return { start, get, cancel, exportScan, startBrowser, finishBrowser, close };
}

module.exports = { createRuntimeScanner, RuntimeError, LIMITS, AUTH_TYPES, privateAddress, analyzeResponse, validateConfig, markdownExport, htmlExport };
