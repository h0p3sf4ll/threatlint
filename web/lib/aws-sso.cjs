'use strict';

/**
 * Browser sign-in to AWS IAM Identity Center, then Parameter Store reads, with no AWS CLI.
 * Uses the OIDC device-authorization flow: the verification page opens in a private window of the
 * user's default browser (an existing Okta session in a normal window fails with "Conflicting User IDs
 * specified on state token"). Tokens and role credentials stay in this process's memory, expire with
 * the sign-in, and are never written to disk or returned to the UI.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { HttpError } = require('./http.cjs');

const execFileAsync = promisify(execFile);
const PARAMETER_REGION = 'us-west-2';
const SNOW_PARAMETERS = ['/cfc-appsec-snow-vulnerabilities-prod/client-id', '/cfc-appsec-snow-vulnerabilities-prod/client-secret'];
const SEMGREP_PARAMETER = '/cfc-appsec-semgrep-scan/semgrep-token';
const HTTP_TIMEOUT_MS = 30_000;
const LOGIN_TTL_MS = 15 * 60_000;
const REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/;
const START_HOSTS = ['.awsapps.com', '.app.aws'];

function validateStart({ startUrl, region } = {}) {
  let url;
  try { url = new URL(String(startUrl || process.env.THREATLINT_AWS_SSO_START_URL || '').trim()); } catch { throw new HttpError('Enter the AWS access portal URL, e.g. https://<name>.awsapps.com/start'); }
  const host = url.hostname.toLowerCase();
  if (url.protocol !== 'https:' || url.username || url.password || !START_HOSTS.some(suffix => host.endsWith(suffix))) {
    throw new HttpError('The AWS access portal URL must be https://<name>.awsapps.com/start');
  }
  const value = String(region || process.env.THREATLINT_AWS_SSO_REGION || '').trim();
  if (!REGION.test(value)) throw new HttpError('Enter the IAM Identity Center region, e.g. us-east-1');
  return { startUrl: `${url.origin}${url.pathname.replace(/\/+$/, '') || '/start'}`, region: value };
}

async function awsJson(fetchImpl, url, { method = 'GET', headers = {}, body } = {}) {
  let response;
  try {
    response = await fetchImpl(url, { method, headers: { Accept: 'application/json', ...headers }, body, redirect: 'error', signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });
  } catch (error) { throw new HttpError(`AWS request failed: ${error.cause?.message || error.message}`, 502); }
  const payload = await response.json().catch(() => ({}));
  return { ok: response.ok, status: response.status, payload };
}

// ── Private-window browser launch ────────────────────────────────────────────

// Browsers whose private mode can be opened from the command line, by bundle ID / ProgId / .desktop name.
const PRIVATE = [
  { id: /^com\.google\.chrome/i, win: /^ChromeHTML/i, linux: /chrome/i, name: 'Google Chrome', mac: 'Google Chrome', exe: 'chrome', flag: '--incognito' },
  { id: /^com\.microsoft\.edge/i, win: /^MSEdgeHTM/i, linux: /edge/i, name: 'Microsoft Edge', mac: 'Microsoft Edge', exe: 'msedge', flag: '--inprivate' },
  { id: /^com\.brave\.browser/i, win: /^BraveHTML/i, linux: /brave/i, name: 'Brave', mac: 'Brave Browser', exe: 'brave', flag: '--incognito' },
  { id: /^org\.chromium\.chromium/i, win: /^ChromiumHTM/i, linux: /chromium/i, name: 'Chromium', mac: 'Chromium', exe: 'chromium', flag: '--incognito' },
  { id: /^com\.vivaldi\.vivaldi/i, win: /^VivaldiHTM/i, linux: /vivaldi/i, name: 'Vivaldi', mac: 'Vivaldi', exe: 'vivaldi', flag: '--incognito' },
  { id: /^org\.mozilla\.firefox/i, win: /^FirefoxURL/i, linux: /firefox/i, name: 'Firefox', mac: 'Firefox', exe: 'firefox', flag: '-private-window' },
];

async function defaultBrowser() {
  try {
    if (process.platform === 'darwin') {
      const plist = path.join(process.env.HOME || '', 'Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist');
      const { stdout } = await execFileAsync('/usr/bin/plutil', ['-convert', 'json', '-o', '-', plist], { timeout: 5000 });
      return JSON.parse(stdout).LSHandlers?.find(item => item.LSHandlerURLScheme === 'https')?.LSHandlerRoleAll || 'com.apple.safari';
    }
    if (process.platform === 'win32') {
      const { stdout } = await execFileAsync('reg', ['query', 'HKCU\\Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\https\\UserChoice', '/v', 'ProgId'], { timeout: 5000, windowsHide: true });
      return /ProgId\s+REG_SZ\s+(\S+)/.exec(stdout)?.[1] || '';
    }
    return (await execFileAsync('xdg-settings', ['get', 'default-web-browser'], { timeout: 5000 })).stdout.trim();
  } catch { return ''; }
}

const platformKey = () => ({ darwin: 'id', win32: 'win' }[process.platform] || 'linux');
const macApp = browser => [`/Applications/${browser.mac}.app`, path.join(process.env.HOME || '', `Applications/${browser.mac}.app`)].find(file => fs.existsSync(file));

async function installed(browser) {
  if (process.platform === 'darwin') return !!macApp(browser);
  if (process.platform === 'win32') return true; // `start` resolves registered executables; a missing one fails and the next is tried.
  try { await execFileAsync('which', [browser.exe], { timeout: 5000 }); return true; } catch { return false; }
}

async function launch(browser, url) {
  if (process.platform === 'darwin') await execFileAsync('/usr/bin/open', ['-na', macApp(browser), '--args', browser.flag, url], { timeout: 15_000 });
  else if (process.platform === 'win32') await execFileAsync('cmd.exe', ['/d', '/c', 'start', '""', browser.exe, browser.flag, url], { timeout: 15_000, windowsHide: true });
  else execFile(browser.exe, [browser.flag, url], { detached: true, stdio: 'ignore' }).unref();
}

/** Opens url in a private window: the default browser when it supports one, else the first installed browser that does. */
async function openPrivate(url, { launcher = launch, detect = defaultBrowser, available = installed } = {}) {
  const current = await detect();
  const key = platformKey();
  const preferred = PRIVATE.find(browser => browser[key].test(current));
  const candidates = [...(preferred ? [preferred] : []), ...PRIVATE.filter(browser => browser !== preferred)];
  for (const browser of candidates) {
    if (!(await available(browser))) continue;
    try { await launcher(browser, url); return { browser: browser.name, usedDefault: browser === preferred }; } catch { /* try the next browser */ }
  }
  throw new HttpError('No browser with a private window could be opened. Open the sign-in link in a private window yourself.', 503);
}

// ── SigV4 for Parameter Store ────────────────────────────────────────────────

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const hmac = (key, value) => crypto.createHmac('sha256', key).update(value).digest();

function signedSsmRequest(credentials, target, body, now = new Date()) {
  const host = `ssm.${PARAMETER_REGION}.amazonaws.com`;
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const date = amzDate.slice(0, 8);
  const headers = { 'content-type': 'application/x-amz-json-1.1', host, 'x-amz-date': amzDate, 'x-amz-security-token': credentials.sessionToken, 'x-amz-target': `AmazonSSM.${target}` };
  const names = Object.keys(headers).sort();
  const canonical = ['POST', '/', '', ...names.map(name => `${name}:${headers[name]}`), '', names.join(';'), sha256(body)].join('\n');
  const scope = `${date}/${PARAMETER_REGION}/ssm/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(canonical)].join('\n');
  const key = ['ssm', 'aws4_request'].reduce(hmac, hmac(hmac(`AWS4${credentials.secretAccessKey}`, date), PARAMETER_REGION));
  const signature = crypto.createHmac('sha256', key).update(toSign).digest('hex');
  const { host: _host, ...sent } = headers;
  return { url: `https://${host}/`, headers: { ...sent, Authorization: `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${names.join(';')}, Signature=${signature}` }, body };
}

/** Decrypted values by name; null (with a reason) when this role cannot read them. */
async function getParameters(fetchImpl, credentials, names) {
  const request = signedSsmRequest(credentials, 'GetParameters', JSON.stringify({ Names: names, WithDecryption: true }));
  const { ok, payload } = await awsJson(fetchImpl, request.url, { method: 'POST', headers: request.headers, body: request.body });
  if (!ok) return { values: null, reason: String(payload.__type || payload.message || 'Access denied').split('#').pop() };
  const values = Object.fromEntries((payload.Parameters || []).map(item => [item.Name, item.Value]));
  return names.every(name => values[name]) ? { values } : { values: null, reason: 'ParameterNotFound' };
}

// ── Sign-in sessions ─────────────────────────────────────────────────────────

function createAwsSso({ fetchImpl = fetch, openBrowser = openPrivate } = {}) {
  const logins = new Map();
  const call = (...args) => awsJson(fetchImpl, ...args);

  function expire() { for (const [id, login] of logins) if (login.expiresAt < Date.now()) logins.delete(id); }
  function loginFor(id) {
    expire();
    const login = typeof id === 'string' ? logins.get(id) : null;
    if (!login) throw new HttpError('This sign-in expired. Sign in again.', 410);
    return login;
  }

  async function start(options) {
    const { startUrl, region } = validateStart(options);
    const oidc = `https://oidc.${region}.amazonaws.com`;
    const json = { 'Content-Type': 'application/json' };
    const client = await call(`${oidc}/client/register`, { method: 'POST', headers: json, body: JSON.stringify({ clientName: 'threatlint-workbench', clientType: 'public' }) });
    if (!client.ok) throw new HttpError(`IAM Identity Center rejected the sign-in client (HTTP ${client.status}). Check the region.`, 502);
    const device = await call(`${oidc}/device_authorization`, { method: 'POST', headers: json,
      body: JSON.stringify({ clientId: client.payload.clientId, clientSecret: client.payload.clientSecret, startUrl }) });
    if (!device.ok) throw new HttpError(`IAM Identity Center did not accept ${startUrl} in ${region} (HTTP ${device.status}). Check the access portal URL and region.`, 502);
    const verify = new URL(device.payload.verificationUriComplete);
    if (verify.protocol !== 'https:' || !/(\.amazonaws\.com|\.awsapps\.com|\.aws)$/.test(verify.hostname)) throw new HttpError('Unexpected AWS verification URL', 502);
    const id = crypto.randomUUID();
    logins.set(id, { region, oidc, clientId: client.payload.clientId, clientSecret: client.payload.clientSecret, deviceCode: device.payload.deviceCode,
      interval: Math.max(1, device.payload.interval || 5), expiresAt: Date.now() + Math.min(LOGIN_TTL_MS, (device.payload.expiresIn || 600) * 1000), token: null });
    let opened = null, openError = null;
    try { opened = await openBrowser(verify.href); } catch (error) { openError = error.message; }
    return { loginId: id, userCode: device.payload.userCode, verificationUrl: verify.href, interval: logins.get(id).interval, browser: opened?.browser || null, usedDefault: !!opened?.usedDefault, openError };
  }

  async function roles(login) {
    const portal = `https://portal.sso.${login.region}.amazonaws.com`;
    const headers = { 'x-amz-sso_bearer_token': login.token };
    const accounts = (await call(`${portal}/assignment/accounts?max_result=100`, { headers })).payload.accountList || [];
    const pairs = [];
    for (const account of accounts) {
      const list = (await call(`${portal}/assignment/roles?account_id=${encodeURIComponent(account.accountId)}&max_result=100`, { headers })).payload.roleList || [];
      for (const role of list) pairs.push({ accountId: account.accountId, accountName: account.accountName || account.accountId, roleName: role.roleName });
    }
    return pairs;
  }

  /** One token exchange per call; the UI polls at the returned interval. */
  async function poll(loginId) {
    const login = loginFor(loginId);
    if (!login.token) {
      const { ok, payload } = await call(`${login.oidc}/token`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientId: login.clientId, clientSecret: login.clientSecret, grantType: 'urn:ietf:params:oauth:grant-type:device_code', deviceCode: login.deviceCode }) });
      if (!ok) {
        if (payload.error === 'authorization_pending') return { status: 'pending', interval: login.interval };
        if (payload.error === 'slow_down') { login.interval += 5; return { status: 'pending', interval: login.interval }; }
        logins.delete(loginId);
        throw new HttpError(payload.error === 'access_denied' ? 'Sign-in was denied in the browser.' : 'Sign-in expired before it was approved. Sign in again.', 401);
      }
      login.token = payload.accessToken;
    }
    login.roles ||= await roles(login);
    if (!login.roles.length) throw new HttpError('Your SSO user has no AWS account roles. Request access to the account holding the ServiceNow keys.', 403);
    return { status: 'signed-in', roles: login.roles };
  }

  /** ServiceNow client and Semgrep token, read with the chosen role (or the first role that can read them). */
  async function values(loginId, { accountId, roleName } = {}) {
    const login = loginFor(loginId);
    if (!login.roles) throw new HttpError('Finish signing in first', 409);
    const chosen = accountId ? login.roles.filter(role => role.accountId === String(accountId) && role.roleName === String(roleName)) : login.roles;
    if (!chosen.length) throw new HttpError('Choose one of your AWS account roles');
    const portal = `https://portal.sso.${login.region}.amazonaws.com`;
    const failures = [];
    for (const role of chosen.slice(0, 20)) {
      const { ok, payload } = await call(`${portal}/federation/credentials?account_id=${encodeURIComponent(role.accountId)}&role_name=${encodeURIComponent(role.roleName)}`,
        { headers: { 'x-amz-sso_bearer_token': login.token } });
      if (!ok || !payload.roleCredentials) { failures.push(`${role.accountName}/${role.roleName}: no credentials`); continue; }
      const credentials = payload.roleCredentials;
      const snow = await getParameters(fetchImpl, credentials, SNOW_PARAMETERS);
      if (!snow.values) { failures.push(`${role.accountName}/${role.roleName}: ${snow.reason}`); continue; }
      const semgrep = await getParameters(fetchImpl, credentials, [SEMGREP_PARAMETER]);
      logins.delete(loginId);
      return { account: `${role.accountName} / ${role.roleName}`, clientId: snow.values[SNOW_PARAMETERS[0]], clientSecret: snow.values[SNOW_PARAMETERS[1]],
        semgrepToken: semgrep.values?.[SEMGREP_PARAMETER] || null, semgrepError: semgrep.values ? null : semgrep.reason };
    }
    throw new HttpError(`None of your roles can read the ServiceNow keys (${failures.slice(0, 3).join('; ')}). Request access through SSO.`, 403);
  }

  return { start, poll, values, cancel: id => logins.delete(id) };
}

module.exports = { createAwsSso, openPrivate, validateStart, signedSsmRequest, PRIVATE };
