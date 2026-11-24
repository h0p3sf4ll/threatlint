'use strict';

// Local-only Parameter Store bindings. Persist references; hold decrypted values in this process only.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const { HttpError, handle } = require('./http.cjs');
const { orgValue } = require('./org-config.cjs');
const { superviseChild } = require('./child-lifecycle.cjs');

const FIELDS = [
  ['THREATLINT_SNOW_INSTANCE', 'ServiceNow instance URL'],
  ['THREATLINT_SNOW_CLIENT_ID', 'ServiceNow client ID', 'snowClientIdParameter'],
  ['THREATLINT_SNOW_CLIENT_SECRET', 'ServiceNow client secret', 'snowClientSecretParameter'],
  ['SEMGREP_APP_TOKEN', 'Semgrep API token', 'semgrepTokenParameter'],
  ['THREATLINT_SEMGREP_DEPLOYMENT', 'Semgrep deployment'],
  ['THREATLINT_ADO_PAT', 'Azure DevOps PAT', 'adoPatParameter'],
  ['THREATLINT_GITHUB_APP_ID', 'GitHub App ID'],
  ['THREATLINT_GITHUB_APP_INSTALLATION_ID', 'GitHub App installation ID'],
  ['THREATLINT_GITHUB_APP_PRIVATE_KEY', 'GitHub App private key (PEM)', 'githubAppPrivateKeyParameter'],
  ['OPENAI_API_KEY', 'OpenAI API key'], ['ANTHROPIC_API_KEY', 'Anthropic API key'],
  ['AWS_BEARER_TOKEN_BEDROCK', 'Bedrock API key'], ['COPILOT_GITHUB_TOKEN', 'Copilot token'],
  ['THREATLINT_DOJO_TOKEN', 'DefectDojo API token', 'dojoTokenParameter'],
  ['THREATLINT_SONAR_TOKEN', 'SonarQube API token', 'sonarTokenParameter'],
].map(([key, label, orgKey]) => ({ key, label, orgKey }));
const PROFILE = /^[\w.@+][\w.@+-]{0,127}$/;
const REGION = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)+-\d+$/;
const PARAMETER = /^(?:[A-Za-z0-9_./][A-Za-z0-9_./-]*|arn:aws(?:-[a-z]+)*:ssm:[a-z0-9-]+:\d{12}:parameter\/[A-Za-z0-9_./-]+)$/;

function verificationUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && !url.port &&
      ((/^[a-z0-9-]+\.(?:awsapps\.com|app\.aws)$/i.test(url.hostname) && /^\/start\/?$/.test(url.pathname) && url.hash.startsWith('#/device')) ||
       (/^device\.sso\.[a-z0-9-]+\.amazonaws\.com$/i.test(url.hostname) && url.pathname === '/')) ? url.href : '';
  } catch { return ''; }
}

function createAwsParameters({ env = process.env, directory, cli, spawnImpl = spawn, python, pythonPath, readParameters } = {}) {
  const workflow = () => require('./avit-batch.cjs');
  cli ||= (...args) => workflow().runCli(...args);
  readParameters ||= (...args) => require('./servicenow.cjs').readParameters(...args);
  const file = path.join(directory || env.THREATLINT_HOME || path.join(os.homedir(), '.threatlint'), 'aws-parameters.json');
  let state = { state: 'idle', message: 'Sign in to AWS, then load your configured values.' }, controller, loading = false, closed = false;
  const owned = new Map();
  const disabled = () => env.THREATLINT_PROFILE_WORKER === '1';
  function local() { if (disabled()) throw new HttpError('AWS browser sign-in is available in the local desktop runner only.', 403); if (closed) throw new HttpError('The local runner has closed.', 503); }
  function read() {
    let saved = {};
    try { saved = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { /* New installation. */ }
    const parameters = Object.fromEntries(FIELDS.map(field => [field.key,
      saved.parameters?.[field.key] ?? (field.orgKey ? orgValue(field.orgKey) : '')]).filter(([, value]) => value));
    return { profile: saved.profile || orgValue('awsProfile') || env.AWS_PROFILE || 'appsec',
      region: saved.region || orgValue('awsRegion') || 'us-west-2', parameters, autoLoad: saved.autoLoad === true };
  }
  function validate(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key => !['profile', 'region', 'parameters', 'autoLoad'].includes(key))) throw new HttpError('Invalid AWS settings');
    if (!PROFILE.test(input.profile || '') || !REGION.test(input.region || '')) throw new HttpError('Enter a valid AWS profile and Parameter Store region.');
    if (!input.parameters || typeof input.parameters !== 'object' || Array.isArray(input.parameters)) throw new HttpError('Enter named Parameter Store references.');
    const allowed = new Set(FIELDS.map(field => field.key));
    for (const [key, value] of Object.entries(input.parameters)) {
      if (!allowed.has(key) || typeof value !== 'string' || value.length > 2048 || (value && !PARAMETER.test(value))) throw new HttpError('Invalid Parameter Store binding. Use a parameter name or SSM ARN.');
    }
    return { profile: input.profile, region: input.region, parameters: input.parameters, autoLoad: input.autoLoad === true };
  }
  function clearOwned() {
    for (const [key, previous] of owned) if (previous === undefined) delete env[key]; else env[key] = previous;
    owned.clear();
  }
  function save(input) {
    local();
    if (controller || loading) throw new HttpError('Wait for the current AWS operation or cancel sign-in before changing settings.', 409);
    const saved = validate(input);
    const previous = read();
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const temporary = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify(saved, null, 2), { mode: 0o600 }); fs.renameSync(temporary, file);
    if (saved.profile !== previous.profile || saved.region !== previous.region || FIELDS.some(({ key }) => (saved.parameters[key] || '') !== (previous.parameters[key] || ''))) clearOwned();
    state = { state: 'idle', message: 'Parameter references saved. Load values to use them.' };
    return view();
  }
  function view() { return disabled() ? { available: false } : { available: true, settings: read(), fields: FIELDS.map(({ key, label }) => ({ key, label })), ...state }; }
  async function status() {
    if (disabled()) return { available: false };
    let discovery = { cliAvailable: false, profiles: [], browsers: [] };
    try { const result = await cli(['aws', 'status', '--json']); if (result.code === 0) discovery = JSON.parse(result.stdout); } catch { /* Availability remains false. */ }
    return { ...view(), ...discovery };
  }
  async function pull({ afterLogin = false } = {}) {
    local();
    if (controller && !afterLogin) throw new HttpError('Finish or cancel AWS sign-in before loading parameters.', 409);
    if (loading) throw new HttpError('AWS parameters are already loading.', 409);
    const settings = validate(read());
    const entries = Object.entries(settings.parameters).filter(([, value]) => value);
    if (!entries.length) throw new HttpError('Add at least one Parameter Store reference in AWS settings.');
    loading = true; state = { state: 'loading', message: 'Reading configured parameters with your AWS session…' };
    try {
      const names = [...new Set(entries.map(([, name]) => name))], values = {};
      for (let i = 0; i < names.length; i += 10) Object.assign(values, await readParameters(names.slice(i, i + 10), { profile: settings.profile, region: settings.region }));
      // Apply the set atomically. Never keep a mixture of old and partly loaded credentials.
      if (closed || entries.some(([, name]) => typeof values[name] !== 'string' || !values[name].trim() || values[name].length > 32768)) throw new Error('missing parameter');
      clearOwned();
      for (const [key, name] of entries) { owned.set(key, env[key]); env[key] = values[name].trim(); }
      owned.set('THREATLINT_AWS_PROFILE', env.THREATLINT_AWS_PROFILE); env.THREATLINT_AWS_PROFILE = settings.profile;
      owned.set('THREATLINT_AWS_REGION', env.THREATLINT_AWS_REGION); env.THREATLINT_AWS_REGION = settings.region;
      state = { state: 'ready', loadedCount: entries.length, loadedKeys: entries.map(([key]) => key), loadedAt: new Date().toISOString(), message: `Loaded ${entries.length} configured values for this app session. Secret values are never displayed.` };
      return view();
    } catch {
      state = { state: 'failed', message: 'Parameters could not be loaded. Check AWS sign-in, parameter names, region, and SSM/KMS read permissions. No new values were applied.' };
      throw new HttpError(state.message, 502);
    } finally { loading = false; }
  }
  function login(input = {}) {
    local();
    if (controller || loading) throw new HttpError('An AWS operation is already in progress.', 409);
    const settings = validate(read()), browser = input.browser || 'auto';
    if (!Object.values(settings.parameters).some(Boolean)) throw new HttpError('Add at least one Parameter Store reference before signing in and loading values.');
    if (!['auto', 'chrome', 'edge', 'safari'].includes(browser)) throw new HttpError('Choose an installed Chrome, Edge, or Safari browser.');
    const args = ['aws', 'login', '--profile', settings.profile, '--browser', browser, '--events'];
    const patterns = { startUrl: /^https:\/\/[a-z0-9-]+\.(?:awsapps\.com|app\.aws)\/start\/?$/i, ssoRegion: REGION, accountId: /^\d{12}$/, role: PROFILE };
    for (const [key, flag] of [['startUrl', '--start-url'], ['ssoRegion', '--sso-region'], ['accountId', '--account-id'], ['role', '--role']]) {
      const value = input[key]; if (value) { if (typeof value !== 'string' || value.length > 2048 || !patterns[key].test(value)) throw new HttpError('Invalid AWS SSO profile settings.'); args.push(flag, value); }
    }
    controller = new AbortController();
    state = { state: 'starting', message: 'Opening AWS sign-in in a private browser window…' };
    const root = pythonPath || workflow().pythonPath();
    const child = spawnImpl(python || workflow().python(), ['-u', '-c', 'from threatlint.cli import main; main()', ...args], {
      env: { ...env, PYTHONPATH: [root, env.PYTHONPATH].filter(Boolean).join(path.delimiter), PYTHONIOENCODING: 'utf-8', AWS_PAGER: '' },
      windowsHide: true, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'],
    });
    // Stop the AWS CLI too when the user cancels, the deadline expires, or the app closes.
    const originalKill = child.kill.bind(child);
    child.kill = signal => {
      try {
        if (child.pid && process.platform !== 'win32') { process.kill(-child.pid, signal); return true; }
        if (child.pid && process.platform === 'win32') {
          spawn(path.win32.join(env.SystemRoot || 'C:\\Windows', 'System32', 'taskkill.exe'), ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' }).on('error', () => originalKill(signal));
          return true;
        }
      } catch { /* exited */ }
      return originalKill(signal);
    };
    let pending = '', authenticated = false;
    const finished = new Promise((resolve, reject) => {
      const lifecycle = superviseChild(child, { signal: controller.signal, timeoutMs: 10 * 60_000, timeoutMessage: 'AWS sign-in timed out.', startMessage: 'AWS sign-in could not start.', resolve, reject,
        onClose: (code, finish) => finish(null, code) });
      child.stdout.on('data', chunk => {
        pending += chunk;
        if (pending.length > 32768) { lifecycle.stop(new Error('Invalid AWS sign-in output')); return; }
        const lines = pending.split(/\r?\n/); pending = lines.pop();
        for (const line of lines) {
          let event; try { event = JSON.parse(line); } catch { continue; }
          if (event.state === 'authenticated') authenticated = true;
          if (event.state === 'awaiting_sign_in') state = { state: 'awaiting_sign_in', message: 'Complete AWS SSO and MFA in the private browser window.',
            browser: ['Google Chrome', 'Microsoft Edge', 'Safari'].includes(event.browser) ? event.browser : '', verificationUrl: verificationUrl(event.verificationUrl) };
        }
      });
      child.stderr.on('data', () => {}); // Raw CLI diagnostics may contain credentials; never expose them.
    });
    finished.then(async code => { if (code !== 0 || !authenticated) throw new Error('AWS sign-in incomplete'); await pull({ afterLogin: true }); })
      .catch(() => { if (!['failed', 'cancelled'].includes(state.state)) state = { state: 'failed', message: 'AWS sign-in did not complete. Check the SSO profile and retry. Safari may need macOS Automation and Accessibility permission; you can also choose Chrome or Edge.' }; })
      .finally(() => { controller = null; });
    return view();
  }
  function cancel() { controller?.abort(); state = { state: 'cancelled', message: 'AWS sign-in cancelled.' }; return view(); }
  function close() { closed = true; controller?.abort(); clearOwned(); }
  return { status, view, save, pull, login, cancel, close, autoLoad: () => read().autoLoad };
}

function registerAwsParameterRoutes(app, options = {}) {
  const manager = createAwsParameters(options);
  app.get('/api/aws/settings', handle(() => manager.status()));
  app.put('/api/aws/settings', handle(req => manager.save(req.body)));
  app.get('/api/aws/login', handle(() => manager.view()));
  app.post('/api/aws/login', handle(req => manager.login(req.body)));
  app.delete('/api/aws/login', handle(() => manager.cancel()));
  app.post('/api/aws/parameters/load', handle(() => manager.pull()));
  return manager;
}
module.exports = { createAwsParameters, registerAwsParameterRoutes, verificationUrl, FIELDS };
