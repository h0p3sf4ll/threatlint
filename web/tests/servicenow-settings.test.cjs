'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-home-'));
process.env.THREATLINT_HOME = home;
const { createWorkbench } = require('../server.js');
const { validateCredentials } = require('../lib/servicenow.cjs');

describe('Saved ServiceNow settings', () => {
  let instance, base;
  before(async () => {
    instance = createWorkbench({ storageDir: fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-store-')) });
    await new Promise(resolve => instance.server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${instance.server.address().port}`;
  });
  after(async () => { await instance.close(); });
  const call = async (method, body) => {
    const response = await fetch(`${base}/api/servicenow/settings`, { method, headers: { 'Content-Type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) });
    return { status: response.status, body: await response.json() };
  };

  it('saves once, never returns the secret, and keeps it when the masked field is left alone', async () => {
    const saved = await call('POST', { instance: 'https://example.service-now.com/', clientId: 'client-id', clientSecret: 'super-secret' });
    assert.deepEqual({ ...saved.body, path: undefined }, { instance: 'https://example.service-now.com', clientId: 'client-id', hasSecret: true, path: undefined });
    assert.doesNotMatch(JSON.stringify((await call('GET')).body), /super-secret/);
    const file = path.join(home, 'servicenow.json');
    if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    await call('POST', { instance: 'https://example.service-now.com', clientId: 'client-id-2' });
    assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).clientSecret, 'super-secret');
    // Runs send blanks; the saved values fill them in.
    assert.deepEqual(validateCredentials({}), { instance: 'https://example.service-now.com', clientId: 'client-id-2', clientSecret: 'super-secret' });
  });
  it('rejects incomplete or non-ServiceNow settings', async () => {
    assert.equal((await call('POST', { instance: 'https://attacker.example', clientId: 'x', clientSecret: 'y' })).status, 400);
  });
});

describe('Saved Semgrep token', () => {
  it('validates against Semgrep, saves owner-only, and never returns the token', async () => {
    const fsx = require('node:fs'), pathx = require('node:path'), osx = require('node:os');
    const calls = [];
    const wb = createWorkbench({ storageDir: fsx.mkdtempSync(pathx.join(osx.tmpdir(), 'tl-')), integrations: { fetchImpl: async (url, options) => {
      calls.push({ url, auth: options.headers.Authorization });
      return { ok: true, status: 200, json: async () => ({ deployments: [{ id: 1, slug: 'example_org' }] }) };
    } } });
    await new Promise(resolve => wb.server.listen(0, '127.0.0.1', resolve));
    const url = `http://127.0.0.1:${wb.server.address().port}/api/semgrep/settings`;
    try {
      const saved = await (await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: 'a'.repeat(64) }) })).json();
      assert.equal(saved.hasToken, true); assert.equal(saved.deployment, 'example_org');
      assert.match(calls[0].url, /^https:\/\/semgrep\.dev\/api\/v1\/deployments$/);
      assert.doesNotMatch(JSON.stringify(await (await fetch(url)).json()), /aaaaaaaaaa/);
      const file = pathx.join(process.env.THREATLINT_HOME, 'semgrep.json');
      if (process.platform !== 'win32') assert.equal(fsx.statSync(file).mode & 0o777, 0o600);
      assert.equal(require('../lib/threatlint-config.cjs').readSemgrep().token, 'a'.repeat(64));
    } finally { await wb.close(); }
  });
});

describe('Saved Azure DevOps PAT and required setup', () => {
  it('passes the PAT to `threatlint ado login` on stdin only, and never returns it', async () => {
    const PAT = 'z'.repeat(52), calls = [];
    let saved = false;
    const threatlintCli = async (args, options = {}) => {
      calls.push({ args, input: options.input });
      if (args[0] === 'ado' && args[1] === 'login') { saved = options.input === PAT; return { code: 0, stdout: '✓ PAT validated and saved to the OS credential store\n', stderr: '' }; }
      if (args[0] === 'ado') return { code: 0, stdout: saved ? 'Azure DevOps PAT: OS credential store\n' : 'No Azure DevOps PAT configured.\n', stderr: '' };
      if (args[0] === 'setup') return { code: 1, stdout: JSON.stringify([{ name: 'Azure DevOps PAT', configured: saved, source: saved ? 'OS credential store' : null, fix: 'threatlint ado login' }]), stderr: '' };
      throw new Error(args.join(' '));
    };
    const wb = createWorkbench({ storageDir: fs.mkdtempSync(path.join(os.tmpdir(), 'tl-')), integrations: { threatlintCli } });
    await new Promise(resolve => wb.server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${wb.server.address().port}`;
    const post = body => fetch(`${base}/api/ado/settings`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    try {
      assert.equal((await (await fetch(`${base}/api/setup/status`)).json()).items[0].configured, false);
      assert.equal((await post({ organization: 'https://dev.azure.com/x', pat: PAT })).status, 400);
      const response = await post({ organization: 'contoso', pat: PAT });
      const text = await response.text();
      assert.equal(response.status, 200); assert.doesNotMatch(text, /zzzzzzzz/); assert.equal(JSON.parse(text).hasPat, true);
      assert.ok(calls.every(call => !call.args.includes(PAT)), 'the PAT is never in argv');
      assert.equal((await (await fetch(`${base}/api/setup/status`)).json()).items[0].configured, true);
    } finally { await wb.close(); }
  });
});
