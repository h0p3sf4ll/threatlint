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
  after(async () => { await instance.close(); fs.rmSync(home, { recursive: true, force: true }); });
  const call = async (method, body) => {
    const response = await fetch(`${base}/api/servicenow/settings`, { method, headers: { 'Content-Type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) });
    return { status: response.status, body: await response.json() };
  };

  it('saves once, never returns the secret, and keeps it when the masked field is left alone', async () => {
    const saved = await call('POST', { instance: 'https://pepsico.service-now.com/', clientId: 'client-id', clientSecret: 'super-secret' });
    assert.deepEqual({ ...saved.body, path: undefined }, { instance: 'https://pepsico.service-now.com', clientId: 'client-id', hasSecret: true, path: undefined });
    assert.doesNotMatch(JSON.stringify((await call('GET')).body), /super-secret/);
    const file = path.join(home, 'servicenow.json');
    if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    await call('POST', { instance: 'https://pepsico.service-now.com', clientId: 'client-id-2' });
    assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).clientSecret, 'super-secret');
    // Runs send blanks; the saved values fill them in.
    assert.deepEqual(validateCredentials({}), { instance: 'https://pepsico.service-now.com', clientId: 'client-id-2', clientSecret: 'super-secret' });
  });
  it('rejects incomplete or non-ServiceNow settings', async () => {
    assert.equal((await call('POST', { instance: 'https://attacker.example', clientId: 'x', clientSecret: 'y' })).status, 400);
  });
});
