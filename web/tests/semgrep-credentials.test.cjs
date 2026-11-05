'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { nativeToken, semgrepToken } = require('../lib/semgrep-cloud.cjs');

test('Semgrep native login is read without copying and follows explicit credential precedence', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'semgrep-login-test-'));
  const names = ['SEMGREP_SETTINGS_FILE', 'SEMGREP_APP_TOKEN', 'THREATLINT_HOME'];
  const previous = Object.fromEntries(names.map(name => [name, process.env[name]]));
  t.after(() => { for (const name of names) previous[name] === undefined ? delete process.env[name] : process.env[name] = previous[name]; fs.rmSync(directory, { recursive: true, force: true }); });
  process.env.SEMGREP_SETTINGS_FILE = path.join(directory, 'settings.yml');
  process.env.THREATLINT_HOME = directory;
  delete process.env.SEMGREP_APP_TOKEN;
  fs.writeFileSync(process.env.SEMGREP_SETTINGS_FILE, 'api_token: "synthetic-native-token-123456" # login\n');
  assert.equal(nativeToken(), 'synthetic-native-token-123456');
  assert.equal(await semgrepToken(), 'synthetic-native-token-123456');
  assert.equal(fs.existsSync(path.join(directory, 'semgrep.json')), false);
  fs.writeFileSync(path.join(directory, 'semgrep.json'), JSON.stringify({ token: 'synthetic-saved-token-123456' }));
  assert.equal(await semgrepToken(), 'synthetic-native-token-123456');
  process.env.SEMGREP_APP_TOKEN = 'synthetic-env-token-123456';
  assert.equal(await semgrepToken(), 'synthetic-env-token-123456');
  for (const input of ['api_token: null\n', 'api_token: *anchor\n', 'x:\n  api_token: synthetic-native-token-123456\n', 'api_token: synthetic-native-token-123456\napi_token: synthetic-second-token-123456\n']) {
    fs.writeFileSync(process.env.SEMGREP_SETTINGS_FILE, input);
    assert.equal(nativeToken(), '');
  }
});
