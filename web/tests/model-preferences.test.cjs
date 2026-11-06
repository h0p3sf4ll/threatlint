'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createWorkbench } = require('../server.js');

const PREFERENCES = {
  provider: 'codex', models: { codex: 'gpt-6-sol', bedrock: 'us.anthropic.fixture-v1:0', lmstudio: 'local-fixture' },
  codexDaybreak: true, bedrockRegion: 'us-east-1', lmstudioUrl: 'http://localhost:1234/v1',
};

async function start(directory) {
  const workbench = createWorkbench({ storageDir: directory });
  await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${workbench.server.address().port}`;
  const call = async (method = 'GET', value, headers = {}) => {
    const response = await fetch(`${base}/api/model-preferences`, { method, headers: { 'Content-Type': 'application/json', ...headers },
      ...(value === undefined ? {} : { body: JSON.stringify(value) }) });
    return { status: response.status, body: await response.json() };
  };
  return { workbench, base, call };
}

function directory(t) {
  const value = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-preferences-'));
  t.after(() => fs.rmSync(value, { recursive: true, force: true }));
  return value;
}

it('restores every model preference after a server restart on a different origin', async t => {
  const root = directory(t);
  const first = await start(root);
  try {
    assert.deepEqual(await first.call(), { status: 200, body: { preferences: null } });
    assert.deepEqual(await first.call('PUT', PREFERENCES), { status: 200, body: { preferences: PREFERENCES } });
  } finally { await first.workbench.close(); }
  const filename = path.join(root, 'model-preferences.json');
  assert.deepEqual(JSON.parse(fs.readFileSync(filename, 'utf8')), PREFERENCES);
  if (process.platform !== 'win32') assert.equal(fs.statSync(filename).mode & 0o777, 0o600);
  const second = await start(root);
  try {
    assert.notEqual(second.base, first.base);
    assert.deepEqual(await second.call(), { status: 200, body: { preferences: PREFERENCES } });
    const changed = { ...PREFERENCES, provider: 'bedrock', models: { ...PREFERENCES.models, codex: '' } };
    assert.equal((await second.call('PUT', changed)).status, 200);
    assert.deepEqual((await second.call()).body.preferences, changed);
    assert.deepEqual(fs.readdirSync(root).filter(name => name.endsWith('.tmp')), []);
  } finally { await second.workbench.close(); }
});

it('normalizes optional defaults and preserves explicit empty default-model choices', async t => {
  const fixture = await start(directory(t));
  try {
    const result = await fixture.call('PUT', { provider: 'claude', models: { claude: '', codex: '  fixture-model  ' } });
    assert.equal(result.status, 200);
    assert.deepEqual(result.body.preferences, { provider: 'claude', models: { claude: '', codex: 'fixture-model' },
      codexDaybreak: false, bedrockRegion: '', lmstudioUrl: 'http://localhost:1234/v1' });
  } finally { await fixture.workbench.close(); }
});

it('rejects secrets, consent, unknown providers and malformed values without replacing saved choices', async t => {
  const root = directory(t), fixture = await start(root);
  try {
    await fixture.call('PUT', PREFERENCES);
    const before = fs.readFileSync(path.join(root, 'model-preferences.json'), 'utf8');
    const invalid = [
      { ...PREFERENCES, apiKey: 'synthetic-secret' }, { ...PREFERENCES, credentials: { openai: 'synthetic-secret' } },
      { ...PREFERENCES, consent: ['openai'] }, { ...PREFERENCES, provider: 'unrecognized' },
      { ...PREFERENCES, models: { openai: 'x'.repeat(201) } }, { ...PREFERENCES, models: { apiKey: 'synthetic-secret' } },
      { ...PREFERENCES, models: { codex: 'model\nline' } }, { ...PREFERENCES, models: [] },
      { ...PREFERENCES, codexDaybreak: 'true' }, { ...PREFERENCES, bedrockRegion: 'us-east-1/other' },
      { ...PREFERENCES, lmstudioUrl: 'https://user:synthetic-secret@example.test/v1' },
      { ...PREFERENCES, lmstudioUrl: 'https://example.test/v1?token=synthetic-secret' },
      { ...PREFERENCES, lmstudioUrl: 'https://example.test/v1#fragment' },
      { ...PREFERENCES, lmstudioUrl: 'http://remote.example/v1' }, { ...PREFERENCES, lmstudioUrl: 'file:///tmp/model' },
      [], { provider: 'codex' },
    ];
    for (const value of invalid) {
      const result = await fixture.call('PUT', value);
      assert.equal(result.status, 400);
      assert.doesNotMatch(JSON.stringify(result.body), /synthetic-secret/);
    }
    assert.equal(fs.readFileSync(path.join(root, 'model-preferences.json'), 'utf8'), before);
  } finally { await fixture.workbench.close(); }
});

it('rejects cross-origin mutation through the existing loopback guard', async t => {
  const fixture = await start(directory(t));
  try {
    assert.equal((await fixture.call('PUT', PREFERENCES, { Origin: 'https://unrelated.example' })).status, 403);
    assert.equal((await fixture.call()).body.preferences, null);
  } finally { await fixture.workbench.close(); }
});

it('does not overwrite an invalid existing file or expose its content', async t => {
  const root = directory(t);
  const filename = path.join(root, 'model-preferences.json');
  fs.writeFileSync(filename, 'invalid synthetic-secret content');
  const fixture = await start(root);
  try {
    for (const result of [await fixture.call(), await fixture.call('PUT', PREFERENCES)]) {
      assert.equal(result.status, 500);
      assert.match(result.body.error, /original file was preserved/);
      assert.doesNotMatch(result.body.error, /synthetic-secret/);
    }
    assert.equal(fs.readFileSync(filename, 'utf8'), 'invalid synthetic-secret content');
  } finally { await fixture.workbench.close(); }
});

it('surfaces read permission failures without replacing the original preferences', async t => {
  const root = directory(t), fixture = await start(root);
  const filename = path.join(root, 'model-preferences.json');
  try {
    await fixture.call('PUT', PREFERENCES);
    const read = fs.readFileSync;
    const before = read(filename, 'utf8');
    t.mock.method(fs, 'readFileSync', function(file, ...args) {
      if (file === filename) throw Object.assign(new Error('synthetic-sensitive-filesystem-detail'), { code: 'EACCES' });
      return read.call(this, file, ...args);
    });
    for (const result of [await fixture.call(), await fixture.call('PUT', { ...PREFERENCES, provider: 'openai' })]) {
      assert.equal(result.status, 500);
      assert.match(result.body.error, /could not be read/);
      assert.doesNotMatch(result.body.error, /synthetic-sensitive/);
    }
    assert.equal(read(filename, 'utf8'), before);
  } finally { await fixture.workbench.close(); }
});

it('preserves the prior file and removes temporary files when atomic replacement fails', async t => {
  const root = directory(t), fixture = await start(root);
  const filename = path.join(root, 'model-preferences.json');
  try {
    await fixture.call('PUT', PREFERENCES);
    const before = fs.readFileSync(filename, 'utf8');
    const rename = fs.renameSync;
    t.mock.method(fs, 'renameSync', function(from, to) {
      if (to === filename) throw new Error('synthetic-sensitive-filesystem-detail');
      return rename.call(this, from, to);
    });
    const result = await fixture.call('PUT', { ...PREFERENCES, provider: 'openai' });
    assert.equal(result.status, 500);
    assert.match(result.body.error, /previous preferences were preserved/);
    assert.doesNotMatch(result.body.error, /synthetic-sensitive/);
    assert.equal(fs.readFileSync(filename, 'utf8'), before);
    assert.deepEqual(fs.readdirSync(root).filter(name => name.endsWith('.tmp')), []);
    assert.deepEqual((await fixture.call()).body.preferences, PREFERENCES);
  } finally { await fixture.workbench.close(); }
});

it('supports an isolated in-memory preference store when persistence is disabled', async () => {
  const first = await start(null);
  try {
    assert.equal((await first.call()).body.preferences, null);
    assert.equal((await first.call('PUT', PREFERENCES)).status, 200);
    assert.deepEqual((await first.call()).body.preferences, PREFERENCES);
  } finally { await first.workbench.close(); }
  const second = await start(null);
  try { assert.equal((await second.call()).body.preferences, null); }
  finally { await second.workbench.close(); }
});
