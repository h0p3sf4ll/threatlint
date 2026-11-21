'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const WebSocket = require('ws');
const { createWorkbench } = require('../server.js');

async function start(directory) {
  const workbench = createWorkbench({ storageDir: directory });
  await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${workbench.server.address().port}`;
  async function call(route, { method = 'GET', json } = {}) {
    const response = await fetch(`${base}${route}`, { method, headers: { Origin: base,
      ...(json === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(json === undefined ? {} : { body: JSON.stringify(json) }) });
    const text = await response.text(); let body = text; try { body = JSON.parse(text); } catch { /* local HTML */ }
    return { status: response.status, body };
  }
  return { workbench, call, base };
}

it('keeps the desktop Workbench usable without Auth0 login and persists separate local user stores', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-desktop-compat-'));
  const firstDir = path.join(root, 'local-user-a'), secondDir = path.join(root, 'local-user-b');
  const first = await start(firstDir), second = await start(secondDir); let restarted;
  try {
    assert.equal((await first.call('/')).status, 200);
    assert.match((await first.call('/')).body, /id="view-workbench"/);
    assert.equal((await first.call('/api/agents')).status, 200);
    const firstPreferences = { provider: 'codex', models: { codex: 'local-a' }, codexDaybreak: false,
      bedrockRegion: '', lmstudioUrl: 'http://localhost:1234/v1' };
    const secondPreferences = { ...firstPreferences, provider: 'lmstudio', models: { lmstudio: 'local-b' } };
    assert.equal((await first.call('/api/model-preferences', { method: 'PUT', json: firstPreferences })).status, 200);
    assert.deepEqual((await second.call('/api/model-preferences')).body, { preferences: null });
    assert.equal((await second.call('/api/model-preferences', { method: 'PUT', json: secondPreferences })).status, 200);
    const repo = path.join(firstDir, 'source'); fs.mkdirSync(repo);
    const session = await first.call('/api/session/local', { method: 'POST', json: { repoPath: repo } });
    assert.equal(session.status, 200);
    assert.equal((await second.call(`/api/session/${session.body.sessionId}`)).status, 404);
    const ws = await new Promise((resolve, reject) => {
      const socket = new WebSocket(first.base.replace('http:', 'ws:'), { origin: first.base });
      socket.once('open', () => resolve(socket)); socket.once('error', reject);
    });
    try {
      const replay = new Promise(resolve => ws.once('message', raw => resolve(JSON.parse(raw))));
      ws.send(JSON.stringify({ action: 'avit_batch_attach' }));
      assert.equal((await replay).type, 'avit_batch_replay');
    } finally { ws.terminate(); }
    await first.workbench.close(); restarted = await start(firstDir);
    assert.deepEqual((await restarted.call('/api/model-preferences')).body.preferences, firstPreferences);
    assert.deepEqual((await second.call('/api/model-preferences')).body.preferences, secondPreferences);
    assert.equal((await restarted.call(`/api/session/${session.body.sessionId}`)).status, 200);
    for (const directory of [firstDir, secondDir]) {
      assert.equal(fs.existsSync(path.join(directory, 'identities.json')), false);
      assert.equal(fs.existsSync(path.join(directory, 'accounts.json')), false);
    }
  } finally {
    await restarted?.workbench.close();
    if (first.workbench.server.listening) await first.workbench.close();
    await second.workbench.close(); fs.rmSync(root, { recursive: true, force: true });
  }
});
