'use strict';
/**
 * HTTP API endpoint tests — spins up the server on a random port.
 */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const { server } = require('../server.js');

let baseUrl;

function get(urlPath) {
  return new Promise((resolve, reject) => {
    http.get(`${baseUrl}${urlPath}`, res => {
      let body = '';
      res.on('data', d => (body += d));
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(body) }); }
        catch { resolve({ status: res.statusCode, body }); }
      });
    }).on('error', reject);
  });
}

function post(urlPath, payload) {
  const data = JSON.stringify(payload);
  return new Promise((resolve, reject) => {
    const req = http.request(`${baseUrl}${urlPath}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
    }, res => {
      let body = '';
      res.on('data', d => (body += d));
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(body) }); }
        catch { resolve({ status: res.statusCode, body }); }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

before(() => new Promise(resolve => {
  server.listen(0, () => {
    baseUrl = `http://localhost:${server.address().port}`;
    resolve();
  });
}));

after(() => new Promise(resolve => server.close(resolve)));

describe('GET /api/agents', () => {
  it('returns 200 with array', async () => {
    const { status, body } = await get('/api/agents');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body));
  });

  it('includes all 14 agents', async () => {
    const { body } = await get('/api/agents');
    const ids = new Set(body.map(a => a.id));
    const expected = [
      'appsec-threat-modeler', 'appsec-code-reviewer', 'appsec-dependency-auditor',
      'appsec-secrets-scanner', 'appsec-iac-reviewer', 'appsec-cicd-auditor',
      'appsec-api-security-reviewer', 'appsec-auth-reviewer', 'appsec-fp-reviewer',
      'appsec-compliance-checker', 'appsec-attack-tree', 'appsec-red-team',
      'appsec-threat-delta', 'appsec-verify-fix',
    ];
    for (const id of expected) {
      assert.ok(ids.has(id), `Missing: ${id}`);
    }
  });

  it('each agent has required UI fields', async () => {
    const { body } = await get('/api/agents');
    for (const a of body) {
      assert.ok(a.id, `missing id`);
      assert.ok(a.label, `${a.id}: missing label`);
      assert.ok(a.color, `${a.id}: missing color`);
      assert.ok(a.emoji, `${a.id}: missing emoji`);
      assert.ok(a.category, `${a.id}: missing category`);
    }
  });

  it('new agents have correct categories', async () => {
    const { body } = await get('/api/agents');
    const byId = Object.fromEntries(body.map(a => [a.id, a]));
    assert.equal(byId['appsec-compliance-checker']?.category, 'Compliance');
    assert.equal(byId['appsec-attack-tree']?.category, 'Adversarial');
    assert.equal(byId['appsec-red-team']?.category, 'Adversarial');
    assert.equal(byId['appsec-threat-delta']?.category, 'Analysis');
    assert.equal(byId['appsec-verify-fix']?.category, 'Analysis');
  });
});

describe('POST /api/session/local', () => {
  it('400 when repoPath missing', async () => {
    const { status } = await post('/api/session/local', {});
    assert.equal(status, 400);
  });

  it('400 for non-existent path', async () => {
    const { status, body } = await post('/api/session/local', { repoPath: '/does/not/exist' });
    assert.equal(status, 400);
    assert.ok(body.error);
  });

  it('200 with sessionId for valid path', async () => {
    const { status, body } = await post('/api/session/local', { repoPath: os.tmpdir() });
    assert.equal(status, 200);
    assert.ok(body.sessionId);
    assert.ok(body.repoPath);
  });
});

describe('GET /api/fs/browse', () => {
  it('200 with entries for valid directory (defaults to homedir)', async () => {
    const { status, body } = await get('/api/fs/browse');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.entries));
  });

  it('200 with entries for an explicit path', async () => {
    const { status, body } = await get(`/api/fs/browse?path=${encodeURIComponent(os.tmpdir())}`);
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.entries));
  });

  it('400 for a non-directory path', async () => {
    const { status } = await get('/api/fs/browse?path=/etc/hosts');
    assert.equal(status, 400);
  });
});

describe('GET /api/report (missing)', () => {
  it('404 for unknown report', async () => {
    const { status } = await get('/api/report/bad-session/bad-agent/0/md');
    assert.equal(status, 404);
  });
});
