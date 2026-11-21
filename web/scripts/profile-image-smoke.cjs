'use strict';

// Uses disposable Docker resources only. This verifies the image, not live Auth0 login.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { createProfileWorkers } = require('../lib/profile-workers.cjs');
const exec = promisify(execFile);

async function main() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-image-smoke-'));
  const namespace = `ci-${crypto.randomUUID().slice(0, 8)}`;
  const users = [{ id: crypto.randomUUID() }, { id: crypto.randomUUID() }];
  const makeManager = () => createProfileWorkers({ directory, namespace, mode: 'docker', maxWorkers: 1,
    image: process.env.THREATLINT_PROFILE_IMAGE || 'threatlint-profile:local', sweepIntervalMs: 0 });
  let manager = makeManager();
  async function request(worker, { method = 'GET', body, authorized = true } = {}) {
    const serialized = body === undefined ? null : JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const headers = { Host: `127.0.0.1:${worker.workerPort}` };
      if (authorized) headers['x-threatlint-worker'] = worker.token;
      if (serialized) Object.assign(headers, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(serialized) });
      const req = http.request({ hostname: '127.0.0.1', port: worker.port, path: '/api/model-preferences', method, headers }, res => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(data) }); } catch (error) { reject(error); } });
        res.on('error', reject);
      });
      req.on('error', reject);
      req.setTimeout(15_000, () => req.destroy(new Error('Profile request timed out')));
      req.end(serialized);
    });
  }
  async function inspect(user, marker, expected = null) {
    const lease = await manager.acquire(user);
    try {
      assert.equal((await request(lease.worker, { authorized: false })).status, 403);
      const before = await request(lease.worker);
      assert.equal(before.status, 200);
      assert.equal(before.body.preferences?.models.openai ?? null, expected);
      if (marker) {
        const result = await request(lease.worker, { method: 'PUT', body: { provider: 'openai', models: { openai: marker } } });
        assert.equal(result.status, 200);
        assert.equal(result.body.preferences.models.openai, marker);
      }
    } finally { lease.release(); }
  }
  try {
    await inspect(users[0], 'ci-profile-a');
    await inspect(users[1], 'ci-profile-b'); // Capacity pressure must safely evict A and preserve its volume.
    await inspect(users[0], null, 'ci-profile-a');
    await manager.close();
    manager = makeManager();
    await inspect(users[0], null, 'ci-profile-a');
    await inspect(users[1], null, 'ci-profile-b');
    process.stdout.write('Docker profiles reject unauthenticated access, isolate settings, and preserve them across eviction and worker-manager restart.\n');
  } finally {
    await manager.close();
    // Exact disposable volume names; never prune production or unrelated Docker state.
    await Promise.allSettled(users.map(user => exec('docker', ['volume', 'rm', `threatlint-${namespace}-${user.id}`])));
    fs.rmSync(directory, { recursive: true, force: true });
  }
}
main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
