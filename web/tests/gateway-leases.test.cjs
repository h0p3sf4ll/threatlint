'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const { WebSocket, WebSocketServer } = require('ws');
const { createWebApp } = require('../web-server.cjs');
const { createAuth0Fixture } = require('./helpers/auth0.cjs');

async function eventually(check) {
  for (let index = 0; index < 100; index++) { if (check()) return; await new Promise(resolve => setTimeout(resolve, 10)); }
  throw new Error('Gateway did not release its worker lease');
}

it('leases workers for full HTTP and WebSocket lifetimes and keeps lifecycle probes private', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-gateway-leases-'));
  const held = [], stats = { active: 0, acquired: 0, capacity: false };
  const upstream = http.createServer((req, res) => {
    if (req.url === '/api/held') { held.push(res); res.writeHead(200, { 'Content-Type': 'text/plain' }); res.write('started'); return; }
    res.setHeader('Content-Type', 'application/json'); res.end('{"ok":true}');
  });
  const wss = new WebSocketServer({ server: upstream });
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
  const worker = { port: upstream.address().port, workerPort: upstream.address().port, token: 'fixture-worker-secret' };
  const workers = {
    async acquire() {
      if (stats.capacity) throw Object.assign(new Error('All profile workers are busy. Try again shortly.'), { status: 503, code: 'profile_capacity', retryAfter: 30 });
      stats.active++; stats.acquired++; let released = false;
      return { worker, release() { if (!released) { released = true; stats.active--; } } };
    },
    async close() {
      for (const client of wss.clients) client.terminate();
      await new Promise(resolve => wss.close(resolve));
      upstream.closeAllConnections(); await new Promise(resolve => upstream.close(resolve));
    },
  };
  const reserve = net.createServer(); await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
  const port = reserve.address().port; await new Promise(resolve => reserve.close(resolve));
  const origin = `http://127.0.0.1:${port}`, provider = createAuth0Fixture();
  const web = createWebApp({ directory: root, origin, mode: 'process', companies: [], workers,
    auth0: provider.configuration, auth0Fetch: provider.fetch });
  await new Promise(resolve => web.server.listen(port, '127.0.0.1', resolve));
  let ws;
  try {
    const signIn = await fetch(`${origin}/auth/session`, { method: 'POST', headers: { Origin: origin, Authorization: `Bearer ${provider.issue()}` } });
    assert.equal(signIn.status, 200); const cookie = signIn.headers.get('set-cookie').split(';')[0]; await signIn.text();
    const call = route => fetch(`${origin}${route}`, { headers: { Cookie: cookie } });
    const privateProbe = await call('/internal/activity'); assert.equal(privateProbe.status, 404); await privateProbe.text(); assert.equal(stats.acquired, 0);
    const response = await new Promise((resolve, reject) => http.get(`${origin}/api/held`, { headers: { Cookie: cookie } }, resolve).once('error', reject));
    response.resume(); assert.equal(stats.active, 1);
    const complete = new Promise(resolve => response.once('end', resolve)); held.shift().end('finished'); await complete;
    await eventually(() => stats.active === 0);
    let abortedRequest;
    const abortedResponse = await new Promise((resolve, reject) => {
      abortedRequest = http.get(`${origin}/api/held`, { headers: { Cookie: cookie } }, resolve);
      abortedRequest.on('error', reject);
    });
    abortedResponse.on('error', () => {}); assert.equal(stats.active, 1); abortedRequest.destroy();
    await eventually(() => stats.active === 0);
    held.shift().destroy();
    ws = new WebSocket(origin.replace('http:', 'ws:'), { origin, headers: { Cookie: cookie } });
    await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); }); assert.equal(stats.active, 1);
    const closed = new Promise(resolve => ws.once('close', resolve)); ws.terminate(); await closed;
    await eventually(() => stats.active === 0);
    stats.capacity = true;
    const busy = await call('/api/agents'); assert.equal(busy.status, 503); assert.equal(busy.headers.get('retry-after'), '30');
    assert.equal((await busy.json()).code, 'profile_capacity');
  } finally { ws?.terminate(); await web.close(); fs.rmSync(root, { recursive: true, force: true }); }
});
