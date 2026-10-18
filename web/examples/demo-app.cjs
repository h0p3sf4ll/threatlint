'use strict';

/**
 * Deliberately weak loopback-only app used by runtime tests, the bundled
 * synthetic example, and the narrated video recordings. Never deploy it.
 *
 * Accounts: admin/admin-pass (role admin), dev/dev-pass (role user).
 * Weaknesses: /api/orders has no auth check, CORS reflects any origin with
 * credentials, the session cookie lacks HttpOnly/SameSite, /debug leaks a
 * stack trace, and /api/admin/users is readable by the user role.
 */

const http = require('node:http');

const TOKENS = { 'admin-token': 'admin', 'dev-token': 'user' };
const SESSIONS = new Map();

function identity(req) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) return TOKENS[auth.slice(7)] || null;
  if (auth.startsWith('Basic ')) {
    const [user, pass] = Buffer.from(auth.slice(6), 'base64').toString().split(':');
    if (user === 'admin' && pass === 'admin-pass') return 'admin';
    if (user === 'dev' && pass === 'dev-pass') return 'user';
  }
  if (req.headers['x-api-key'] === 'demo-key') return 'user';
  const sid = /sid=([\w-]+)/.exec(req.headers.cookie || '')?.[1];
  return sid ? SESSIONS.get(sid) || null : null;
}

function createDemoApp() {
  return http.createServer((req, res) => {
    const url = new URL(req.url, 'http://demo');
    const send = (status, body, headers = {}) => {
      res.writeHead(status, { 'Content-Type': 'application/json', Server: 'demo-node/18.2.0', 'X-Powered-By': 'Express 4.18.2', ...headers });
      res.end(typeof body === 'string' ? body : JSON.stringify(body));
    };
    if (req.headers.origin) res.setHeader('Access-Control-Allow-Origin', req.headers.origin), res.setHeader('Access-Control-Allow-Credentials', 'true');
    const role = identity(req);
    if (req.method === 'POST' && url.pathname === '/oauth/token') {
      let body = ''; req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        const form = new URLSearchParams(body);
        if (form.get('client_id') === 'ci-client' && form.get('client_secret') === 'ci-secret') return send(200, { access_token: 'admin-token', token_type: 'Bearer', expires_in: 300 });
        if (form.get('grant_type') === 'password' && form.get('username') === 'dev' && form.get('password') === 'dev-pass') return send(200, { access_token: 'dev-token', token_type: 'Bearer' });
        send(401, { error: 'invalid_client' });
      });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/login') {
      let body = ''; req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        const form = new URLSearchParams(body);
        const user = { admin: 'admin-pass', dev: 'dev-pass' }[form.get('username')] === form.get('password') ? (form.get('username') === 'admin' ? 'admin' : 'user') : null;
        if (!user) return send(401, { error: 'bad credentials' });
        const sid = Math.random().toString(36).slice(2);
        SESSIONS.set(sid, user);
        send(200, { ok: true }, { 'Set-Cookie': `sid=${sid}; Path=/` });
      });
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(405, { error: 'method not allowed' });
    switch (url.pathname) {
      case '/': return send(200, '<!doctype html><title>Demo shop</title><h1>Demo shop</h1>', { 'Content-Type': 'text/html' });
      case '/api/health': return send(200, { ok: true });
      case '/api/profile': return role ? send(200, { role, email: `${role}@demo.test` }) : send(401, { error: 'login required' });
      case '/api/orders': return send(200, { orders: [{ id: 1, total: 42, card: '**** 4242' }, { id: 2, total: 13, card: '**** 1881' }] });
      case '/api/admin/users': return role ? send(200, { users: ['admin@demo.test', 'dev@demo.test', 'ops@demo.test'] }) : send(403, { error: 'forbidden' });
      case '/debug': return send(500, 'Traceback (most recent call last):\n  File "/srv/app/views.py", line 88, in orders\nKeyError: user_id', { 'Content-Type': 'text/plain' });
      default: return send(404, { error: 'not found' });
    }
  });
}

if (require.main === module) {
  const port = Number(process.env.DEMO_PORT || 4010);
  createDemoApp().listen(port, '127.0.0.1', () => console.log(`Weak demo app (loopback only): http://127.0.0.1:${port}`));
}

module.exports = { createDemoApp };
