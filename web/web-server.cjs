'use strict';

const express = require('express');
const http = require('node:http');
const path = require('node:path');
const { createAuth, sessionCookie, clearCookie } = require('./lib/web-auth.cjs');
const { createProfileWorkers } = require('./lib/profile-workers.cjs');
const { stateDirectory, acquireStateLock } = require('./lib/web-state.cjs');

const PUBLIC = path.join(__dirname, 'public');
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

function webOrigin(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('Set THREATLINT_WEB_ORIGIN to the externally visible HTTP(S) origin');
  if (url.protocol !== 'https:' && !LOOPBACK.has(url.hostname)) throw new Error('Public web deployments require an HTTPS origin');
  return url;
}

function createWebApp(options = {}) {
  const origin = webOrigin(options.origin || process.env.THREATLINT_WEB_ORIGIN || 'http://127.0.0.1:3000');
  const directory = options.directory || stateDirectory();
  const mode = options.mode || process.env.THREATLINT_PROFILE_MODE || 'docker';
  if (mode === 'process' && !LOOPBACK.has(origin.hostname)) throw new Error('Process profiles are only available for trusted loopback development');
  const release = acquireStateLock(directory);
  let auth, workers;
  try {
    auth = createAuth({ directory, sessionTtlMs: options.sessionTtlMs, now: options.now });
    workers = options.workers || createProfileWorkers({ directory, mode,
      image: process.env.THREATLINT_PROFILE_IMAGE || 'threatlint-profile:local',
      maxWorkers: Number(process.env.THREATLINT_MAX_PROFILES || 8),
      ...(process.env.THREATLINT_PROFILE_NAMESPACE ? { namespace: process.env.THREATLINT_PROFILE_NAMESPACE } : {}) });
  } catch (error) { release(); throw error; }
  const registrationEnabled = options.registrationEnabled ?? process.env.THREATLINT_WEB_REGISTRATION === '1';
  const secure = origin.protocol === 'https:';
  const app = express(); app.disable('x-powered-by');
  const server = http.createServer(app);
  server.headersTimeout = 15_000;
  const tunnels = new Set();
  const buckets = new Map();
  let authPending = 0, closing = false;

  function allowed(req, mutation = false) {
    if (req.headers.host?.toLowerCase() !== origin.host || req.headers['sec-fetch-site'] === 'cross-site') return false;
    if (req.headers.origin && req.headers.origin !== origin.origin) return false;
    return !mutation || req.headers.origin === origin.origin;
  }
  function limit(req, action) {
    const now = Date.now();
    for (const [key, bucket] of buckets) if (bucket.expires <= now) buckets.delete(key);
    const account = String(req.body?.email || '').toLowerCase().slice(0, 254);
    const keys = [[`ip:${req.socket.remoteAddress}`, 100], [`account:${action}:${account}`, 15]];
    for (const [key, max] of keys) {
      const bucket = buckets.get(key) || { count: 0, expires: now + 15 * 60_000 };
      if (bucket.count >= max || buckets.size >= 10000 || authPending >= 4) return false;
      bucket.count++; buckets.set(key, bucket);
    }
    return true;
  }
  function expireTunnels() {
    for (const tunnel of tunnels) if (!auth.authenticate(tunnel.req)) { tunnel.socket.destroy(); tunnel.upstream?.destroy(); tunnels.delete(tunnel); }
  }
  const sweep = setInterval(expireTunnels, 1000); sweep.unref();
  function workerHeaders(req, worker) {
    const headers = { ...req.headers, host: `127.0.0.1:${worker.workerPort}`, 'x-threatlint-worker': worker.token };
    delete headers.cookie; delete headers.authorization;
    for (const key of Object.keys(headers)) if (/^(forwarded|x-forwarded-|x-threatlint-(?!worker$))/.test(key)) delete headers[key];
    if (headers.origin) headers.origin = `http://127.0.0.1:${worker.workerPort}`;
    return headers;
  }

  app.use((req, res, next) => {
    res.set({ 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
      'X-Frame-Options': 'DENY', 'Content-Security-Policy': CSP });
    if (secure) res.set('Strict-Transport-Security', 'max-age=31536000');
    if (!allowed(req, !['GET', 'HEAD', 'OPTIONS'].includes(req.method))) return res.status(403).json({ error: 'Use the configured same-origin web app' });
    next();
  });
  app.get('/healthz', (_req, res) => res.json({ status: 'ok' }));
  app.get('/auth/config', (_req, res) => res.json({ registrationEnabled }));
  app.get('/auth/session', (req, res) => {
    const session = auth.authenticate(req);
    if (!session) return res.set('X-Threatlint-Auth', 'required').status(401).json({ error: 'Sign in to continue' });
    res.json({ user: session.user, web: true });
  });
  app.use('/auth', express.json({ limit: '8kb' }));
  for (const action of ['login', 'register']) app.post(`/auth/${action}`, async (req, res, next) => {
    if (action === 'register' && !registrationEnabled) return res.status(403).json({ error: 'Registration is closed. Ask your administrator for an account.' });
    if (!limit(req, action)) { res.set('Retry-After', '900'); return res.status(429).json({ error: 'Too many attempts. Try again later.' }); }
    authPending++;
    try {
      const result = await auth[action](req.body);
      // Replacing a login in the same browser revokes its previous session as well.
      auth.logout(req); expireTunnels();
      res.set('Set-Cookie', sessionCookie(result, { secure })).json({ user: result.user });
    } catch (error) { next(error); }
    finally { authPending--; }
  });
  app.post('/auth/logout', (req, res, next) => {
    try { auth.logout(req); expireTunnels(); res.set('Set-Cookie', clearCookie({ secure })).json({ ok: true }); }
    catch (error) { next(error); }
  });
  app.use('/auth', (_req, res) => res.status(404).json({ error: 'Unknown account route' }));
  for (const [url, file] of Object.entries({ '/login': 'login.html', '/login.html': 'login.html', '/login.js': 'login.js', '/login.css': 'login.css', '/mark.svg': 'mark.svg' })) {
    app.get(url, (req, res) => {
      if (file === 'login.html' && auth.authenticate(req)) return res.redirect('/');
      res.sendFile(path.join(PUBLIC, file));
    });
  }
  app.use(async (req, res, next) => {
    const session = auth.authenticate(req);
    if (!session) {
      if (req.path.startsWith('/api/') || req.headers.accept?.includes('application/json')) return res.set('X-Threatlint-Auth', 'required').status(401).json({ error: 'Sign in to continue' });
      return res.redirect('/login');
    }
    try {
      const worker = await workers.get(session.user);
      if (!auth.authenticate(req)) return res.set('X-Threatlint-Auth', 'required').status(401).json({ error: 'Sign in to continue' });
      const upstream = http.request({ hostname: '127.0.0.1', port: worker.port, method: req.method, path: req.originalUrl,
        headers: workerHeaders(req, worker) }, response => {
        const headers = { ...response.headers, 'cache-control': 'no-store' };
        delete headers['set-cookie'];
        res.writeHead(response.statusCode, headers); response.pipe(res);
      });
      upstream.on('error', () => { if (!res.headersSent) res.status(502).json({ error: 'Your Workbench is unavailable. Try again.' }); else res.destroy(); });
      req.on('aborted', () => upstream.destroy()); res.on('close', () => upstream.destroy());
      req.pipe(upstream);
    } catch (error) { next(error); }
  });
  app.use((error, _req, res, _next) => {
    const status = Number.isInteger(error.status) && error.status >= 400 && error.status < 600 ? error.status : 500;
    res.status(status).json({ error: status < 500 ? (status === 413 ? 'Account request is too large' : error.message) : 'Your Workbench could not start. Ask the administrator to check the profile runtime.' });
  });

  server.on('upgrade', async (req, socket, head) => {
    const reject = status => { if (!socket.destroyed) socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`); };
    if (!allowed(req) || req.headers.origin !== origin.origin) return reject('403 Forbidden');
    const session = auth.authenticate(req);
    if (!session) return reject('401 Unauthorized');
    if (req.url !== '/') return reject('404 Not Found');
    const tunnel = { req, socket, upstream: null };
    tunnels.add(tunnel); socket.once('close', () => { tunnel.upstream?.destroy(); tunnels.delete(tunnel); });
    try {
      const worker = await workers.get(session.user);
      if (socket.destroyed || !auth.authenticate(req)) return reject('401 Unauthorized');
      const request = http.request({ hostname: '127.0.0.1', port: worker.port, path: '/', headers: workerHeaders(req, worker) });
      request.on('upgrade', (response, upstream, upstreamHead) => {
        tunnel.upstream = upstream;
        if (socket.destroyed) return upstream.destroy();
        const headers = Object.entries(response.headers).flatMap(([key, value]) => (Array.isArray(value) ? value : [value]).map(item => `${key}: ${item}`));
        socket.write(`HTTP/1.1 101 Switching Protocols\r\n${headers.join('\r\n')}\r\n\r\n`);
        if (upstreamHead.length) socket.write(upstreamHead);
        if (head.length) upstream.write(head);
        upstream.on('error', () => socket.destroy()); socket.on('error', () => upstream.destroy());
        upstream.once('close', () => socket.destroy());
        socket.pipe(upstream); upstream.pipe(socket);
      });
      request.on('response', () => reject('502 Bad Gateway'));
      request.on('error', () => reject('502 Bad Gateway')); request.end();
    } catch { reject('503 Service Unavailable'); }
  });

  async function close() {
    if (closing) return; closing = true;
    clearInterval(sweep);
    for (const tunnel of tunnels) { tunnel.socket.destroy(); tunnel.upstream?.destroy(); }
    try {
      await workers.close();
      if (server.listening) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
    } finally { release(); }
  }
  return { app, server, auth, workers, close, origin: origin.origin };
}

if (require.main === module) {
  try {
    const host = process.env.THREATLINT_WEB_HOST || '127.0.0.1';
    if (process.env.THREATLINT_PROFILE_MODE === 'process' && !LOOPBACK.has(host)) throw new Error('Process mode must bind to loopback');
    const web = createWebApp();
    web.server.listen(Number(process.env.PORT || 3000), host, () => console.log(`Threatlint web app: ${web.origin}`));
    web.server.once('error', error => { console.error(error.message); web.close().then(() => { process.exitCode = 1; }); });
    process.once('SIGINT', () => web.close().then(() => process.exit(0)));
    process.once('SIGTERM', () => web.close().then(() => process.exit(0)));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { createWebApp, webOrigin };
