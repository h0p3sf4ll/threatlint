'use strict';

const express = require('express');
const http = require('node:http');
const path = require('node:path');
const { createAuth, sessionCookie, clearCookie } = require('./lib/web-auth.cjs');
const { createProfileWorkers } = require('./lib/profile-workers.cjs');
const { stateDirectory, acquireStateLock } = require('./lib/web-state.cjs');
const { auth0Configuration, permittedSubject } = require('./lib/auth0-config.cjs');
const { createAuth0Api, requiresAuth } = require('@auth0/auth0-express-api');
const { AuthClient } = require('@auth0/auth0-auth-js');
const { createCompanies } = require('./lib/companies.cjs');
const { createAccessControl, requiredPermission, ROLE_CLAIM } = require('./lib/rbac.cjs');
const { registerGatewayManagement } = require('./lib/management-gateway.cjs');
const { createAuth0Management, unavailable } = require('./lib/auth0-management.cjs');
const { createOrganizationService } = require('./lib/organization-service.cjs');

const PUBLIC = path.join(__dirname, 'public');
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);

function webOrigin(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('Set THREATLINT_WEB_ORIGIN to the externally visible HTTP(S) origin');
  if (url.protocol !== 'https:' && !LOOPBACK.has(url.hostname)) throw new Error('Public web deployments require an HTTPS origin');
  return url;
}

function createWebApp(options = {}) {
  const origin = webOrigin(options.origin || process.env.THREATLINT_WEB_ORIGIN || 'https://app.threatlint.dev');
  const configuration = auth0Configuration(origin, options.auth0);
  const authShutdown = new AbortController();
  const tenantOrigin = `https://${configuration.domain}`;
  const csp = `default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' ws: wss: ${tenantOrigin}; frame-src ${tenantOrigin}; worker-src 'self'; img-src 'self' data:; media-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`;
  // These are official SDK transports. Test injection changes transport, never token validation.
  const sdkFetch = async (url, init = {}) => (options.auth0Fetch || fetch)(url, { ...init, redirect: 'error', signal: AbortSignal.any([authShutdown.signal, AbortSignal.timeout(10_000), ...(init.signal ? [init.signal] : [])]) });
  const auth0Router = createAuth0Api({ domain: configuration.domain, clientId: configuration.clientId, audience: configuration.audience, customFetch: sdkFetch });
  const auth0Client = new AuthClient({ domain: configuration.domain, clientId: configuration.clientId, customFetch: sdkFetch });
  const directory = options.directory || stateDirectory();
  const mode = options.mode || process.env.THREATLINT_PROFILE_MODE || 'docker';
  if (mode === 'process' && !LOOPBACK.has(origin.hostname)) throw new Error('Process profiles are only available for trusted loopback development');
  const release = acquireStateLock(directory);
  let auth, workers, access, companies, organizations;
  try {
    companies = createCompanies({ companies: options.companies, directory });
    auth = createAuth({ directory, sessionTtlMs: options.sessionTtlMs, now: options.now });
    access = createAccessControl({ directory, adminSubjects: options.adminSubjects, issuer: `${tenantOrigin}/` });
    const management = createAuth0Management({ ...(options.auth0Management || {}), domain: configuration.domain,
      transport: options.auth0ManagementFetch || options.auth0Fetch || fetch, signal: authShutdown.signal });
    organizations = createOrganizationService({ directory, issuer: `${tenantOrigin}/`, companies, management,
      grantCreator: (identity, company) => access.grantCreator(identity, company) });
    workers = options.workers || createProfileWorkers({ directory, mode,
      image: process.env.THREATLINT_PROFILE_IMAGE || 'threatlint-profile:local',
      maxWorkers: Number(process.env.THREATLINT_MAX_PROFILES || 8),
      ...(process.env.THREATLINT_PROFILE_NAMESPACE ? { namespace: process.env.THREATLINT_PROFILE_NAMESPACE } : {}) });
  } catch (error) { release(); throw error; }
  const secure = origin.protocol === 'https:';
  const app = express(); app.disable('x-powered-by');
  const server = http.createServer(app);
  server.headersTimeout = 15_000;
  const tunnels = new Set();
  const buckets = new Map();
  let authPending = 0, closing = false;
  const membershipChecks = new Map();

  function activeSession(req) {
    const session = auth.authenticate(req);
    if (!session?.user.company) return session;
    const company = companies.forOrganization(session.user.company.organizationId);
    return company ? { ...session, user: { ...session.user, company } } : null;
  }
  async function verifiedSession(req, { fresh = false } = {}) {
    if (closing) return null;
    const session = activeSession(req);
    if (!session?.user.company || !organizations.available) return session;
    const identity = auth.identity(session.user.id), organizationId = session.user.company.organizationId;
    const key = JSON.stringify([identity?.issuer, identity?.subject, organizationId]);
    let check = membershipChecks.get(key);
    if (fresh || !check || check.expires <= Date.now()) {
      if (!check?.pending) {
        for (const [entry, value] of membershipChecks) if (!value.pending && value.expires <= Date.now()) membershipChecks.delete(entry);
        if (membershipChecks.size >= 10000 && !membershipChecks.has(key)) throw unavailable();
        check = { expires: 0 };
        check.pending = organizations.member(identity, organizationId).then(member => { check.member = member; check.expires = Date.now() + 5000; return member; })
          .finally(() => { delete check.pending; });
        membershipChecks.set(key, check);
      }
    }
    const member = check.pending ? await check.pending : check.member;
    if (closing) return null;
    if (!member) { auth.revoke({ ...identity, organizationId }); return null; }
    // A concurrent administrator removal may have revoked the cookie while the API call was in flight.
    return activeSession(req);
  }

  function allowed(req, mutation = false) {
    // Universal Login and logout return by cross-site top-level navigation. The SPA SDK validates callback state.
    const entryNavigation = !mutation && req.method === 'GET' && (['/', '/login', '/login.html'].includes(req.path) || /^\/c\/[^/]+\/?(?:login)?$/.test(req.path))
      && req.headers['sec-fetch-mode'] === 'navigate' && req.headers['sec-fetch-dest'] === 'document';
    if (req.headers.host?.toLowerCase() !== origin.host || (req.headers['sec-fetch-site'] === 'cross-site' && !entryNavigation)) return false;
    if (req.headers.origin && req.headers.origin !== origin.origin) return false;
    return !mutation || req.headers.origin === origin.origin;
  }
  function limit(req, operation = 'signin', actorId) {
    const now = Date.now();
    for (const [key, bucket] of buckets) if (bucket.expires <= now) buckets.delete(key);
    // Sign-in keeps the socket-IP budget. Authenticated management actions have separate,
    // verified-profile budgets, so a shared reverse proxy does not combine these operations.
    const key = actorId ? `${operation}:profile:${actorId}` : `${operation}:ip:${req.socket.remoteAddress}`;
    const existing = buckets.get(key), bucket = existing || { count: 0, expires: now + 15 * 60_000 };
    if (bucket.count >= 100 || (!existing && buckets.size >= 10000) || (operation === 'signin' && authPending >= 4)) return false;
    bucket.count++; buckets.set(key, bucket);
    return true;
  }
  let sweepingTunnels = false;
  function closeTunnel(tunnel) { tunnel.socket.destroy(); tunnel.upstream?.destroy(); tunnels.delete(tunnel); }
  async function expireTunnels() {
    // Local revocation/demotion must close sockets immediately, even during a slow tenant lookup.
    for (const tunnel of tunnels) {
      let permitted = false;
      try { const session = activeSession(tunnel.req); permitted = !!session && access.access(session.user).permissions.review; }
      catch { /* A broken role store cannot leave an existing socket authorized. */ }
      if (!permitted) closeTunnel(tunnel);
    }
    if (sweepingTunnels) return;
    sweepingTunnels = true;
    try {
      await Promise.all([...tunnels].map(async tunnel => {
        let permitted = false;
        try { const session = await verifiedSession(tunnel.req); permitted = !!session && access.access(session.user).permissions.review; } catch {}
        if (!permitted) closeTunnel(tunnel);
      }));
    } finally { sweepingTunnels = false; }
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
      'X-Frame-Options': 'DENY', 'Content-Security-Policy': csp });
    if (closing) return res.status(503).json({ error: 'The Workbench is restarting. Try again shortly.' });
    if (secure) res.set('Strict-Transport-Security', 'max-age=31536000');
    if (!allowed(req, !['GET', 'HEAD', 'OPTIONS'].includes(req.method))) return res.status(403).json({ error: 'Use the configured same-origin web app' });
    next();
  });
  app.get('/healthz', (_req, res) => res.json({ status: 'ok' }));
  // Worker lifecycle probes are gateway-internal and are never forwarded from browser requests.
  app.use('/internal', (_req, res) => res.status(404).json({ error: 'Not found' }));
  app.get('/auth/config', (req, res) => {
    if (req.query.company === undefined) return res.json(configuration);
    const company = companies.get(req.query.company);
    if (!company) return res.status(404).json({ error: 'Company workspace not found' });
    res.json({ ...configuration, company });
  });
  app.get('/auth/session', async (req, res, next) => {
    try {
      const session = await verifiedSession(req);
      if (!session) return res.set('X-Threatlint-Auth', 'required').status(401).json({ error: 'Sign in to continue' });
      const current = access.access(session.user);
      res.json({ user: session.user, web: true, role: current.role, permissions: current.permissions });
    } catch (error) { next(error); }
  });
  app.use('/auth', express.json({ limit: '8kb' }));
  app.post('/auth/session', (req, res, next) => {
    if (!limit(req)) { res.set('Retry-After', '900'); return res.status(429).json({ error: 'Too many sign-in attempts. Try again later.' }); }
    authPending++;
    let counted = true;
    const releaseAttempt = () => { if (counted) { counted = false; authPending--; } };
    res.once('finish', releaseAttempt); res.once('close', releaseAttempt);
    next();
  }, auth0Router, requiresAuth({ scopes: 'openid' }), async (req, res, next) => {
    try {
      const claims = req.auth0.user;
      const authorizedClient = claims.azp ?? claims.client_id;
      if (claims.iss !== `${tenantOrigin}/` || authorizedClient !== configuration.clientId
          || (claims.azp && claims.client_id && claims.azp !== claims.client_id) || !permittedSubject(claims.sub)
          || claims.gty === 'client-credentials' || claims.act || !Number.isSafeInteger(claims.exp)) {
        return res.status(403).json({ error: 'Use Google, Apple, GitHub, or an approved enterprise SSO connection for Threatlint.' });
      }
      const identity = await auth0Client.getUserInfo({ accessToken: req.auth0.token, expectedSubject: claims.sub });
      if (closing) throw unavailable();
      if (identity.sub !== claims.sub) return res.status(401).json({ error: 'Auth0 identity could not be verified' });
      const requestedSlug = req.headers['x-threatlint-company'];
      const requestedCompany = requestedSlug === undefined ? null : companies.get(requestedSlug);
      const identityKey = { issuer: claims.iss, subject: claims.sub };
      // Discovery can import an existing pre-added organization only from the tenant's Management API.
      if (claims.org_id !== undefined && organizations.available && !await organizations.member(identityKey, claims.org_id)) {
        return res.status(403).json({ error: 'You are not a member of this organization.' });
      }
      const company = claims.org_id === undefined ? null : companies.forOrganization(claims.org_id);
      if ((requestedSlug !== undefined && (!requestedCompany || !company || requestedCompany.organizationId !== company.organizationId))
          || (claims.org_id !== undefined && !company)) {
        return res.status(403).json({ error: 'Sign in through this company’s Auth0 organization with an authorized membership.' });
      }
      if (closing) throw unavailable();
      const result = auth.establish({ issuer: claims.iss, subject: claims.sub, displayName: identity.name || identity.nickname,
        email: identity.email, expiresAt: claims.exp * 1000, ...(company ? { company } : {}) });
      const current = access.observe(result.user, { issuer: claims.iss, subject: claims.sub, roles: claims[ROLE_CLAIM] });
      // Only the verified issuer + subject determines ownership; email never links profiles.
      auth.logout(req); expireTunnels();
      res.set('Set-Cookie', sessionCookie(result, { secure })).json({ user: result.user, role: current.role, permissions: current.permissions });
    } catch (error) {
      if (error.code === 'userinfo_error' || error.name === 'UserInfoError') return res.status(401).json({ error: 'Auth0 identity could not be verified. Sign in again.' });
      next(error);
    }
  });
  app.post('/auth/logout', (req, res, next) => {
    try {
      const profile = req.headers['x-threatlint-profile'];
      if (profile !== undefined && activeSession(req)?.user.id !== profile) return res.status(409).json({ error: 'Your active profile changed. Reload this page.', code: 'profile_changed' });
      auth.logout(req); expireTunnels(); res.set('Set-Cookie', clearCookie({ secure })).json({ ok: true });
    }
    catch (error) { next(error); }
  });
  app.get('/auth/organizations', async (req, res, next) => {
    try {
      const session = await verifiedSession(req);
      if (!session) return res.set('X-Threatlint-Auth', 'required').status(401).json({ error: 'Sign in to continue' });
      if (req.headers['x-threatlint-profile'] !== undefined && req.headers['x-threatlint-profile'] !== session.user.id) return res.status(409).json({ error: 'Your active profile changed. Reload this page.', code: 'profile_changed' });
      if (!organizations.available) return res.status(503).json({ error: unavailable().message, managementAvailable: false, canCreate: false });
      const available = await organizations.memberships(auth.identity(session.user.id));
      res.json({ organizations: available, managementAvailable: true, canCreate: organizations.canCreate && available.length === 0 });
    } catch (error) { next(error); }
  });
  app.post('/auth/organizations', async (req, res, next) => {
    try {
      const session = await verifiedSession(req);
      if (!session) return res.set('X-Threatlint-Auth', 'required').status(401).json({ error: 'Sign in to continue' });
      if (req.headers['x-threatlint-profile'] !== undefined && req.headers['x-threatlint-profile'] !== session.user.id) return res.status(409).json({ error: 'Your active profile changed. Reload this page.', code: 'profile_changed' });
      if (!limit(req, 'organization-create', session.user.id)) return res.set('Retry-After', '900').status(429).json({ error: 'Too many organization requests. Try again later.' });
      const company = await organizations.create(auth.identity(session.user.id), req.body);
      membershipChecks.clear();
      res.status(201).json({ organization: company });
    } catch (error) { next(error); }
  });
  app.use('/auth', (_req, res) => res.status(404).json({ error: 'Unknown account route' }));
  app.get('/vendor/auth0-spa-js.js', (_req, res) => res.sendFile(path.join(__dirname, 'node_modules/@auth0/auth0-spa-js/dist/auth0-spa-js.production.js')));
  for (const [url, file] of Object.entries({ '/login': 'login.html', '/login.html': 'login.html', '/login.js': 'login.js', '/auth0-client.js': 'auth0-client.js', '/login.css': 'login.css', '/mark.svg': 'mark.svg' })) {
    app.get(url, (req, res) => {
      res.sendFile(path.join(PUBLIC, file));
    });
  }
  // Auth0's configured SPA callback is the root URL, including when replacing an existing login.
  app.get('/', (req, res, next) => {
    if (!activeSession(req) || (req.query.state && (req.query.code || req.query.error))) return res.sendFile(path.join(PUBLIC, 'login.html'));
    next();
  });
  app.get(['/c/:slug', '/c/:slug/', '/c/:slug/login'], (req, res, next) => {
    const company = companies.get(req.params.slug);
    if (!company) return res.status(404).send('Company workspace not found');
    const session = activeSession(req);
    if (session?.user.company?.organizationId !== company.organizationId) return res.sendFile(path.join(PUBLIC, 'login.html'));
    if (req.path.endsWith('/login')) return res.redirect(`/c/${company.slug}/`);
    req.workbenchPath = '/';
    next();
  });
  app.use(async (req, res, next) => {
    try {
    const session = await verifiedSession(req);
    if (!session) {
      if (req.path.toLowerCase().startsWith('/api/') || req.headers.accept?.includes('application/json')) return res.set('X-Threatlint-Auth', 'required').status(401).json({ error: 'Sign in to continue' });
      return res.redirect('/login');
    }
    if (req.path.toLowerCase().startsWith('/api/')) {
      const headerProfile = req.headers['x-threatlint-profile'];
      const linkProfile = req.query._profile;
      if ((headerProfile !== undefined && headerProfile !== session.user.id) || (linkProfile !== undefined && linkProfile !== session.user.id)) {
        return res.status(409).json({ error: 'Your active profile changed. Reload this page.' });
      }
      if (linkProfile !== undefined) {
        const target = new URL(req.originalUrl, origin);
        target.searchParams.delete('_profile');
        req.workbenchPath = target.pathname + target.search;
      }
      const current = access.access(session.user);
      const permission = requiredPermission(req.method, req.path);
      if (!current.permissions[permission]) return res.status(403).json({ error: `Your ${current.role} role cannot perform this action`, code: 'role_forbidden' });
      req.threatlintAccess = current;
    }
    req.threatlintSession = session;
    next();
    } catch (error) { next(error); }
  });
  async function memberAccess(actor) {
    const current = access.access(actor);
    if (!actor.company || !current.permissions.manageMembers) return current;
    if (!organizations.available) throw unavailable();
    const members = await organizations.management.listMembers(actor.company.organizationId);
    const actorIdentity = auth.identity(actor.id);
    if (!actorIdentity || !members.some(member => member.user_id === actorIdentity.subject)) {
      if (actorIdentity) auth.revoke({ ...actorIdentity, organizationId: actor.company.organizationId });
      await expireTunnels();
      throw Object.assign(new Error('Your company membership changed. Sign in again.'), { status: 401 });
    }
    return access.mergeMembers(actor, members, { issuer: `${tenantOrigin}/`, profileForIdentity: identity => auth.profile(identity) });
  }
  app.get('/api/access', async (req, res, next) => { try { res.json(await memberAccess(req.threatlintSession.user)); } catch (error) { next(error); } });
  app.get('/api/access/candidates', async (req, res, next) => {
    try {
      const actor = req.threatlintSession.user;
      if (!actor.company || !access.access(actor).permissions.manageMembers) return res.status(403).json({ error: 'Only company administrators can find existing users' });
      if (!organizations.available) throw unavailable();
      const email = req.query.email;
      if (Object.keys(req.query).some(key => key !== 'email') || typeof email !== 'string' || email.length > 254 || !/^[^\s@\x00-\x1f\x7f]+@[^\s@\x00-\x1f\x7f]+\.[^\s@\x00-\x1f\x7f]+$/.test(email)) return res.status(400).json({ error: 'Enter an exact email address' });
      if (!limit(req, 'member-search', actor.id)) return res.set('Retry-After', '900').status(429).json({ error: 'Too many member searches. Try again later.' });
      const values = await organizations.management.usersByEmail(email);
      if (!Array.isArray(values) || values.length > 100) throw unavailable();
      const users = values.filter(value => permittedSubject(value?.user_id) && typeof value.email === 'string' && value.email.toLowerCase() === email.toLowerCase())
        .map(value => ({ subject: value.user_id, email: value.email, displayName: String(value.name || value.nickname || value.user_id).replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, 80), provider: value.user_id.split('|')[0] }));
      res.json({ users });
    } catch (error) { next(error); }
  });
  app.post('/api/access/members', express.json({ limit: '8kb' }), async (req, res, next) => {
    try {
      const actor = req.threatlintSession.user;
      // Legacy observed-profile updates remain available when Management has not been configured.
      if (!organizations.available && req.body?.userId) { const current = access.update(actor, req.body); await expireTunnels(); return res.json(current); }
      if (!actor.company || !access.access(actor).permissions.manageMembers) return res.status(403).json({ error: 'Only company administrators can manage members' });
      if (!organizations.available) throw unavailable();
      await organizations.serialize(async () => {
        const current = await memberAccess(actor);
        if (req.body?.userId) access.update(actor, req.body);
        else {
          if (!req.body || Object.keys(req.body).some(key => !['subject', 'role'].includes(key)) || !permittedSubject(req.body.subject)) throw Object.assign(new Error('Choose an existing federated user ID and a valid role'), { status: 400 });
          const remote = await organizations.management.getUser(req.body.subject);
          if (!remote || remote.user_id !== req.body.subject) throw Object.assign(new Error('Existing user not found'), { status: 404 });
          // Validate the local assignment before the external membership change.
          if (!['administrator', 'analyst', 'viewer'].includes(req.body.role)) throw Object.assign(new Error('Choose a valid role'), { status: 400 });
          if (current.members.some(member => member.subject === req.body.subject)) access.updateIdentity(actor, { issuer: `${tenantOrigin}/`, subject: req.body.subject, role: req.body.role });
          else {
            access.assignIdentity(actor, { issuer: `${tenantOrigin}/`, subject: req.body.subject, role: req.body.role,
              displayName: String(remote.name || remote.nickname || remote.user_id).slice(0, 80), email: typeof remote.email === 'string' ? remote.email.slice(0, 254) : '' });
            // Persist the intended least-privilege assignment before membership can become effective.
            await organizations.management.addMember(actor.company.organizationId, req.body.subject);
          }
        }
        membershipChecks.clear(); await expireTunnels(); res.json(await memberAccess(actor));
      });
    }
    catch (error) { next(error); }
  });
  app.delete('/api/access/members/:subject', async (req, res, next) => {
    try {
      const actor = req.threatlintSession.user;
      if (!actor.company || !access.access(actor).permissions.manageMembers) return res.status(403).json({ error: 'Only company administrators can manage members' });
      if (!organizations.available) throw unavailable();
      if (!permittedSubject(req.params.subject)) return res.status(400).json({ error: 'Choose an existing federated user ID' });
      await organizations.serialize(async () => {
        const current = await memberAccess(actor), target = { issuer: `${tenantOrigin}/`, subject: req.params.subject };
        if (!current.members.some(member => member.subject === target.subject)) return res.status(404).json({ error: 'Company member not found' });
        access.assertRemovable(actor, target);
        // Revoke locally before making the network request; an ambiguous removal can never retain a live cookie.
        auth.revoke({ ...target, organizationId: actor.company.organizationId });
        access.removeIdentity(actor, target); await expireTunnels();
        await organizations.management.removeMember(actor.company.organizationId, target.subject);
        membershipChecks.clear();
        if (auth.identity(actor.id)?.subject === target.subject) return res.set('Set-Cookie', clearCookie({ secure })).json({ removed: true, signedOut: true });
        res.json(await memberAccess(actor));
      });
    } catch (error) { next(error); }
  });
  // Organization management routes share their own verified tenant scope, before personal-worker proxying.
  registerGatewayManagement(app, { scopeDirectory: req => access.scopeDirectory(req.threatlintSession.user),
    userForRequest: req => req.threatlintSession.user, workers, integrations: options.integrations || {} });
  app.use(async (req, res, next) => {
    const session = req.threatlintSession;
    let lease;
    try {
      lease = await workers.acquire(session.user);
      const { worker } = lease;
      if (req.aborted || res.destroyed) { lease.release(); return; }
      const currentSession = await verifiedSession(req);
      if (!currentSession) { lease.release(); return res.set('X-Threatlint-Auth', 'required').status(401).json({ error: 'Sign in to continue' }); }
      if (req.path.toLowerCase().startsWith('/api/') && !access.access(currentSession.user).permissions[requiredPermission(req.method, req.path)]) {
        lease.release(); return res.status(403).json({ error: 'Your role changed. Reload this page.', code: 'role_forbidden' });
      }
      const upstream = http.request({ hostname: '127.0.0.1', port: worker.port, method: req.method, path: req.workbenchPath || req.originalUrl,
        headers: workerHeaders(req, worker) }, response => {
        const headers = { ...response.headers, 'cache-control': 'no-store', 'content-security-policy': csp };
        delete headers['set-cookie'];
        res.writeHead(response.statusCode, headers); response.pipe(res);
      });
      const releaseLease = () => { upstream.destroy(); lease.release(); };
      upstream.on('error', () => { lease.release(); if (!res.headersSent) res.status(502).json({ error: 'Your Workbench is unavailable. Try again.' }); else res.destroy(); });
      req.once('aborted', releaseLease); res.once('close', releaseLease); res.once('finish', releaseLease);
      req.pipe(upstream);
    } catch (error) { lease?.release(); next(error); }
  });
  app.use((error, _req, res, _next) => {
    const status = Number.isInteger(error.status) && error.status >= 400 && error.status < 600 ? error.status : 500;
    if (Number.isInteger(error.retryAfter) && error.retryAfter > 0 && error.retryAfter <= 3600) res.set('Retry-After', String(error.retryAfter));
    const capacity = error.code === 'profile_capacity';
    const organizationFailure = ['organization_management_unavailable', 'organization_operation_unavailable'].includes(error.code);
    res.status(status).json({ error: capacity || organizationFailure ? error.message : status < 500 ? (status === 413 ? 'Account request is too large' : error.message) : 'Your Workbench could not start. Ask the administrator to check the profile runtime.',
      ...(capacity || organizationFailure ? { code: error.code } : {}) });
  });

  server.on('upgrade', async (req, socket, head) => {
    const reject = status => { if (!socket.destroyed) socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`); };
    if (!allowed(req) || req.headers.origin !== origin.origin) return reject('403 Forbidden');
    let session;
    try { session = await verifiedSession(req); } catch { return reject('503 Service Unavailable'); }
    if (!session) return reject('401 Unauthorized');
    try { if (!access.access(session.user).permissions.review) return reject('403 Forbidden'); }
    catch { return reject('403 Forbidden'); }
    let socketUrl;
    try { socketUrl = new URL(req.url, origin); } catch { return reject('400 Bad Request'); }
    if (socketUrl.pathname !== '/' || [...socketUrl.searchParams.keys()].some(key => key !== 'profile')) return reject('404 Not Found');
    if (socketUrl.searchParams.has('profile') && socketUrl.searchParams.get('profile') !== session.user.id) return reject('403 Forbidden');
    const tunnel = { req, socket, upstream: null, release: null };
    tunnels.add(tunnel); socket.once('close', () => { tunnel.upstream?.destroy(); tunnel.release?.(); tunnels.delete(tunnel); });
    try {
      const lease = await workers.acquire(session.user);
      tunnel.release = lease.release;
      const { worker } = lease;
      const currentSession = await verifiedSession(req);
      if (socket.destroyed || !currentSession) { lease.release(); return reject('401 Unauthorized'); }
      if (!access.access(currentSession.user).permissions.review) { lease.release(); return reject('403 Forbidden'); }
      const request = http.request({ hostname: '127.0.0.1', port: worker.port, path: '/', headers: workerHeaders(req, worker) });
      request.on('upgrade', (response, upstream, upstreamHead) => {
        tunnel.upstream = upstream;
        if (socket.destroyed) { lease.release(); return upstream.destroy(); }
        const headers = Object.entries(response.headers).flatMap(([key, value]) => (Array.isArray(value) ? value : [value]).map(item => `${key}: ${item}`));
        socket.write(`HTTP/1.1 101 Switching Protocols\r\n${headers.join('\r\n')}\r\n\r\n`);
        if (upstreamHead.length) socket.write(upstreamHead);
        if (head.length) upstream.write(head);
        upstream.on('error', () => socket.destroy()); socket.on('error', () => upstream.destroy());
        upstream.once('close', () => socket.destroy());
        socket.pipe(upstream); upstream.pipe(socket);
      });
      request.on('response', response => { response.resume(); lease.release(); reject('502 Bad Gateway'); });
      request.on('error', () => { lease.release(); reject('502 Bad Gateway'); }); request.end();
    } catch { tunnel.release?.(); reject('503 Service Unavailable'); }
  });

  let closePromise;
  function close() {
    if (closePromise) return closePromise;
    closing = true;
    authShutdown.abort();
    clearInterval(sweep);
    for (const tunnel of tunnels) { tunnel.socket.destroy(); tunnel.upstream?.destroy(); }
    closePromise = (async () => {
      try {
        await organizations.close();
        await workers.close();
        if (server.listening) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
      } finally { release(); }
    })();
    return closePromise;
  }
  return { app, server, auth, workers, access, organizations, close, origin: origin.origin };
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
