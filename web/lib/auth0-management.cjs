'use strict';

const { permittedSubject } = require('./auth0-config.cjs');
const ORGANIZATION = /^org_[A-Za-z0-9]{1,128}$/;
const CONNECTION = /^con_[A-Za-z0-9]{1,128}$/;
const SCOPES = ['read:organizations', 'create:organizations', 'read:organization_members',
  'create:organization_members', 'delete:organization_members', 'read:organization_connections',
  'create:organization_connections', 'read:users'];
function unavailable() { return Object.assign(new Error('Organization management is unavailable. Ask the administrator to check Auth0 configuration.'), { status: 503, code: 'organization_management_unavailable' }); }
function identifier(value, expression) { if (typeof value !== 'string' || !expression.test(value)) throw Object.assign(new Error('Invalid organization identifier'), { status: 400 }); return encodeURIComponent(value); }

/** Server-only tenant Management API transport. Neither its credentials nor access tokens reach a profile worker. */
function createAuth0Management({ domain, clientId = process.env.AUTH0_MANAGEMENT_CLIENT_ID,
  clientSecret = process.env.AUTH0_MANAGEMENT_CLIENT_SECRET,
  connectionIds = process.env.AUTH0_ORGANIZATION_CONNECTION_IDS || '', transport = fetch, now = Date.now, signal } = {}) {
  if (typeof domain !== 'string' || !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/i.test(domain)) throw new Error('Invalid Auth0 Management domain');
  if (!clientId && !clientSecret) return null;
  if (typeof clientId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(clientId) || typeof clientSecret !== 'string' || !clientSecret || clientSecret.length > 4096 || /[\x00-\x1f\x7f]/.test(clientSecret)) throw new Error('Configure both Auth0 Management client credentials');
  const connections = Array.isArray(connectionIds) ? [...connectionIds] : typeof connectionIds === 'string' ? connectionIds.split(',').map(value => value.trim()).filter(Boolean) : [];
  if (connections.length > 10 || connections.some(value => !CONNECTION.test(value)) || new Set(connections).size !== connections.length) throw new Error('AUTH0_ORGANIZATION_CONNECTION_IDS must contain unique approved Auth0 connection IDs');
  const origin = `https://${domain.toLowerCase()}`, audience = `${origin}/api/v2/`;
  let token, expires = 0, pending, inFlight = 0;
  async function decode(response) {
    if (!response.body) return null;
    const reader = response.body.getReader(); let bytes = 0; const chunks = [];
    try { for (;;) { const part = await reader.read(); if (part.done) break; bytes += part.value.length; if (bytes > 2 * 1024 * 1024) { await reader.cancel(); throw unavailable(); } chunks.push(Buffer.from(part.value)); } }
    finally { reader.releaseLock(); }
    const text = Buffer.concat(chunks).toString('utf8');
    if (!text) return null;
    try { return JSON.parse(text); } catch { throw unavailable(); }
  }
  async function send(url, init, timeoutMs = 10_000) {
    if (inFlight >= 16) throw Object.assign(unavailable(), { retryAfter: 30 });
    inFlight++;
    try { const response = await transport(url, { ...init, redirect: 'error', signal: AbortSignal.any([AbortSignal.timeout(timeoutMs), ...(signal ? [signal] : [])]) }); const data = await decode(response); if (signal?.aborted) throw unavailable(); return { response, data }; }
    catch { throw unavailable(); }
    finally { inFlight--; }
  }
  async function accessToken() {
    if (token && expires > now() + 30_000) return token;
    if (!pending) pending = (async () => {
      const { response, data } = await send(`${origin}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret, audience, scope: SCOPES.join(' ') }) });
      if (!response.ok || typeof data?.access_token !== 'string' || !data.access_token || data.access_token.length > 32768 || !Number.isFinite(data.expires_in) || data.expires_in < 60) throw unavailable();
      token = data.access_token; expires = now() + Math.min(data.expires_in, 86400) * 1000; return token;
    })().finally(() => { pending = null; });
    return pending;
  }
  async function request(method, endpoint, body, { missing = false, conflict = false, timeoutMs = 10_000 } = {}) {
    const bearer = await accessToken();
    const { response, data } = await send(`${audience}${endpoint}`, { method, headers: { Authorization: `Bearer ${bearer}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }, timeoutMs);
    if (response.status === 401) { token = undefined; expires = 0; }
    if (missing && response.status === 404) return null;
    if (conflict && response.status === 409) return null;
    if (!response.ok) throw unavailable();
    return data;
  }
  async function pages(endpoint, key, checkpoint = false) {
    const result = [], cursors = new Set(), deadline = Date.now() + 30_000; let previous, cursor;
    for (let page = 0; page < 100; page++) {
      const remaining = deadline - Date.now(); if (remaining <= 0) throw unavailable();
      const query = checkpoint ? `take=100${cursor ? `&from=${encodeURIComponent(cursor)}` : ''}` : `page=${page}&per_page=100&include_totals=true`;
      const data = await request('GET', `${endpoint}?${query}`, undefined, { timeoutMs: Math.min(10_000, remaining) });
      const values = Array.isArray(data) ? data : data?.[key];
      if (!Array.isArray(values) || values.length > 100 || !values.every(value => value && typeof value === 'object' && !Array.isArray(value))) throw unavailable();
      const fingerprint = JSON.stringify(values);
      if (values.length && fingerprint === previous) throw unavailable();
      result.push(...values); previous = fingerprint;
      if (result.length > 10000) throw unavailable();
      if (checkpoint) {
        if (!data.next) return result;
        if (typeof data.next !== 'string' || data.next.length > 2048 || /[\x00-\x1f\x7f]/.test(data.next) || cursors.has(data.next)) throw unavailable();
        cursor = data.next; cursors.add(cursor); continue;
      }
      if (data?.total !== undefined && (!Number.isSafeInteger(data.total) || data.total < 0 || data.total > 10000)) throw unavailable();
      if (typeof data?.total === 'number' && result.length >= data.total) return result;
      if (values.length < 100) return result;
    }
    throw unavailable();
  }
  const subject = value => { if (!permittedSubject(value)) throw Object.assign(new Error('Choose an existing federated user ID'), { status: 400 }); return encodeURIComponent(value); };
  return Object.freeze({ connections: Object.freeze(connections),
    listUserOrganizations: user => pages(`users/${subject(user)}/organizations`, 'organizations', true),
    listMembers: org => pages(`organizations/${identifier(org, ORGANIZATION)}/members`, 'members', true),
    getUser: user => request('GET', `users/${subject(user)}`, undefined, { missing: true }),
    usersByEmail: email => request('GET', `users-by-email?email=${encodeURIComponent(email)}`),
    getOrganizationByName: name => request('GET', `organizations/name/${encodeURIComponent(name)}`, undefined, { missing: true }),
    createOrganization: body => request('POST', 'organizations', body, { conflict: true }),
    listConnections: org => pages(`organizations/${identifier(org, ORGANIZATION)}/enabled_connections`, 'enabled_connections'),
    enableConnection: (org, connection) => request('POST', `organizations/${identifier(org, ORGANIZATION)}/enabled_connections`, { connection_id: connection, assign_membership_on_login: false }),
    addMember: (org, user) => request('POST', `organizations/${identifier(org, ORGANIZATION)}/members`, { members: [decodeURIComponent(subject(user))] }),
    removeMember: (org, user) => request('DELETE', `organizations/${identifier(org, ORGANIZATION)}/members`, { members: [decodeURIComponent(subject(user))] }),
  });
}
module.exports = { createAuth0Management, unavailable, SCOPES };
