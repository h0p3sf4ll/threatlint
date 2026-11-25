'use strict';

/** Organization-scoped connection and ticket registry. Secrets never enter public records. */
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { HttpError } = require('./http.cjs');
const { validateConnection, PROVIDERS, text } = require('./issue-trackers.cjs');

const MAX_CONNECTIONS = 100, MAX_FINDINGS = 10000;
function publicConnection(connection) {
  const provider = PROVIDERS.find(item => item.id === connection.provider);
  return { id: connection.id, name: connection.name, kind: connection.kind, provider: connection.provider,
    enabled: connection.enabled !== false, isDefault: connection.isDefault === true, hasToken: !!connection.token,
    updatedAt: connection.updatedAt, ...(provider?.credentialSource ? { credentialSource: provider.credentialSource, pullOnly: true, instance: connection.instance } : {}),
    ...Object.fromEntries((provider?.fields || []).map(field => [field.name, connection[field.name] || ''])) };
}
function reviewReference(connection, externalId) {
  if (connection.provider === 'servicenow-avit') return `${connection.instance}#${externalId}`;
  if (connection.provider === 'jira') return `${connection.baseUrl}/browse/${externalId}`;
  if (connection.provider === 'github-issues') return `${connection.repository}#${externalId}`;
  return `${connection.organization}/${connection.project}#${externalId}`;
}
function publicFinding(finding) {
  const { body, revision, closed, closureAcknowledgement, ...safe } = finding;
  return { ...safe };
}
function createManagementStore(directory = null) {
  const file = directory ? path.join(directory, 'integration-management.json') : null;
  let key = null;
  let state = { version: 1, connections: [], findings: [], operations: [], audit: [] };
  if (file) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const keyFile = path.join(directory, 'integration-management.key');
    if (!fs.existsSync(keyFile)) {
      if (fs.existsSync(file)) throw new Error('The integration encryption key is unavailable; existing data was preserved');
      try { fs.writeFileSync(keyFile, crypto.randomBytes(32), { mode: 0o600, flag: 'wx' }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    }
    key = fs.readFileSync(keyFile);
    if (key.length !== 32) throw new Error('The integration encryption key is invalid');
    if (fs.existsSync(file)) {
      try {
        const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
        if (![1, 2].includes(saved.version) || !Array.isArray(saved.connections) || !Array.isArray(saved.findings) || !Array.isArray(saved.operations) || !Array.isArray(saved.audit) || saved.connections.length > MAX_CONNECTIONS || saved.findings.length > MAX_FINDINGS || saved.operations.length > MAX_FINDINGS || saved.audit.length > 2000) throw new Error('Invalid registry');
        state = { ...state, ...saved, connections: saved.connections.map(connection => {
          if (connection.provider === 'servicenow-avit') {
            if (saved.version !== 2 || connection.credentialSource !== 'servicenow-settings' || Object.hasOwn(connection, 'encryptedToken') || Object.hasOwn(connection, 'token') ||
                require('./servicenow.cjs').validateInstanceUrl(connection.instance) !== connection.instance || connection.id !== serviceNowId(connection.instance)) throw new Error('Invalid ServiceNow descriptor');
            return { ...connection };
          }
          return { ...connection, token: decrypt(connection.encryptedToken) };
        }) };
      } catch { throw new Error('Integration settings could not be read; existing data was preserved'); }
    }
  }
  function encrypt(token) {
    const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64');
  }
  function decrypt(value) {
    const bytes = Buffer.from(value, 'base64');
    if (bytes.length < 29) throw new Error('Invalid encrypted token');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
    decipher.setAuthTag(bytes.subarray(12, 28));
    return Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString('utf8');
  }
  function save() {
    if (!file) return;
    const connections = state.connections.map(connection => { const { token, encryptedToken, ...safe } = connection; return connection.provider === 'servicenow-avit' ? safe : { ...safe, encryptedToken: encrypt(token) }; });
    const temporary = `${file}.${crypto.randomUUID()}.tmp`;
    try { fs.writeFileSync(temporary, JSON.stringify({ ...state, connections }, null, 2), { mode: 0o600 }); fs.renameSync(temporary, file); }
    finally { try { fs.unlinkSync(temporary); } catch (error) { if (error.code !== 'ENOENT') throw error; } }
  }
  function connection(id, { enabled = true, kind } = {}) {
    const value = typeof id === 'string' && state.connections.find(item => item.id === id);
    if (!value) throw new HttpError('Connection not found', 404);
    if (kind && value.kind !== kind) throw new HttpError(`Choose a ${kind} connection`);
    if (enabled && value.enabled === false) throw new HttpError('Enable this connection in Settings before using it', 409);
    return value;
  }
  function upsert(raw) {
    const previous = raw?.id ? connection(raw.id, { enabled: false }) : null;
    if (!previous && state.connections.length >= MAX_CONNECTIONS) throw new HttpError('At most 100 saved connections are supported', 409);
    const candidate = validateConnection(raw, previous);
    if (previous && (state.findings.some(item => item.connectionId === previous.id) || state.operations.some(item => item.connectionId === previous.id))) {
      for (const field of ['baseUrl', 'project', 'repository', 'organization']) {
        if ((candidate[field] || '') !== (previous[field] || '')) throw new HttpError('This connection has ticket history. Add a new named connection to change its destination.', 409);
      }
    }
    const value = { ...candidate, id: previous?.id || crypto.randomUUID(), updatedAt: Date.now() };
    if (!value.enabled) value.isDefault = false;
    if (value.isDefault) for (const item of state.connections) if (item.kind === value.kind) item.isDefault = false;
    if (previous) state.connections[state.connections.indexOf(previous)] = value;
    else state.connections.push(value);
    return value;
  }
  function serviceNowId(instance) { return 'servicenow-avit-' + crypto.createHash('sha256').update(instance).digest('hex'); }
  function serviceNowConnection(instance, { create = true } = {}) {
    const normalized = require('./servicenow.cjs').validateInstanceUrl(instance), id = serviceNowId(normalized);
    const previous = state.connections.find(item => item.id === id);
    if (previous) {
      if (previous.enabled === false) throw new HttpError('This ServiceNow issue source is disabled', 409);
      return previous;
    }
    if (create && state.connections.length >= MAX_CONNECTIONS) throw new HttpError('At most 100 saved connections are supported', 409);
    const value = { id, name: 'ServiceNow AVIT — ' + new URL(normalized).hostname, provider: 'servicenow-avit', kind: 'tracker',
      credentialSource: 'servicenow-settings', instance: normalized, enabled: true, isDefault: false, updatedAt: Date.now() };
    if (create) { state.version = 2; state.connections.push(value); }
    return value;
  }
  function remove(id) {
    const value = connection(id, { enabled: false });
    if (state.findings.some(item => item.connectionId === id) || state.operations.some(item => item.connectionId === id)) throw new HttpError('This connection has tracked findings or ticket operations. Disable it to preserve ticket history.', 409);
    state.connections = state.connections.filter(item => item !== value);
  }
  function audit(actor, action, target, outcome = 'success') {
    state.audit.push({ id: crypto.randomUUID(), timestamp: Date.now(), actor: text(actor || 'local', 200), action, target: text(target, 300), outcome });
    state.audit = state.audit.slice(-2000);
  }
  function putFinding(connection, issue, extra = {}) {
    const previous = state.findings.find(item => item.connectionId === connection.id && item.externalId === issue.externalId);
    if (!previous && state.findings.length >= MAX_FINDINGS) throw new HttpError('The finding registry supports at most 10,000 tickets', 409);
    const disposition = issue.closed ? previous?.disposition === 'FALSE POSITIVE' ? 'FALSE POSITIVE' : 'RESOLVED' : 'OPEN';
    const value = { ...previous, id: previous?.id || crypto.randomUUID(), connectionId: connection.id, provider: connection.provider,
      externalId: issue.externalId, title: issue.title, state: issue.state, url: issue.url, severity: issue.severity || 'UNSPECIFIED',
      disposition, generated: previous?.generated === true, reviewReference: reviewReference(connection, issue.externalId), issueType: issue.issueType || previous?.issueType || '',
      closureAcknowledgement: issue.closed ? previous?.closureAcknowledgement : undefined, updatedAt: Date.now(), ...extra };
    if (previous) state.findings[state.findings.indexOf(previous)] = value; else state.findings.push(value);
    return value;
  }
  let pending = Promise.resolve();
  function mutate(work) { const operation = pending.then(work); pending = operation.catch(() => {}); return operation; }
  function transaction(work) {
    const previous = structuredClone(state);
    try { const result = work(); save(); return result; }
    catch (error) { state = previous; throw error; }
  }
  const cursorKey = key || crypto.randomBytes(32);
  function cursorScope(connection, filters) {
    return crypto.createHash('sha256').update(JSON.stringify([connection.id, connection.provider, connection.instance, connection.baseUrl,
      connection.organization, connection.project, connection.repository, connection.issueType, connection.closeState, filters])).digest('hex');
  }
  function pullCursor(connection, filters, position) {
    if (position === null || position === undefined) return null;
    const payload = Buffer.from(JSON.stringify({ version: 1, scope: cursorScope(connection, filters), position })).toString('base64url');
    const signature = crypto.createHmac('sha256', cursorKey).update('issue-pull-v1:' + payload).digest('base64url');
    return payload + '.' + signature;
  }
  function readPullCursor(connection, filters, cursor) {
    if (cursor === undefined || cursor === null) return null;
    if (typeof cursor !== 'string' || cursor.length > 4096 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(cursor)) throw new HttpError('Invalid issue pull cursor; start this source again');
    const [payload, signature] = cursor.split('.'), expected = crypto.createHmac('sha256', cursorKey).update('issue-pull-v1:' + payload).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) throw new HttpError('Invalid issue pull cursor; start this source again');
    let value; try { value = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); } catch { throw new HttpError('Invalid issue pull cursor'); }
    if (value.version !== 1 || value.scope !== cursorScope(connection, filters)) throw new HttpError('Issue pull filters or source changed; start this source again');
    return value.position;
  }
  return { get state() { return state; }, save, transaction, mutate, connection, upsert, remove, audit, putFinding,
    serviceNowConnection, pullCursor, readPullCursor,
    listConnections: () => state.connections.map(publicConnection), listFindings: () => state.findings.map(publicFinding) };
}

module.exports = { createManagementStore, publicConnection, publicFinding, reviewReference, MAX_CONNECTIONS, MAX_FINDINGS };
