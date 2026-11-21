'use strict';

/** Source-backed scans reuse the Python sandbox, while live URL scans keep their existing transport. */
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');
const { python, pythonPath } = require('./avit-batch.cjs');
const { validateConfig, analyzeResponse, markdownExport, htmlExport } = require('./runtime.cjs');
const { redactText } = require('./scan-import.cjs');
const { HttpError } = require('./http.cjs');

const AUTH = new Set(['none', 'basic', 'bearer', 'cookie', 'api-key', 'headers']);
function createSandboxRuntime({ live, store, resolveSource, spawnImpl = spawn }) {
  const scans = new Map(), children = new Map();
  let starting = 0;
  const publicScan = scan => structuredClone(scan);
  const event = (scan, message) => scan.events.push({ at: Date.now(), message });
  function finish(scan, result, scope) {
    const secrets = [scope.auth, ...scope.roles.map(role => role.auth)].flatMap(auth => Object.entries(auth).flatMap(([key, value]) =>
      key === 'headers' ? Object.values(value) : ['token', 'password', 'cookie', 'value'].includes(key) ? [value] : [])).filter(value => typeof value === 'string' && value);
    let serialized = JSON.stringify(result);
    for (const value of secrets.sort((a, b) => b.length - a.length)) serialized = serialized.split(JSON.stringify(value).slice(1, -1)).join('<redacted credential>');
    result = JSON.parse(serialized);
    scan.coverage.cleanup = result.cleanup; scan.coverage.isolation = result.isolation; scan.coverage.tests = result.tests;
    const observed = new Map();
    const findingFor = finding => scan.findings.push({ ...finding, id: `RT-${String(scan.findings.length + 1).padStart(3, '0')}` });
    for (const [index, response] of (result.responses || []).entries()) {
      const identity = result.identities[response.id] || {};
      const headers = Object.fromEntries((response.headers || []).map(([key, value]) => [key.toLowerCase(), redactText(value)]));
      const record = { id: `request-${index}`, ...identity, method: 'GET', statusCode: response.status || null, elapsedMs: response.elapsed_ms, error: response.error ? 'Sandbox request failed' : null };
      // Bodies and auth headers never enter the public snapshot. Findings contain bounded, redacted observations.
      scan.requests.push(record);
      observed.set(`${identity.identity}|${identity.path}`, { status: response.status, body: response.body || '' });
      scan.nodes.push({ id: record.id, kind: 'response', label: `${identity.path} · ${response.status || 'failed'}`, status: response.status ? 'observed' : 'failed', evidence: record });
      if (response.status) for (const finding of analyzeResponse(record, { headers, body: redactText(response.body || '') }, scope)) {
        findingFor(finding);
      }
    }
    for (const item of scope.assertions) {
      const anon = observed.get(`anonymous|${item.path}`);
      if (anon && !item.expected.includes(anon.status)) findingFor({ rule: 'RT-AUTHZ-ASSERT', severity: anon.status < 300 ? 'HIGH' : 'MEDIUM',
        title: `Access-control assertion failed for ${item.path}`, cwe: 'CWE-862', path: item.path, identity: 'anonymous',
        description: `Anonymous response ${anon.status}; expected ${item.expected.join(' or ')}.`,
        fix: 'Check the intended access policy and enforce it server-side.', evidence: { expected: item.expected, observed: anon.status } });
    }
    for (const requestPath of scope.paths) {
      const main = observed.get(`primary|${requestPath}`), anon = observed.get(`anonymous|${requestPath}`);
      if (!main || main.status >= 300 || !main.body) continue;
      const sensitive = /api|admin|account|user|private|profile|order|billing|settings/i.test(requestPath) && !/health|status|ping|version|public/i.test(requestPath);
      if (anon && anon.status < 300 && anon.body === main.body && sensitive && !scope.assertions.some(item => item.path === requestPath)) {
        findingFor({ rule: 'RT-AUTHZ-ANON-EQUAL', severity: 'MEDIUM', title: `${requestPath} returns identical content with and without credentials`, path: requestPath, identity: 'anonymous', cwe: 'CWE-306',
          description: 'The sandbox returned the same nonempty body to both identities. Confirm whether this route is intended to be public.', fix: 'Verify the route access policy and enforce authentication on protected routes.', evidence: { authenticated: main.status, anonymous: anon.status } });
      }
      for (const role of scope.roles) {
        const other = observed.get(`${role.label}|${requestPath}`);
        if ((!anon || [401, 403].includes(anon.status)) && other?.status < 300 && other.body === main.body) findingFor({ rule: 'RT-AUTHZ-ROLE-EQUAL', severity: /admin/i.test(requestPath) ? 'HIGH' : 'MEDIUM',
          title: `${role.label} receives the primary identity's ${requestPath} content`, path: requestPath, identity: role.label, cwe: 'CWE-639',
          description: 'Both identities received identical content. Validate the intended role boundary before declaring an authorization bypass.', fix: 'Enforce the intended role and object permissions on the server.', evidence: { primary: main.status, role: other.status } });
      }
    }
    if (scan.status !== 'cancelling') scan.status = 'complete';
  }
  return {
    get active() { return starting > 0 || children.size > 0 || live.active === true; },
    async start(config) {
      if (!config?.source?.workspaceId && !config?.source?.url) return live.start(config);
      if (config.source.confirmBuild !== true) throw new HttpError('Authorize building the supplied source in an ephemeral environment');
      if (scans.size >= 25) {
        const old = [...scans].find(([, scan]) => scan.status !== 'running');
        if (old) scans.delete(old[0]); else throw new HttpError('Sandbox history is full of active scans', 429);
      }
      if (children.size + starting >= 2) throw new HttpError('Two source-backed runtime scans are already running', 429);
      const scope = validateConfig({ ...config, target: 'http://127.0.0.1', authorization: { ...config.authorization, allowPrivate: true } });
      if (scope.limits.maxRequests > 40) throw new HttpError('The isolated environment supports at most 40 requests');
      if ([scope.auth, ...scope.roles.map(role => role.auth)].some(auth => !AUTH.has(auth.type))) throw new HttpError('For isolated scans, use sandbox test credentials: bearer, basic, cookie, API key, or custom headers');
      if ([scope.auth, ...scope.roles.map(role => role.auth)].some(auth => auth.type === 'api-key' && auth.location !== 'header')) throw new HttpError('Isolated scans support API keys in headers; query placement is unavailable');
      if (scope.roles.some(role => /^(primary|anonymous)$/i.test(role.label)) || new Set(scope.roles.map(role => role.label)).size !== scope.roles.length) throw new HttpError('Use distinct role names other than primary or anonymous');
      if (scope.assertions.length && scope.auth.type !== 'none' && !scope.compareAnonymous) throw new HttpError('Enable anonymous comparison to evaluate the access-control assertions');
      if (scope.auth.type === 'none' && config.source.anonymousConfirmed !== true) throw new HttpError('Provide sandbox test credentials, or explicitly choose an anonymous-only scan');
      const identities = 1 + scope.roles.length + Number(scope.compareAnonymous);
      if (scope.paths.length * identities > scope.limits.maxRequests) throw new HttpError('Paths and roles exceed the shared sandbox request budget');
      if (config.source.workspaceId && config.source.url) throw new HttpError('Choose a workspace or a source URL');
      starting++;
      try {
      let workspace;
      if (config.source.workspaceId) {
        const session = store.sessions.get(config.source.workspaceId);
        if (!session || !fs.existsSync(session.repoPath)) throw new HttpError('Source workspace not found', 404);
        workspace = { id: session.id, repoPath: session.repoPath };
      } else workspace = await resolveSource(config.source.url, config.source.branch || '');
      const scan = { id: crypto.randomUUID(), status: 'running', target: 'http://sandbox.internal', startedAt: Date.now(), finishedAt: null, requests: [], findings: [], nodes: [], edges: [], events: [],
        coverage: { authorization: scope.reason, authType: scope.auth.type, maxRequests: scope.limits.maxRequests, sourceWorkspaceId: workspace.id, environment: 'ephemeral Docker sandbox' } };
      const child = spawnImpl(python(), ['-m', 'threatlint.runtime_workbench'], { windowsHide: true,
        env: { ...process.env, PYTHONPATH: [pythonPath(), process.env.PYTHONPATH].filter(Boolean).join(path.delimiter), PYTHONIOENCODING: 'utf-8' } });
      scans.set(scan.id, scan); children.set(scan.id, child);
      let pending = '', failure = false, received = false;
      const timer = setTimeout(() => child.kill('SIGTERM'), 30 * 60000);
      child.stdout.on('data', chunk => {
        pending += chunk;
        if (pending.length > 20 * 1024 * 1024) { failure = true; child.kill('SIGTERM'); return; }
        const lines = pending.split('\n'); pending = lines.pop();
        for (const line of lines) {
          try {
            const data = JSON.parse(line);
            if (data.stage) event(scan, redactText(data.stage).slice(0, 200));
            if (data.error) { failure = true; event(scan, data.error); }
            if (data.result) { finish(scan, data.result, scope); received = true; }
          } catch { failure = true; }
        }
      });
      // Build stderr can contain credentials or repository scripts; never return it as evidence.
      child.stderr.on('data', () => {});
      child.on('error', () => { failure = true; scan.status = 'failed'; event(scan, 'Python runtime bridge could not start'); });
      child.on('close', code => {
        clearTimeout(timer); children.delete(scan.id); scan.finishedAt = Date.now();
        scan.status = scan.status === 'cancelling' ? 'cancelled' : code !== 0 || failure || !received ? 'failed' : 'complete';
        if (!received) { scan.coverage.cleanup = 'unverified'; event(scan, 'Scan incomplete. Verify Docker build/start configuration and labelled resource cleanup.'); }
      });
      child.stdin.end(JSON.stringify({ repoPath: workspace.repoPath, paths: scope.paths, auth: scope.auth, roles: scope.roles, checks: { compareAnonymous: scope.compareAnonymous }, limits: scope.limits }));
      return { id: scan.id };
      } finally { starting--; }
    },
    get(id) { return scans.has(id) ? publicScan(scans.get(id)) : live.get(id); },
    cancel(id) { const child = children.get(id); if (!scans.has(id)) return live.cancel(id); if (child) { scans.get(id).status = 'cancelling'; child.kill('SIGTERM'); } return true; },
    exportScan(id, format) {
      if (!scans.has(id)) return live.exportScan(id, format);
      const scan = publicScan(scans.get(id));
      return format === 'json' ? { contentType: 'application/json', body: JSON.stringify(scan, null, 2) }
        : format === 'md' ? { contentType: 'text/markdown', body: markdownExport(scan) } : { contentType: 'text/html', body: htmlExport(scan) };
    },
    startBrowser: config => live.startBrowser(config), finishBrowser: id => live.finishBrowser(id),
    async close() {
      const stopped = [...children.values()].map(child => new Promise(resolve => { child.once('close', resolve); child.kill('SIGTERM'); }));
      await Promise.all([live.close?.(), ...stopped]);
    },
  };
}
module.exports = { createSandboxRuntime };
