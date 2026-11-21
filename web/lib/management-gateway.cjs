'use strict';

const http = require('node:http');
const express = require('express');
const { HttpError } = require('./http.cjs');
const { registerManagementRoutes } = require('./routes/management.cjs');

/** A bounded private call into the current user's isolated worker. The organization registry
 * stays at the gateway; source credentials enter only the requesting member's runtime. */
async function workerCall(workers, user, pathname, body) {
  const lease = await workers.acquire(user);
  try {
    const { worker } = lease;
    return await new Promise((resolve, reject) => {
      const payload = body === undefined ? null : JSON.stringify(body);
      let settled = false;
      const finish = (error, value) => { if (settled) return; settled = true; error ? reject(error) : resolve(value); };
      const request = http.request({ hostname: '127.0.0.1', port: worker.port, path: pathname,
        method: payload ? 'POST' : 'GET', headers: { Host: `127.0.0.1:${worker.workerPort}`,
          'x-threatlint-worker': worker.token, ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}) } }, response => {
        let size = 0; const chunks = [];
        response.on('data', chunk => {
          size += chunk.length;
          if (size > 10 * 1024 * 1024) { finish(new HttpError('The profile response is too large', 502)); request.destroy(); return; }
          chunks.push(chunk);
        });
        response.on('error', () => finish(new HttpError('Your profile could not be reached', 502)));
        response.on('end', () => {
          if (response.statusCode === 404) return finish(new HttpError('Report not found in your profile', 404));
          if (response.statusCode < 200 || response.statusCode >= 300) return finish(new HttpError('Your profile could not complete this action', 502));
          try { finish(null, JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
          catch { finish(new HttpError('Your profile returned an invalid response', 502)); }
        });
      });
      request.setTimeout(30_000, () => { finish(new HttpError('Your profile did not respond in time', 504)); request.destroy(); });
      request.on('error', () => finish(new HttpError('Your profile could not be reached', 502)));
      request.end(payload);
    });
  } finally { lease.release(); }
}

function registerGatewayManagement(app, { scopeDirectory, userForRequest, workers, integrations = {} }) {
  // This router is mounted after session, organization and role checks and before the worker proxy.
  app.use('/api/management', express.json({ limit: '128kb' }));
  return registerManagementRoutes(app, { scopeDirectory, integrations,
    actor: req => userForRequest(req).id,
    resolveReport: (req, id) => {
      if (typeof id !== 'string' || !/^[a-f0-9-]{36}$/i.test(id)) throw new HttpError('Report not found', 404);
      return workerCall(workers, userForRequest(req), `/internal/management/report/${encodeURIComponent(id)}`);
    },
    activateSource: (req, connection) => workerCall(workers, userForRequest(req), '/internal/management/source',
      { provider: connection.provider, token: connection.token, organization: connection.organization || undefined }),
  });
}

module.exports = { registerGatewayManagement, workerCall };
