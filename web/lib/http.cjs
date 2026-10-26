'use strict';

/** HTTP plumbing shared by every route module: loopback guard, headers, and error mapping. */

const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; media-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/** Same-origin loopback only: the runner is a single-user local service, not a web server. */
function localRequest(req, server) {
  const port = server.address()?.port;
  let host;
  try { host = new URL(`http://${req.headers.host}`); } catch { return false; }
  if (!LOOPBACK_HOSTS.has(host.hostname)) return false;
  if (port && host.port !== String(port)) return false;
  if (req.headers['sec-fetch-site'] === 'cross-site') return false;
  if (req.headers.origin) {
    try { if (new URL(req.headers.origin).host !== host.host) return false; } catch { return false; }
  }
  return true;
}

function securityHeaders(server) {
  return (req, res, next) => {
    if (!localRequest(req, server)) return res.status(403).json({ error: 'Only same-origin loopback requests are accepted' });
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', CSP);
    // UI assets revalidate on every load so a rebuilt app never renders yesterday's scripts.
    res.setHeader('Cache-Control', req.path.startsWith('/api/') ? 'no-store' : 'no-cache');
    return next();
  };
}

function sendError(res, error, fallback = 'Request could not be processed') {
  const status = Number.isInteger(error?.status) && error.status >= 400 && error.status < 600 ? error.status : 400;
  res.status(status).json({ error: error?.message || fallback, ...(error?.code ? { code: error.code } : {}) });
}

/**
 * Wraps a handler so thrown or rejected errors become JSON responses.
 * The handler returns the payload; `status` sets the success code.
 */
function handle(work, { status = 200, fallback } = {}) {
  return async (req, res) => {
    try {
      const payload = await work(req, res);
      if (res.headersSent) return;
      if (payload === undefined) res.status(204).end();
      else res.status(status).json(payload);
    } catch (error) { sendError(res, error, fallback); }
  };
}

class HttpError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}

module.exports = { localRequest, securityHeaders, sendError, handle, HttpError, LOOPBACK_HOSTS };
