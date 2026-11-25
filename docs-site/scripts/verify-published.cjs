'use strict';

// Verify the exact built site. This script only reads local files and sends GETs.
const fs = require('node:fs');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');
const { retired } = require('../navigation.cjs');

const ROOT = path.resolve(__dirname, '../../marketing');
const DOCS = path.join(ROOT, 'docs');
const CONCURRENCY = 3;
const ATTEMPTS = 3;
const RETRY_MS = 5000;
const TIMEOUT_MS = 30000;

class VerificationError extends Error {}
const check = (condition, message) => { if (!condition) throw new VerificationError(message); };

function parseBase(args) {
  check(args.length <= 1 && (!args.length || args[0].startsWith('--base=')), 'Usage: node verify-published.cjs [--base=http://127.0.0.1:8088]');
  let base;
  try { base = new URL(args[0]?.slice('--base='.length) || 'https://threatlint.dev'); }
  catch { throw new VerificationError('Supply a valid site origin'); }
  check(!base.username && !base.password && !base.search && !base.hash && base.pathname === '/', 'Base must be an origin without credentials, path, query, or fragment');
  check(base.protocol === 'https:' || (base.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname)), 'Use HTTPS, or HTTP on loopback for a local preview');
  return base;
}

function localBytes(filename) {
  const resolved = path.resolve(filename);
  check(resolved.startsWith(ROOT + path.sep), 'Referenced file escapes the built website');
  const stat = fs.lstatSync(resolved);
  check(stat.isFile() && !stat.isSymbolicLink() && fs.realpathSync(resolved).startsWith(fs.realpathSync(ROOT) + path.sep), 'Expected a regular built website file');
  return fs.readFileSync(resolved);
}

function htmlFiles(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const filename = path.join(directory, entry.name);
    check(!entry.isSymbolicLink(), 'Unexpected link in the built documentation');
    if (entry.isDirectory()) files.push(...htmlFiles(filename));
    else if (entry.isFile() && entry.name.endsWith('.html') && entry.name !== '404.html') files.push(filename);
  }
  return files.sort();
}

function attributes(tag) {
  const result = {};
  for (const match of tag.matchAll(/([a-z][\w:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)) {
    result[match[1].toLowerCase()] = match[2] ?? match[3] ?? match[4];
  }
  return result;
}

function collectTargets(base) {
  const targets = new Map();
  const add = target => {
    const existing = targets.get(target.resource);
    check(!existing || (existing.expected?.equals(target.expected) && existing.csp === target.csp), 'Conflicting expectations for a published route');
    if (!existing) targets.set(target.resource, target);
  };
  for (const name of ['index.html', 'styles.css', 'assets/mark.svg', 'robots.txt', 'sitemap.xml']) {
    add({ resource: name === 'index.html' ? '/' : '/' + name, kind: 'root', expected: localBytes(path.join(ROOT, name)) });
  }
  const directives = [...fs.readFileSync(path.join(DOCS, '.htaccess'), 'utf8').matchAll(/Header\s+always\s+set\s+Content-Security-Policy\s+"([^"\r\n]+)"/g)];
  check(directives.length === 1, 'Expected exactly one built documentation CSP');
  const csp = directives[0][1];
  const pages = htmlFiles(DOCS);
  check(pages.length > 0, 'Build the documentation before verifying publication');
  const assets = new Set();
  for (const filename of pages) {
    const relative = path.relative(DOCS, filename).split(path.sep).join('/');
    const resource = '/docs/' + (relative === 'index.html' ? '' : relative.endsWith('/index.html') ? relative.slice(0, -'index.html'.length) : relative);
    check(!retired.some(item => resource === '/docs/' + item.route || resource.startsWith('/docs/' + item.route + '/')), 'A retired page remains in the local build');
    const expected = localBytes(filename);
    add({ resource, kind: 'docs', expected, csp });
    for (const match of expected.toString('utf8').matchAll(/<(script|link)\b[^>]*>/gi)) {
      const attrs = attributes(match[0]);
      const rel = (attrs.rel || '').toLowerCase().split(/\s+/);
      const reference = match[1].toLowerCase() === 'script' ? attrs.src :
        rel.includes('stylesheet') || rel.includes('modulepreload') || (rel.includes('preload') && ['script', 'style'].includes(attrs.as)) ? attrs.href : null;
      if (!reference) continue;
      const url = new URL(reference.replaceAll('&amp;', '&'), new URL(resource, base));
      check(url.origin === base.origin, 'A documentation script or stylesheet points outside the published site');
      url.hash = '';
      assets.add(url.pathname + url.search);
    }
  }
  for (const resource of [...assets].sort()) {
    const url = new URL(resource, base);
    const filename = path.resolve(ROOT, '.' + decodeURIComponent(url.pathname));
    add({ resource, kind: 'asset', expected: localBytes(filename) });
  }
  for (const item of retired) {
    check(/^[a-z0-9]+(?:[/-][a-z0-9]+)*$/.test(item.route), 'Unexpected retired-route definition');
    for (const suffix of ['', '/', '/index.html']) {
      const resource = '/docs/' + item.route + suffix;
      check(!targets.has(resource), 'An active and retired route overlap');
      targets.set(resource, { resource, kind: 'retired', status: item.redirect ? 301 : 410,
        destination: item.redirect ? new URL(item.redirect, base) : null });
    }
  }
  return [...targets.values()];
}

async function exactBody(response, expected) {
  let offset = 0;
  for await (const chunk of response.body) {
    const bytes = Buffer.from(chunk);
    check(offset + bytes.length <= expected.length && bytes.equals(expected.subarray(offset, offset + bytes.length)), 'Published bytes differ from the built source');
    offset += bytes.length;
  }
  check(offset === expected.length, 'Published bytes differ from the built source');
}

async function verifyTarget(target, base, deployment) {
  const url = new URL(target.resource, base);
  url.searchParams.set('deployment', deployment);
  let response;
  try {
    response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { 'Cache-Control': 'no-cache', Pragma: 'no-cache' } });
    check(response.status === (target.status || 200), 'Expected HTTP ' + (target.status || 200) + ', received ' + response.status);
    if (target.destination) {
      const location = response.headers.get('location');
      check(location, 'Retired-page redirect has no destination');
      const destination = new URL(location, url);
      check(destination.origin === base.origin && destination.pathname === target.destination.pathname, 'Retired-page redirect has an unexpected destination');
    }
    if (target.csp) check(response.headers.get('content-security-policy') === target.csp, 'Published documentation CSP differs from the built policy');
    if (target.expected) await exactBody(response, target.expected);
  } finally {
    if (response?.body && !response.bodyUsed) await response.body.cancel().catch(() => {});
  }
}

async function verifyPublished(base, deployment) {
  const targets = collectTargets(base);
  const failures = [];
  const counts = { root: 0, docs: 0, asset: 0, retired: 0 };
  for (const target of targets) counts[target.kind]++;
  let next = 0, verified = 0, requests = 0;
  async function worker() {
    while (!failures.length) {
      const target = targets[next++];
      if (!target) return;
      for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
        requests++;
        try { await verifyTarget(target, base, deployment); verified++; break; }
        catch (error) {
          if (attempt < ATTEMPTS) { await delay(RETRY_MS); continue; }
          failures.push({ path: target.resource, attempts: attempt,
            reason: error instanceof VerificationError ? error.message : error.name === 'TimeoutError' ? 'Request timed out' : 'Network request failed' });
        }
      }
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  return { status: failures.length ? 'failed' : 'passed', base: base.origin, deployment, counts,
    expected: targets.length, verified, requests, concurrency: CONCURRENCY, failures };
}

module.exports = { collectTargets, verifyTarget, verifyPublished };
if (require.main === module) {
  (async () => {
    const base = parseBase(process.argv.slice(2));
    const deployment = process.env.GITHUB_SHA || 'local';
    check(/^(?:[a-f0-9]{40}|local)$/i.test(deployment), 'GITHUB_SHA must identify the deployed commit');
    const report = await verifyPublished(base, deployment);
    console.log(JSON.stringify(report));
    if (report.status !== 'passed') process.exitCode = 1;
  })().catch(error => {
    console.error(JSON.stringify({ status: 'failed', reason: error instanceof VerificationError ? error.message : 'Could not inspect the built website' }));
    process.exitCode = 1;
  });
}
