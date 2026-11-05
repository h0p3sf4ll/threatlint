'use strict';

/** Read-only DefectDojo findings snapshot for the Metrics view. */

const { HttpError } = require('./http.cjs');
const scanners = require('./scanners.cjs');

const PAGE_SIZE = 100;
const MAX_PAGE_CHARS = 8 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 30_000;
const SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);

function connectionStatus() {
  try { scanners.connection('dojo'); return { connected: true }; }
  catch { return { connected: false }; }
}

function concise(value, max = 300) { return String(value ?? '').trim().slice(0, max); }

function normalize(row, now = Date.now()) {
  if (!row || typeof row !== 'object' || !Number.isSafeInteger(row.id) || row.id < 1) {
    throw new HttpError('DefectDojo returned a finding without a valid id', 502);
  }
  const id = `DOJO-${row.id}`;
  const severity = concise(row.severity, 30).toUpperCase();
  const date = [row.date, row.created, row.date_created].map(value => Date.parse(value)).find(Number.isFinite);
  const workspace = concise(row.product_name, 120) || (Number.isSafeInteger(row.product) && row.product > 0 ? `Product ${row.product}` : 'DefectDojo');
  return {
    id,
    title: concise(row.title) || id,
    severity: SEVERITIES.has(severity) ? severity : 'UNSPECIFIED',
    disposition: row.false_p === true ? 'FALSE POSITIVE' : row.active === false || row.is_mitigated === true ? 'REMEDIATED' : 'OPEN',
    timestamp: date ?? now,
    workspace,
    rule: concise(row.vuln_id_from_tool, 160) || (Number.isSafeInteger(row.cwe) && row.cwe > 0 ? `CWE-${row.cwe}` : 'DefectDojo finding'),
    hasEvidence: !!(concise(row.file_path, 500) && Number.isInteger(row.line) && row.line > 0),
    fingerprint: `defectdojo:${row.id}`,
  };
}

async function readPage(fetchImpl, conn, offset, signal) {
  const query = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset), ordering: 'id' });
  const url = `${conn.url}/api/v2/findings/?${query}`;
  let response;
  try {
    response = await fetchImpl(url, { method: 'GET', headers: { Accept: 'application/json', Authorization: `Token ${conn.token}` },
      redirect: 'error', signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)]) : AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  } catch {
    throw new HttpError('DefectDojo findings request failed', 502);
  }
  if (!response.ok) throw new HttpError(`DefectDojo returned HTTP ${response.status} while reading findings`, 502);
  let text;
  try { text = await response.text(); }
  catch { throw new HttpError('DefectDojo could not return the findings page', 502); }
  if (text.length > MAX_PAGE_CHARS) throw new HttpError('DefectDojo findings page is too large for metrics sync', 502);
  let page;
  try { page = JSON.parse(text); }
  catch { throw new HttpError('DefectDojo returned invalid JSON for findings', 502); }
  if (!page || !Number.isSafeInteger(page.count) || page.count < 0 || !Array.isArray(page.results) || page.results.length > PAGE_SIZE) {
    throw new HttpError('DefectDojo returned an invalid findings page', 502);
  }
  return page;
}

/**
 * Reads every finding the configured token may view; there is no count limit. A result that changes
 * mid-sync fails the whole sync so the dashboard never shows a partial total.
 * We construct each page URL ourselves rather than following an upstream `next` URL.
 */
async function fetchMetrics({ fetchImpl = fetch, signal } = {}) {
  const conn = scanners.connection('dojo');
  const first = await readPage(fetchImpl, conn, 0, signal);
  const rows = [...first.results];
  let offset = rows.length;
  while (offset < first.count) {
    if (!rows.length) throw new HttpError('DefectDojo pagination stopped before all findings were read', 502);
    const page = await readPage(fetchImpl, conn, offset, signal);
    if (page.count !== first.count || page.results.length === 0) throw new HttpError('DefectDojo findings changed during metrics sync; retry', 409);
    rows.push(...page.results);
    offset += page.results.length;
  }
  const items = rows.map(row => normalize(row));
  if (new Set(items.map(item => item.id)).size !== first.count) throw new HttpError('DefectDojo findings changed during metrics sync; retry', 409);
  return { items };
}

module.exports = { fetchMetrics, connectionStatus, normalize, PAGE_SIZE };
