'use strict';

/**
 * DefectDojo and SonarQube connections for the Workbench, mirroring src/threatlint/scanners/. The Workbench reviews
 * findings through the Python CLI (`threatlint dojo|sonar fetch/checkout/resolve`) so it behaves exactly like the CLI;
 * this module holds what Node needs itself: the saved connection (~/.threatlint/defectdojo.json and sonarqube.json,
 * mode 0600, shared with `threatlint dojo|sonar login`), URL validation, reference parsing, the token check, and the
 * write-back used when an imported scan report is posted (attach/note/status for DefectDojo, comment/transition for
 * SonarQube). Tokens are never returned to the page and every request refuses redirects.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { HttpError } = require('./http.cjs');
const { CLOSING_COMMENT, TRUE_POSITIVE_COMMENT, AMBIGUOUS_COMMENT } = require('./servicenow.cjs');

const HTTP_TIMEOUT_MS = 30_000;
const MAX_REFERENCES = 50;
const DOCX_TYPE = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
const DISPOSITIONS = ['TRUE POSITIVE', 'FALSE POSITIVE', 'AMBIGUOUS'];

const TOOLS = {
  dojo: { id: 'dojo', name: 'defectdojo', label: 'DefectDojo', file: 'defectdojo.json', urlEnv: 'THREATLINT_DOJO_URL', tokenEnv: 'THREATLINT_DOJO_TOKEN', example: 'DOJO-123', attachments: true },
  sonar: { id: 'sonar', name: 'sonarqube', label: 'SonarQube', file: 'sonarqube.json', urlEnv: 'THREATLINT_SONAR_URL', tokenEnv: 'THREATLINT_SONAR_TOKEN', example: 'SONAR-AYxExampleKey01', attachments: false },
};
const SONAR_SUMMARY = { 'FALSE POSITIVE': 'Closed by Threatlint as a false positive.', 'TRUE POSITIVE': 'True positive per Threatlint review; left open.',
  AMBIGUOUS: 'Ambiguous per Threatlint review; left open pending the evidence the report names.' };

function tool(id) {
  const found = Object.hasOwn(TOOLS, id) ? TOOLS[id] : Object.values(TOOLS).find(item => item.name === id);
  if (!found) throw new HttpError('tool must be "dojo" (DefectDojo) or "sonar" (SonarQube)');
  return found;
}

// ── Connection ──────────────────────────────────────────────────────────────

function home() { return process.env.THREATLINT_HOME || path.join(os.homedir(), '.threatlint'); }
function configPath(id) { return path.join(home(), tool(id).file); }

function readConfig(id) {
  try { const value = JSON.parse(fs.readFileSync(configPath(id), 'utf8')); return { url: String(value.url || ''), token: String(value.token || '') }; }
  catch { return { url: '', token: '' }; }
}
function writeConfig(id, values) {
  const file = configPath(id);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temp, `${JSON.stringify(values, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temp, file);
  if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
}
function clearConfig(id) { try { fs.unlinkSync(configPath(id)); return true; } catch { return false; } }
/** What the settings page may see: never the token itself. */
function publicConfig(id) {
  const { url, token } = readConfig(id);
  const spec = tool(id);
  return { tool: spec.id, label: spec.label, url: url || process.env[spec.urlEnv] || '', hasToken: !!token || !!process.env[spec.tokenEnv],
    tokenSource: token ? 'saved' : process.env[spec.tokenEnv] ? 'environment' : null, path: configPath(id) };
}

/** HTTPS base URL (origin plus an optional context path); a pasted API URL is trimmed back to its base. */
function validateBaseUrl(value, id) {
  const { label } = tool(id);
  let url;
  try { url = new URL(String(value || '').trim()); } catch { throw new HttpError(`Enter the HTTPS ${label} URL`); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new HttpError(`Use the HTTPS ${label} URL, e.g. https://${tool(id).name}.example.test`);
  const pathname = url.pathname.replace(/\/api(?:\/v2)?(?:\/.*)?$/, '').replace(/\/+$/, '');
  if (pathname && !/^(?:\/[A-Za-z0-9._~-]+){1,4}$/.test(pathname)) throw new HttpError(`The ${label} URL path is not a plain context path`);
  return `${url.origin}${pathname}`;
}

/** Connection for a request: saved settings, then the environment. */
function connection(id) {
  const spec = tool(id);
  const saved = readConfig(id);
  const url = saved.url || process.env[spec.urlEnv] || '';
  const token = saved.token || process.env[spec.tokenEnv] || '';
  if (!url || !token) throw new HttpError(`Add the ${spec.label} URL and API token in Settings → ${spec.label} (or run \`threatlint ${spec.id} login\`).`, 412);
  return { tool: spec.id, url: validateBaseUrl(url, id), token };
}

function authHeaders(id, token) {
  return tool(id).id === 'dojo' ? { Authorization: `Token ${token}` } : { Authorization: `Basic ${Buffer.from(`${token}:`).toString('base64')}` };
}

async function requestJson(fetchImpl, id, url, options = {}) {
  const { label } = tool(id);
  let response;
  try {
    // redirect: 'error' keeps the token on the validated host.
    response = await fetchImpl(url, { ...options, headers: { Accept: 'application/json', ...options.headers }, redirect: 'error', signal: options.signal || AbortSignal.timeout(HTTP_TIMEOUT_MS) });
  } catch (error) { throw new HttpError(`${label} request failed: ${error.cause?.message || error.message}`, 502); }
  if (!response.ok) {
    const hint = { 401: ' Check the API token.', 403: ' The token lacks permission for this operation.', 404: ' Not found; check the reference and the base URL.' }[response.status] || '';
    throw Object.assign(new HttpError(`${label} returned HTTP ${response.status}.${hint}`, 502), { upstreamStatus: response.status });
  }
  const text = typeof response.text === 'function' ? await response.text() : JSON.stringify(await response.json());
  if (!text.trim()) return null;
  try { return JSON.parse(text); } catch { throw new HttpError(`${label} returned a non-JSON response (check the URL)`, 502); }
}

/** Checks a token against the server before it is saved. */
async function validateToken(id, url, token, { fetchImpl = fetch } = {}) {
  if (typeof token !== 'string' || !/^[\x21-\x7e]{8,400}$/.test(token)) throw new HttpError(`That does not look like a ${tool(id).label} API token`);
  if (tool(id).id === 'dojo') { await requestJson(fetchImpl, id, `${url}/api/v2/findings/?limit=1`, { headers: authHeaders(id, token) }); return; }
  const result = await requestJson(fetchImpl, id, `${url}/api/authentication/validate`, { headers: authHeaders(id, token) });
  if (result?.valid !== true) throw new HttpError('SonarQube did not accept the token', 400);
}

// ── References ──────────────────────────────────────────────────────────────

const DOJO_REF = /^(?:DOJO-|DOJO:|DEFECTDOJO-)?(\d{1,12})$/i;
const SONAR_REF = /^(?:(SONAR-HOTSPOT-|HOTSPOT-)|(?:SONAR-)?)([A-Za-z0-9_-]{6,64})$/i;

/** Canonical references (DOJO-123, SONAR-<key>, SONAR-HOTSPOT-<key>) from free text; bounded and de-duplicated. */
function parseReferences(id, value) {
  const spec = tool(id);
  const text = Array.isArray(value) ? value.join(' ') : String(value ?? '');
  if (text.length > 64 * 1024) throw new HttpError('The list is too long');
  const tokens = text.split(/[\s,;]+/).filter(Boolean);
  const pattern = spec.id === 'dojo' ? DOJO_REF : SONAR_REF;
  const invalid = tokens.filter(token => !pattern.test(token));
  if (invalid.length) throw new HttpError(`Not a ${spec.label} ${spec.id === 'dojo' ? 'finding id' : 'issue or hotspot key'}: ${invalid.slice(0, 5).join(', ')} (e.g. ${spec.example})`);
  const references = [...new Set(tokens.map(token => {
    const match = pattern.exec(token);
    return spec.id === 'dojo' ? `DOJO-${Number(match[1])}` : match[1] ? `SONAR-HOTSPOT-${match[2]}` : `SONAR-${match[2]}`;
  }))];
  if (!references.length) throw new HttpError(`Enter at least one ${spec.label} reference`);
  if (references.length > MAX_REFERENCES) throw new HttpError(`Review at most ${MAX_REFERENCES} ${spec.label} findings at a time`);
  return references;
}

/** True when the text names the reference as a whole token (DOJO-12 does not match DOJO-123). */
function mentions(text, reference) {
  return new RegExp(`(?<![\\w-])${reference.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w-])`, 'i').test(String(text || ''));
}

// ── Write-back (scan-import posts) ──────────────────────────────────────────

/**
 * DefectDojo: attach the Word report (skipping one already attached), add the Threatlint note, then
 * FALSE POSITIVE -> false_p / inactive; TRUE POSITIVE -> verified; AMBIGUOUS -> note only.
 */
async function resolveDojo(conn, reference, { disposition, files = [] }, { fetchImpl = fetch } = {}) {
  const [ref] = parseReferences('dojo', reference);
  if (!DISPOSITIONS.includes(disposition)) throw new HttpError(`${ref} has no TRUE POSITIVE / FALSE POSITIVE / AMBIGUOUS disposition`);
  const findingId = Number(ref.slice(5));
  const base = `${conn.url}/api/v2/findings/${findingId}`;
  const headers = authHeaders('dojo', conn.token);
  let finding;
  try { finding = await requestJson(fetchImpl, 'dojo', `${base}/`, { headers }); }
  catch (error) { if ([403, 404].includes(error.upstreamStatus)) throw Object.assign(new HttpError(`${ref} was not found or is not readable with this token`, 404), { code: 'finding_unreadable' }); throw error; }
  let existing = new Set();
  try { const listed = await requestJson(fetchImpl, 'dojo', `${base}/files/`, { headers }); existing = new Set((listed?.files || listed?.results || []).map(row => String(row?.title || ''))); } catch { /* upload anyway */ }
  const attachments = [];
  // Attach first so a finding is never closed without its evidence.
  for (const file of files) {
    if (existing.has(file.name)) { attachments.push({ name: file.name, alreadyAttached: true }); continue; }
    const form = new FormData();
    form.append('title', file.name);
    form.append('file', new Blob([file.content], { type: file.type }), file.name);
    await requestJson(fetchImpl, 'dojo', `${base}/files/`, { method: 'POST', headers, body: form });
    attachments.push({ name: file.name });
  }
  const falsePositive = disposition === 'FALSE POSITIVE';
  const note = falsePositive ? CLOSING_COMMENT : disposition === 'AMBIGUOUS' ? AMBIGUOUS_COMMENT : TRUE_POSITIVE_COMMENT;
  await requestJson(fetchImpl, 'dojo', `${base}/notes/`, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ entry: note, private: false }) });
  const patch = falsePositive ? { false_p: true, active: false, verified: false } : disposition === 'TRUE POSITIVE' ? { verified: true, ...(finding?.false_p ? { false_p: false, active: true } : {}) } : null;
  const stored = patch ? await requestJson(fetchImpl, 'dojo', `${base}/`, { method: 'PATCH', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify(patch) }) || {} : {};
  const closed = falsePositive && stored.false_p === true && !stored.active;
  return { reference: ref, disposition, note, attachments, closed, leftOpen: !falsePositive, url: `${conn.url}/finding/${findingId}`,
    action: falsePositive ? (closed ? 'closed' : 'close not applied') : disposition === 'TRUE POSITIVE' ? (stored.verified ? 'verified' : 'verify not applied') : 'noted' };
}

function sonarComment(disposition, summary, where) {
  return `${SONAR_SUMMARY[disposition]} Summary: ${String(summary || '').replace(/\s+/g, ' ').trim().slice(0, 300)}. Full report: ${String(where || 'the Threatlint report kept by the reviewer').slice(0, 500)}.`.slice(0, 4000);
}

/**
 * SonarQube: no attachments, so a comment carries a summary and names where the full report lives.
 * Issues: comment, then FALSE POSITIVE -> falsepositive; TRUE POSITIVE -> confirm when offered. Hotspots: FALSE POSITIVE -> REVIEWED/SAFE; else comment.
 */
async function resolveSonar(conn, reference, { disposition, summary = '', where = '' }, { fetchImpl = fetch } = {}) {
  const [ref] = parseReferences('sonar', reference);
  if (!DISPOSITIONS.includes(disposition)) throw new HttpError(`${ref} has no TRUE POSITIVE / FALSE POSITIVE / AMBIGUOUS disposition`);
  const hotspot = ref.startsWith('SONAR-HOTSPOT-');
  const key = ref.slice(hotspot ? 14 : 6);
  const headers = { ...authHeaders('sonar', conn.token), 'Content-Type': 'application/x-www-form-urlencoded' };
  const post = (route, params) => requestJson(fetchImpl, 'sonar', `${conn.url}${route}`, { method: 'POST', headers, body: new URLSearchParams(params).toString() });
  const comment = sonarComment(disposition, summary, where);
  const result = { reference: ref, disposition, note: comment, attachments: [], closed: false, leftOpen: disposition !== 'FALSE POSITIVE' };
  try {
    if (hotspot) {
      if (disposition === 'FALSE POSITIVE') { await post('/api/hotspots/change_status', { hotspot: key, status: 'REVIEWED', resolution: 'SAFE', comment }); return { ...result, closed: true, action: 'closed' }; }
      await post('/api/hotspots/add_comment', { hotspot: key, comment });
      return { ...result, action: 'noted' };
    }
    await post('/api/issues/add_comment', { issue: key, text: comment });
  } catch (error) { if (error.upstreamStatus === 404) throw Object.assign(new HttpError(`${ref} was not found or is not readable with this token`, 404), { code: 'finding_unreadable' }); throw error; }
  const transition = { 'FALSE POSITIVE': 'falsepositive', 'TRUE POSITIVE': 'confirm' }[disposition];
  if (!transition) return { ...result, action: 'noted' };
  try {
    const stored = await post('/api/issues/do_transition', { issue: key, transition });
    if (disposition === 'FALSE POSITIVE') { const closed = (stored?.issue?.resolution ?? 'FALSE-POSITIVE') === 'FALSE-POSITIVE'; return { ...result, closed, action: closed ? 'closed' : 'close not applied' }; }
    return { ...result, action: 'confirmed' };
  } catch (error) {
    if (disposition === 'TRUE POSITIVE' && error.upstreamStatus === 400) return { ...result, action: 'noted', detail: 'Confirm is not available for this issue; the comment records the verdict' };
    throw error;
  }
}

module.exports = { TOOLS, tool, configPath, readConfig, writeConfig, clearConfig, publicConfig, validateBaseUrl, connection, validateToken, parseReferences, mentions,
  resolveDojo, resolveSonar, sonarComment, DOCX_TYPE, MAX_REFERENCES };
