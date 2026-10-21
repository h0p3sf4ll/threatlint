'use strict';

/**
 * Semgrep AppSec Platform tuning for confirmed false positives. The public API cannot edit rule
 * logic, so the narrowest durable tuning is triage: matching findings are set to ignored /
 * false_positive with a note, and Semgrep carries that triage to the same fingerprint on later
 * scans and other branches. Matching is limited to one rule, one repository, and one file, and the
 * user confirms the exact finding IDs before anything is ignored. Rule-logic changes stay a
 * scanner-owner task, proposed in the FP report.
 */

const { HttpError } = require('./http.cjs');
const { readParameters } = require('./servicenow.cjs');

const API = 'https://semgrep.app/api/v1';
const TOKEN_PARAMETER = '/cfc-appsec-semgrep-scan/semgrep-token';
const HTTP_TIMEOUT_MS = 30_000;
const PAGE_SIZE = 100;
const MAX_PAGES = 20;
const MAX_NOTE = 3000;
const SLUG = /^[\w.-]{1,100}$/;
const REPO = /^[\w.@/-]{1,200}$/;

async function semgrepToken({ profile } = {}) {
  if (process.env.SEMGREP_APP_TOKEN) return process.env.SEMGREP_APP_TOKEN;
  const token = (await readParameters([TOKEN_PARAMETER], { profile }))[TOKEN_PARAMETER];
  if (!token) throw new HttpError(`Your AWS identity cannot read ${TOKEN_PARAMETER}. Request access through SSO.`, 403);
  return token;
}

async function requestJson(fetchImpl, url, options = {}) {
  let response;
  try {
    // redirect: 'error' keeps the bearer token on semgrep.app.
    response = await fetchImpl(url, { ...options, headers: { Accept: 'application/json', ...options.headers }, redirect: 'error', signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });
  } catch (error) { throw new HttpError(`Semgrep request failed: ${error.cause?.message || error.message}`, 502); }
  if (!response.ok) {
    const hint = { 401: ' Check the Semgrep API token.', 403: ' The token needs the Web API scope for this deployment.', 404: ' Check the deployment slug.' }[response.status] || '';
    throw new HttpError(`Semgrep returned HTTP ${response.status}.${hint}`, 502);
  }
  try { return await response.json(); } catch { throw new HttpError('Semgrep returned a non-JSON response', 502); }
}

/** The token's deployment; a token normally belongs to exactly one. */
async function deployment(token, slug, fetchImpl) {
  const { deployments = [] } = await requestJson(fetchImpl, `${API}/deployments`, { headers: { Authorization: `Bearer ${token}` } });
  const found = slug ? deployments.find(item => item.slug === slug) : deployments.length === 1 ? deployments[0] : null;
  if (!found) throw new HttpError(slug ? `The Semgrep token cannot access deployment ${slug}` : 'The Semgrep token can access several deployments; choose one', 400);
  return { slug: found.slug, name: found.name };
}

const tail = value => String(value || '').replaceAll('\\', '/').replace(/^\.?\//, '');
// Rule IDs are dotted paths (e.g. python.lang.security.audit.x); a short scanner ID matches its last segments.
const sameRule = (name, rule) => name === rule || name.endsWith(`.${rule}`);
const samePath = (path, wanted) => { const a = tail(path), b = tail(wanted); return a === b || a.endsWith(`/${b}`) || b.endsWith(`/${a}`); };

function validateTarget(target) {
  const value = target && typeof target === 'object' ? target : {};
  const rule = String(value.rule || '').trim(), repo = String(value.repo || '').trim(), path = String(value.path || '').trim();
  if (!/^[\w.:/-]{3,300}$/.test(rule)) throw new HttpError('Enter the Semgrep rule ID that produced the false positive');
  if (!REPO.test(repo)) throw new HttpError('Enter the Semgrep project (repository) name, e.g. org/repo');
  if (!path || path.length > 500 || path.includes('..')) throw new HttpError('Enter the repository-relative file path of the false positive');
  const line = value.line == null || value.line === '' ? null : Number(value.line);
  if (line != null && (!Number.isInteger(line) || line < 1)) throw new HttpError('Line must be a positive integer');
  const slug = value.deployment ? String(value.deployment).trim() : '';
  if (slug && !SLUG.test(slug)) throw new HttpError('Invalid Semgrep deployment slug');
  return { rule, repo, path, line, deployment: slug };
}

/** Open findings for exactly this rule, repository, and file (and line, when given). */
async function matchFindings(token, target, { fetchImpl = fetch } = {}) {
  const { slug, name } = await deployment(token, target.deployment, fetchImpl);
  const headers = { Authorization: `Bearer ${token}` };
  const matches = [];
  for (let page = 0; page < MAX_PAGES; page++) {
    const query = new URLSearchParams({ issue_type: 'sast', repos: target.repo, status: 'open', dedup: 'true', page: String(page), page_size: String(PAGE_SIZE) });
    const { findings = [] } = await requestJson(fetchImpl, `${API}/deployments/${encodeURIComponent(slug)}/findings?${query}`, { headers });
    for (const finding of findings) {
      if (!sameRule(String(finding.rule_name || ''), target.rule) || !samePath(finding.location?.file_path, target.path)) continue;
      if (target.line != null && Math.abs(Number(finding.location?.line) - target.line) > 3) continue;
      matches.push({ id: finding.id, rule: finding.rule_name, path: finding.location?.file_path, line: finding.location?.line ?? null,
        ref: finding.ref || null, state: finding.triage_state || finding.status || null, url: finding.line_of_code_url || null });
    }
    if (findings.length < PAGE_SIZE) break;
  }
  return { deployment: { slug, name }, matches };
}

/** Ignores the confirmed finding IDs as false positives; the IDs must come from matchFindings. */
async function ignoreAsFalsePositive(token, slug, issueIds, note, { fetchImpl = fetch } = {}) {
  if (!SLUG.test(String(slug || ''))) throw new HttpError('Invalid Semgrep deployment slug');
  const ids = [...new Set(issueIds)];
  if (!ids.length || ids.length > 50 || ids.some(id => !Number.isSafeInteger(id) || id < 1)) throw new HttpError('Choose between 1 and 50 Semgrep findings to ignore');
  const body = { issue_type: 'sast', issue_ids: ids, new_triage_state: 'ignored', new_triage_reason: 'false_positive', new_note: String(note).slice(0, MAX_NOTE) };
  const result = await requestJson(fetchImpl, `${API}/deployments/${encodeURIComponent(slug)}/triage`,
    { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  return { triaged: result.num_triaged ?? 0, issueIds: result.triaged_issues || [] };
}

module.exports = { TOKEN_PARAMETER, semgrepToken, validateTarget, matchFindings, ignoreAsFalsePositive, sameRule, samePath };
