'use strict';

/**
 * Closes false positives in Azure DevOps Boards and GitHub Advanced Security code scanning, the same
 * way ServiceNow AVITs are closed: the FP review report is attached first (prefixed with the item's
 * ID), then the item is closed with a "Closed by Threatlint" note, and the stored state is reported.
 * Like AVR's CodeSecurity view, only code-scanning findings qualify (Semgrep covers code only):
 * GitHub code-scanning alerts are code findings by definition; ADO work items must be tagged or
 * titled as CodeSecurity/SAST/Semgrep (THREATLINT_ADO_CODE_SECURITY_PATTERN overrides).
 * Tokens are used per request and never stored.
 */

const { HttpError } = require('./http.cjs');

const HTTP_TIMEOUT_MS = 30_000;
const ADO_API = '7.1';
const ADO_ORG = /^[A-Za-z0-9][\w.-]{0,49}$/;
const ADO_PROJECT = /^[^\\/:*?"<>|#%&]{1,64}$/;
const GH_NAME = /^[A-Za-z0-9][\w.-]{0,99}$/;
const ADO_CODE_SECURITY = /code\s*security|\bsast\b|static\s+(?:application|code)|semgrep|code\s*scanning/i;
// Item references as the FP reviewer writes them in "Original finding".
const ADO_REF = /\bADO[#-](\d{1,10})\b/i;
const GHAS_REF = /\bGHAS[#-]([A-Za-z0-9][\w.-]{0,99})\/([A-Za-z0-9][\w.-]{0,99})#(\d{1,10})\b/i;

async function request(fetchImpl, url, options, service) {
  let response;
  try {
    // redirect: 'error' keeps the PAT on the validated API origin.
    response = await fetchImpl(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });
  } catch (error) { throw new HttpError(`${service} request failed: ${error.cause?.message || error.message}`, 502); }
  if (!response.ok) {
    const hint = { 401: ' Check the token.', 403: ' The token lacks permission for this operation.', 404: ' The item was not found or the token cannot see it.' }[response.status] || '';
    throw new HttpError(`${service} returned HTTP ${response.status}.${hint}`, 502);
  }
  try { return await response.json(); } catch { throw new HttpError(`${service} returned a non-JSON response`, 502); }
}

function token(value, service) {
  const text = typeof value === 'string' ? value.trim() : '';
  if (!text || text.length > 1000 || /\s/.test(text)) throw new HttpError(`Add a ${service} token in Model & settings`, 401);
  return text;
}

// ── Azure DevOps Boards ──────────────────────────────────────────────────────

function validateAdo(value) {
  const settings = value && typeof value === 'object' ? value : {};
  const organization = String(settings.organization || '').trim(), project = String(settings.project || '').trim();
  if (!ADO_ORG.test(organization)) throw new HttpError('Enter the Azure DevOps organization slug (not a URL)');
  if (!ADO_PROJECT.test(project)) throw new HttpError('Enter the Azure DevOps project name');
  return { organization, project, token: token(settings.token, 'Azure DevOps'), closedState: String(settings.closedState || process.env.THREATLINT_ADO_CLOSED_STATE || '').trim() || null };
}

function adoCodeSecurity(fields) {
  const custom = process.env.THREATLINT_ADO_CODE_SECURITY_PATTERN;
  let pattern = ADO_CODE_SECURITY;
  if (custom) { try { pattern = new RegExp(custom, 'i'); } catch { throw new HttpError('THREATLINT_ADO_CODE_SECURITY_PATTERN is not a valid regular expression', 500); } }
  return ['System.Tags', 'System.Title', 'System.AreaPath'].some(name => pattern.test(String(fields?.[name] || '')));
}

/** The Closed state of the item's type: the configured one, else the first state in the "Completed" category. */
async function adoClosedState(fetchImpl, base, headers, type, configured) {
  if (configured) return configured;
  const { value = [] } = await request(fetchImpl, `${base}/_apis/wit/workitemtypes/${encodeURIComponent(type)}/states?api-version=${ADO_API}`, { headers }, 'Azure DevOps');
  const done = value.filter(state => state.category === 'Completed');
  const state = done.find(item => /^closed$/i.test(item.name)) || done.find(item => /^(done|resolved)$/i.test(item.name)) || done[0];
  if (!state) throw new HttpError(`The ${type} work item type has no Completed state; set THREATLINT_ADO_CLOSED_STATE`, 502);
  return state.name;
}

async function closeAdoWorkItem(settings, id, { note, files }, { fetchImpl = fetch } = {}) {
  const ado = validateAdo(settings);
  if (!/^\d{1,10}$/.test(String(id))) throw new HttpError('Azure DevOps work item IDs are numbers');
  const base = `https://dev.azure.com/${encodeURIComponent(ado.organization)}/${encodeURIComponent(ado.project)}`;
  const auth = `Basic ${Buffer.from(`:${ado.token}`).toString('base64')}`;
  const headers = { Authorization: auth, Accept: 'application/json' };
  const item = await request(fetchImpl, `${base}/_apis/wit/workitems/${id}?fields=System.State,System.WorkItemType,System.Title,System.Tags,System.AreaPath&api-version=${ADO_API}`, { headers }, 'Azure DevOps');
  if (!adoCodeSecurity(item.fields)) throw new HttpError(`ADO#${id} is not tagged as a CodeSecurity finding; Threatlint closes only code findings that Semgrep covers`, 422);
  const state = await adoClosedState(fetchImpl, base, headers, item.fields['System.WorkItemType'], ado.closedState);
  const patch = [];
  const attachments = [];
  for (const file of files) {
    const uploaded = await request(fetchImpl, `https://dev.azure.com/${encodeURIComponent(ado.organization)}/_apis/wit/attachments?fileName=${encodeURIComponent(file.name)}&api-version=${ADO_API}`,
      { method: 'POST', headers: { ...headers, 'Content-Type': 'application/octet-stream' }, body: file.content }, 'Azure DevOps');
    attachments.push({ name: file.name, url: uploaded.url });
    patch.push({ op: 'add', path: '/relations/-', value: { rel: 'AttachedFile', url: uploaded.url, attributes: { comment: 'Threatlint FP review report' } } });
  }
  patch.push({ op: 'add', path: '/fields/System.History', value: note.replaceAll('\n', '<br>') }, { op: 'add', path: '/fields/System.State', value: state });
  // Reason is process-specific; ADO picks the state's default reason when omitted.
  const updated = await request(fetchImpl, `${base}/_apis/wit/workitems/${id}?api-version=${ADO_API}`,
    { method: 'PATCH', headers: { ...headers, 'Content-Type': 'application/json-patch+json' }, body: JSON.stringify(patch) }, 'Azure DevOps');
  const stored = updated.fields?.['System.State'] ?? null;
  return { tracker: 'azure-devops', item: `ADO#${id}`, closed: stored === state, state: stored, attachments,
    url: `https://dev.azure.com/${encodeURIComponent(ado.organization)}/${encodeURIComponent(ado.project)}/_workitems/edit/${id}` };
}

// ── GitHub Advanced Security code scanning ───────────────────────────────────

function validateGithub(value) {
  const settings = value && typeof value === 'object' ? value : {};
  return { token: token(settings.token, 'GitHub') };
}

/**
 * Code-scanning alerts cannot hold files, so the report is attached to a tracking issue in the same
 * repository (the closest GitHub equivalent of an attachment), and the dismissal comment links it.
 */
async function dismissGithubAlert(settings, owner, repo, number, { note, files, reportName }, { fetchImpl = fetch } = {}) {
  const github = validateGithub(settings);
  if (!GH_NAME.test(owner) || !GH_NAME.test(repo) || !/^\d{1,10}$/.test(String(number))) throw new HttpError('Use a GitHub code-scanning alert reference like GHAS-owner/repo#12');
  const api = `https://api.github.com/repos/${owner}/${repo}`;
  const headers = { Authorization: `Bearer ${github.token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
  const alert = await request(fetchImpl, `${api}/code-scanning/alerts/${number}`, { headers }, 'GitHub');
  if (alert.state !== 'open') return { tracker: 'github', item: `GHAS-${owner}/${repo}#${number}`, closed: alert.state === 'dismissed', state: alert.state, attachments: [], url: alert.html_url, alreadyClosed: true };
  const markdown = files.find(file => file.type === 'text/markdown');
  const body = [`${note}`, '', `Code-scanning alert: ${alert.html_url}`, `Rule: ${alert.rule?.id || 'unknown'} (${alert.tool?.name || 'scanner'})`, '',
    `<details><summary>${reportName}</summary>`, '', String(markdown?.content || '').slice(0, 60_000), '', '</details>'].join('\n');
  const issue = await request(fetchImpl, `${api}/issues`, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: `${reportName.replace(/\.md$/, '')}: false positive (code-scanning #${number})`, body }) }, 'GitHub');
  const closedIssue = await request(fetchImpl, `${api}/issues/${issue.number}`, { method: 'PATCH', headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ state: 'closed', state_reason: 'completed' }) }, 'GitHub').catch(() => issue);
  const comment = `Closed by Threatlint as a false positive. Report: ${closedIssue.html_url || issue.html_url}`.slice(0, 280);
  const updated = await request(fetchImpl, `${api}/code-scanning/alerts/${number}`, { method: 'PATCH', headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ state: 'dismissed', dismissed_reason: 'false positive', dismissed_comment: comment }) }, 'GitHub');
  return { tracker: 'github', item: `GHAS-${owner}/${repo}#${number}`, closed: updated.state === 'dismissed', state: updated.state ?? null,
    attachments: [{ name: reportName, url: issue.html_url }], url: alert.html_url };
}

/** Every tracker item a finding references, from its Original finding field (then title/body). */
function trackerRefs(finding, field) {
  const refs = [];
  for (const text of [field(finding.body, 'Original finding|Original ID|Original finding ID'), finding.title]) {
    const value = String(text || '');
    const ado = ADO_REF.exec(value), ghas = GHAS_REF.exec(value), avit = /\bAVIT\d{4,12}\b/i.exec(value);
    if (avit) refs.push({ tracker: 'servicenow', id: avit[0].toUpperCase(), label: avit[0].toUpperCase() });
    if (ado) refs.push({ tracker: 'azure-devops', id: ado[1], label: `ADO-${ado[1]}` });
    if (ghas) refs.push({ tracker: 'github', owner: ghas[1], repo: ghas[2], id: ghas[3], label: `GHAS-${ghas[1]}-${ghas[2]}-${ghas[3]}` });
    if (refs.length) break;
  }
  return refs;
}

module.exports = { closeAdoWorkItem, dismissGithubAlert, trackerRefs, validateAdo, validateGithub, adoCodeSecurity, ADO_REF, GHAS_REF };
