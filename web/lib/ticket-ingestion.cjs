'use strict';

/** Ticket ingestion shared by Finding triage and Metrics. Secrets never leave settings responses. */
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { HttpError, handle } = require('./http.cjs');
const { redactText } = require('./scan-import.cjs');

const LABELS = { github: 'GitHub Issues', jira: 'Jira', 'azure-devops': 'Azure DevOps Boards' };
const MAX_ITEMS = 10000;
const E = encodeURIComponent;
function spec(id) { if (!Object.hasOwn(LABELS, id)) throw new HttpError('Unknown issue tracker'); return LABELS[id]; }
function configFile(id) { spec(id); return path.join(process.env.THREATLINT_HOME || path.join(os.homedir(), '.threatlint'), `tracker-${id}.json`); }
function readConfig(id) { try { return JSON.parse(fs.readFileSync(configFile(id), 'utf8')); } catch { return {}; } }
function publicConfig(id) { const { token, ...config } = readConfig(id); return { id, label: spec(id), ...config, hasToken: !!token }; }
function validate(id, body, saved = {}) {
  spec(id);
  const token = body.token || saved.token;
  if (typeof token !== 'string' || !/^[\x21-\x7e]{8,4096}$/.test(token)) throw new HttpError('Enter an API token without whitespace');
  if (id === 'github') {
    if (!/^[\w.-]+\/[\w.-]+$/.test(body.repository || '') || body.repository.split('/').some(part => ['.', '..'].includes(part))) throw new HttpError('Enter a GitHub repository as owner/repository');
    return { token, repository: body.repository };
  }
  if (id === 'azure-devops') {
    if (!/^[a-z0-9][a-z0-9-]{0,99}$/i.test(body.organization || '') || !/^[\w .-]{1,100}$/.test(body.project || '') || ['.', '..'].includes(body.project)) throw new HttpError('Enter an ADO organization slug and project');
    return { token, organization: body.organization, project: body.project };
  }
  let url;
  try { url = new URL(body.url); } catch { throw new HttpError('Enter your Jira Cloud HTTPS URL'); }
  if (url.protocol !== 'https:' || !/^[a-z0-9-]+\.atlassian\.net$/i.test(url.hostname) || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new HttpError('Use a Jira Cloud origin such as https://team.atlassian.net');
  if (typeof body.email !== 'string' || !/^[^\s@:]+@[^\s@]+$/.test(body.email)) throw new HttpError('Enter the Jira account email');
  if (typeof body.query !== 'string' || !body.query.trim() || body.query.length > 2000) throw new HttpError('Enter a bounded JQL query for the security issues to sync');
  return { token, url: url.origin, email: body.email, query: body.query.trim() };
}
function richText(value) {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(richText).join('\n');
  return value && typeof value === 'object' ? [value.text, richText(value.content)].filter(Boolean).join(' ') : '';
}
function severity(text) {
  const match = /\b(critical|high|medium|moderate|low|info(?:rmational)?)\b/i.exec(text);
  return match ? match[1].toUpperCase().replace('MODERATE', 'MEDIUM').replace('INFORMATIONAL', 'INFO') : 'UNSPECIFIED';
}
function normalize(id, row, conn) {
  let item;
  if (id === 'github') {
    const labels = (row.labels || []).map(label => typeof label === 'string' ? label : label.name).join(' ');
    item = { id: `${conn.repository}#${row.number}`, title: row.title, description: row.body, timestamp: row.created_at,
      severity: severity(labels), disposition: row.state === 'closed' ? 'RESOLVED' : 'OPEN', workspace: conn.repository, labels };
  } else if (id === 'jira') {
    const f = row.fields || {};
    const labels = (f.labels || []).join(' ');
    item = { id: row.key, title: f.summary, description: richText(f.description), timestamp: f.created, severity: severity(`${f.priority?.name || ''} ${labels}`),
      disposition: f.status?.statusCategory?.key === 'done' ? 'RESOLVED' : 'OPEN', workspace: f.project?.key || row.key?.split('-')[0], labels };
  } else {
    const f = row.fields || {};
    item = { id: `ADO-${row.id}`, title: f['System.Title'], description: f['System.Description'] || f['Microsoft.VSTS.TCM.ReproSteps'], timestamp: f['System.CreatedDate'],
      severity: severity(f['Microsoft.VSTS.Common.Severity'] || ''), disposition: /^(closed|done|resolved|removed)$/i.test(f['System.State']) ? 'RESOLVED' : 'OPEN',
      workspace: `${conn.organization}/${conn.project}`, labels: f['System.Tags'] || '' };
  }
  const evidence = `${item.title || ''}\n${item.description || ''}\n${item.labels || ''}`;
  const scanner = /\b(semgrep|trivy|sonarqube)\b/i.exec(evidence)?.[1]?.toLowerCase() || 'unknown';
  return { ...item, title: redactText(item.title || item.id).slice(0, 300), description: redactText(item.description || '').slice(0, 12000),
    scanner, rule: /\bCWE-\d+\b|\bCVE-\d{4}-\d+\b/i.exec(evidence)?.[0] || 'n/a', hasEvidence: /\.[\w]+:\d+\b/.test(evidence) };
}
async function request(id, conn, route, { fetchImpl = fetch, signal, method = 'GET', body } = {}) {
  const base = id === 'github' ? 'https://api.github.com' : id === 'jira' ? conn.url : `https://dev.azure.com/${E(conn.organization)}/${E(conn.project)}`;
  const Authorization = id === 'github' ? `Bearer ${conn.token}` : `Basic ${Buffer.from(`${id === 'jira' ? conn.email : ''}:${conn.token}`).toString('base64')}`;
  let response;
  try { response = await fetchImpl(`${base}${route}`, { method, redirect: 'error', signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(30000)]) : AbortSignal.timeout(30000),
    headers: { Authorization, Accept: 'application/json', 'Content-Type': 'application/json', ...(id === 'github' ? { 'X-GitHub-Api-Version': '2022-11-28' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) }); }
  catch { throw new HttpError(`${spec(id)} request failed; check the connection and retry`, 502); }
  if (!response.ok) throw new HttpError(`${spec(id)} returned HTTP ${response.status}; check access and token permissions`, 502);
  try {
    if (response.body?.[Symbol.asyncIterator]) {
      const chunks = []; let length = 0;
      for await (const chunk of response.body) {
        length += chunk.length;
        if (length > 8 * 1024 * 1024) throw new Error('response limit');
        chunks.push(Buffer.from(chunk));
      }
      return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    }
    return await response.json();
  } catch { throw new HttpError(`${spec(id)} returned invalid or oversized JSON; previous snapshot preserved`, 502); }
}
function references(id, value) {
  const refs = [...new Set(String(value || '').split(/[\s,;]+/).filter(Boolean))];
  if (refs.length > 200) throw new HttpError('Review at most 200 explicit tickets per batch');
  const pattern = id === 'jira' ? /^[A-Z][A-Z0-9_]*-\d{1,12}$/ : id === 'github' ? /^#?[1-9]\d{0,11}$/ : /^(?:ADO-)?[1-9]\d{0,11}$/i;
  if (refs.some(ref => !pattern.test(ref))) throw new HttpError(id === 'jira' ? 'Use Jira keys such as SEC-123' : id === 'github' ? 'Use issue numbers from the configured repository, such as #123' : 'Use ADO work item IDs such as 123 or ADO-123');
  return refs;
}
async function fetchItems(id, { refs = '', connection, ...options } = {}) {
  const conn = connection || readConfig(id);
  if (!conn.token) throw new HttpError(`Configure ${spec(id)} in Settings first`, 412);
  const selected = references(id, refs);
  const rows = [];
  if (id === 'github') {
    const base = `/repos/${conn.repository.split('/').map(E).join('/')}/issues`;
    if (selected.length) {
      for (const ref of selected) { const row = await request(id, conn, `${base}/${ref.replace('#', '')}`, options); if (row.pull_request) throw new HttpError(`${ref} is a pull request; choose a GitHub issue`); rows.push(row); }
    } else {
      for (let page = 1; ; page++) {
        const result = await request(id, conn, `${base}?state=all&per_page=100&page=${page}`, options);
        if (!Array.isArray(result)) throw new HttpError('GitHub returned an unsupported issue list', 502);
        rows.push(...result.filter(row => !row.pull_request));
        if (result.length < 100) break;
        if (page >= 100) throw new HttpError('GitHub sync exceeded 10,000 records; narrow the repository scope', 413);
      }
    }
  } else if (id === 'jira') {
    if (selected.length) for (const ref of selected) rows.push(await request(id, conn, `/rest/api/3/issue/${E(ref)}`, options));
    else {
      let nextPageToken;
      const seen = new Set();
      for (;;) {
        const result = await request(id, conn, '/rest/api/3/search/jql', { ...options, method: 'POST', body: { jql: conn.query, maxResults: 100, fields: ['summary', 'description', 'priority', 'status', 'created', 'labels', 'project'], ...(nextPageToken ? { nextPageToken } : {}) } });
        if (!Array.isArray(result.issues)) throw new HttpError('Jira returned an unsupported issue list', 502);
        rows.push(...result.issues);
        if (result.isLast === true) break;
        nextPageToken = result.nextPageToken;
        if (!nextPageToken || seen.has(nextPageToken) || rows.length >= MAX_ITEMS) throw new HttpError('Jira pagination incomplete; previous snapshot preserved', 502);
        seen.add(nextPageToken);
      }
    }
  } else {
    let ids = selected.map(ref => Number(ref.replace(/^ADO-/i, '')));
    if (!ids.length) {
      const result = await request(id, conn, '/_apis/wit/wiql?api-version=7.1&$top=10001', { ...options, method: 'POST', body: { query: "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project ORDER BY [System.Id]" } });
      if (!Array.isArray(result.workItems)) throw new HttpError('ADO returned an unsupported work item list', 502);
      ids = result.workItems.map(row => row.id);
      if (ids.length > MAX_ITEMS) throw new HttpError('ADO project exceeds 10,000 items; use explicit IDs for triage', 413);
    }
    for (let offset = 0; offset < ids.length; offset += 200) {
      const batch = ids.slice(offset, offset + 200);
      const result = await request(id, conn, '/_apis/wit/workitemsbatch?api-version=7.1', { ...options, method: 'POST', body: { ids: batch, errorPolicy: 'fail' } });
      if (!Array.isArray(result.value) || result.value.length !== batch.length) throw new HttpError('ADO returned an incomplete batch; previous snapshot preserved', 502);
      rows.push(...result.value);
    }
  }
  return rows.map(row => normalize(id, row, conn));
}
function registerIssueTrackerRoutes(app, { scanImports, integrations = {} }) {
  app.get('/api/issue-trackers/:id/settings', handle(req => publicConfig(req.params.id)));
  app.post('/api/issue-trackers/:id/settings', handle(async req => {
    const id = req.params.id;
    const conn = validate(id, req.body || {}, readConfig(id));
    // A bounded read validates credentials before saving; no defect is changed.
    const route = id === 'github' ? `/repos/${conn.repository.split('/').map(E).join('/')}` : id === 'jira' ? '/rest/api/3/myself' : '/_apis/wit/workitemtypes?api-version=7.1';
    await request(id, conn, route, { fetchImpl: integrations.fetchImpl || fetch });
    const file = configFile(id);
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const temp = `${file}.${crypto.randomUUID()}.tmp`;
    fs.writeFileSync(temp, JSON.stringify(conn), { mode: 0o600 }); fs.renameSync(temp, file);
    return publicConfig(id);
  }));
  app.delete('/api/issue-trackers/:id/settings', handle(req => { fs.rmSync(configFile(req.params.id), { force: true }); return publicConfig(req.params.id); }));
  app.post('/api/issue-trackers/:id/triage', handle(async req => {
    const id = req.params.id;
    spec(id);
    if (!String(req.body?.references || '').trim()) throw new HttpError('Enter the ticket IDs to triage');
    const items = await fetchItems(id, { refs: req.body.references, fetchImpl: integrations.fetchImpl || fetch });
    const { accepted } = await scanImports.create({ filename: `${id}-tickets.json`, content: Buffer.from(JSON.stringify({ threatlintFindings: items, target: LABELS[id], tracker: id })),
      fields: { ...(req.body || {}), source: 'tickets' } });
    return accepted;
  }, { status: 201 }));
}
module.exports = { LABELS, readConfig, publicConfig, validate, normalize, fetchItems, references, registerIssueTrackerRoutes };
