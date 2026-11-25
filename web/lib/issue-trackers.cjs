'use strict';

const { HttpError } = require('./http.cjs');

const MAX_RESPONSE = 4 * 1024 * 1024;
const PROVIDERS = Object.freeze([
  { id: 'servicenow-avit', label: 'ServiceNow AVIT', kind: 'tracker', credentialSource: 'servicenow-settings', pullOnly: true, fields: [] },
  { id: 'jira', label: 'Jira Cloud', kind: 'tracker', fields: [
    { name: 'baseUrl', label: 'Jira site URL', type: 'url', required: true, placeholder: 'https://company.atlassian.net' },
    { name: 'username', label: 'Account email', required: true }, { name: 'project', label: 'Project key', required: true },
    { name: 'issueType', label: 'Issue type', placeholder: 'Task' },
    { name: 'closeTransitionId', label: 'False-positive close transition ID', placeholder: 'Workflow transition to a Done status' },
  ] },
  { id: 'azure-boards', label: 'Azure Boards', kind: 'tracker', fields: [
    { name: 'organization', label: 'Organization slug', required: true }, { name: 'project', label: 'Project', required: true },
    { name: 'issueType', label: 'Work item type', placeholder: 'Bug' }, { name: 'closeState', label: 'Closed state', placeholder: 'Closed' },
  ] },
  { id: 'github-issues', label: 'GitHub Issues', kind: 'tracker', fields: [
    { name: 'repository', label: 'Repository', required: true, placeholder: 'owner/repository' },
  ] },
  { id: 'github', label: 'GitHub', kind: 'scm', fields: [{ name: 'organization', label: 'Organization filter (optional)' }] },
  { id: 'azure-devops', label: 'Azure DevOps', kind: 'scm', fields: [{ name: 'organization', label: 'Organization slug', required: true }] },
]);

function text(value, max = 300) { return String(value ?? '').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '').slice(0, max); }
function input(value, label, max = 200, optional = false) {
  if (optional && (value === undefined || value === '')) return '';
  if (typeof value !== 'string' || !value.trim() || value.length > max || /[\p{Cc}\p{Cf}]/u.test(value)) throw new HttpError(`Enter a valid ${label}`);
  return value.trim();
}
function segment(value) { return encodeURIComponent(value); }
function validateConnection(raw, previous = null) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new HttpError('Enter connection settings');
  const provider = PROVIDERS.find(item => item.id === raw.provider);
  if (!provider || raw.kind !== provider.kind) throw new HttpError('Choose a supported connection type and provider');
  if (provider.credentialSource) throw new HttpError('ServiceNow issues use the current profile’s ServiceNow Settings');
  if (previous && (raw.provider !== previous.provider || raw.kind !== previous.kind)) throw new HttpError('Create a new connection to change its provider');
  const value = { provider: provider.id, kind: provider.kind, name: input(raw.name, 'connection name', 100),
    enabled: raw.enabled !== false, isDefault: raw.isDefault === true };
  for (const field of provider.fields) value[field.name] = input(raw[field.name], field.label, field.name === 'baseUrl' ? 300 : 200, !field.required);
  const token = raw.token === undefined || raw.token === '' ? previous?.token : raw.token;
  if (typeof token !== 'string' || !token || token.length > 8192 || /\s|[\p{Cc}\p{Cf}]/u.test(token)) throw new HttpError('Enter an API token without whitespace');
  value.token = token;
  if (value.organization && !/^[A-Za-z0-9][A-Za-z0-9-]{0,49}$/.test(value.organization)) throw new HttpError('Use an organization slug, not a URL');
  if (provider.id === 'jira') {
    let url; try { url = new URL(value.baseUrl); } catch { throw new HttpError('Enter the Jira Cloud HTTPS site URL'); }
    if (url.protocol !== 'https:' || !/^[a-z0-9][a-z0-9-]*\.atlassian\.net$/.test(url.hostname) || url.port || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new HttpError('Use a Jira Cloud site origin such as https://company.atlassian.net');
    value.baseUrl = url.origin;
    if (!/^[A-Z][A-Z0-9_]{1,39}$/.test(value.project)) throw new HttpError('Use the Jira project key');
    if (value.closeTransitionId && !/^\d{1,10}$/.test(value.closeTransitionId)) throw new HttpError('Use a numeric Jira close transition ID');
    value.issueType ||= 'Task';
  }
  if (provider.id === 'azure-boards') { value.issueType ||= 'Bug'; value.closeState ||= 'Closed'; }
  if (provider.id === 'github-issues' && !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(value.repository)) throw new HttpError('Use owner/repository for GitHub Issues');
  return value;
}
function endpoint(connection, suffix) {
  if (connection.provider === 'jira') return connection.baseUrl + '/rest/api/3' + suffix;
  if (connection.provider === 'github-issues') return 'https://api.github.com/repos/' + connection.repository.split('/').map(segment).join('/') + suffix;
  if (connection.provider === 'github') return 'https://api.github.com' + suffix;
  return 'https://dev.azure.com/' + segment(connection.organization) + suffix;
}
function headers(connection) {
  return { Accept: 'application/json', 'User-Agent': 'ThreatLint',
    Authorization: connection.provider === 'jira' ? `Basic ${Buffer.from(`${connection.username}:${connection.token}`).toString('base64')}`
      : connection.provider.startsWith('azure-') ? `Basic ${Buffer.from(`:${connection.token}`).toString('base64')}` : `Bearer ${connection.token}`,
    ...(connection.provider.startsWith('github') ? { 'X-GitHub-Api-Version': '2022-11-28' } : {}) };
}
async function responseJson(response) {
  if (Number(response.headers?.get?.('content-length') || 0) > MAX_RESPONSE) throw new HttpError('Provider response is too large', 502);
  let body = '';
  if (response.body?.getReader) {
    const reader = response.body.getReader(); const chunks = []; let size = 0;
    try { while (true) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > MAX_RESPONSE) throw new HttpError('Provider response is too large', 502); chunks.push(value); } }
    finally { reader.releaseLock(); }
    body = Buffer.concat(chunks).toString('utf8');
  } else if (typeof response.text === 'function') body = await response.text();
  else return response.json();
  if (Buffer.byteLength(body) > MAX_RESPONSE) throw new HttpError('Provider response is too large', 502);
  if (!body.trim()) return {};
  try { return JSON.parse(body); } catch { throw new HttpError('Provider returned an invalid JSON response', 502); }
}
async function request(connection, suffix, options = {}, fetchImpl = fetch) {
  let response;
  try { response = await fetchImpl(endpoint(connection, suffix), { method: options.method || 'GET',
    headers: { ...headers(connection), ...(options.body !== undefined ? { 'Content-Type': options.contentType || 'application/json' } : {}) },
    ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}), redirect: 'error',
    signal: options.signal ? AbortSignal.any([AbortSignal.timeout(15_000), options.signal]) : AbortSignal.timeout(15_000) }); }
  catch { throw new HttpError('Issue provider request failed or timed out. Check connection settings and provider availability.', 502); }
  if (!response.ok) throw Object.assign(new HttpError(`Issue provider returned HTTP ${response.status}. Check permissions and workflow settings.`, response.status === 401 || response.status === 403 ? 403 : 502), { upstreamStatus: response.status });
  const data = await responseJson(response);
  return options.includeHeaders ? { data, headers: response.headers } : data;
}
function adf(body) { return { version: 1, type: 'doc', content: [{ type: 'paragraph', content: [{ type: 'text', text: text(body, 100_000) || 'ThreatLint finding' }] }] }; }
function adfText(value) {
  if (!value || typeof value !== 'object') return text(value || '', 100_000);
  const parts = []; const visit = (node, depth) => { if (!node || depth > 20 || parts.length > 10000) return; if (node.type === 'text') parts.push(text(node.text, 10000)); for (const child of Array.isArray(node.content) ? node.content.slice(0, 10000) : []) visit(child, depth + 1); };
  visit(value, 0); return parts.join('\n').slice(0, 100_000);
}
function externalId(connection, value) {
  const id = String(value ?? '').trim();
  if (connection.provider === 'jira') { if (!new RegExp(`^${connection.project}-[1-9][0-9]{0,14}$`).test(id)) throw new HttpError('Use Jira issue keys in this connection’s project'); }
  else if (!/^[1-9][0-9]{0,14}$/.test(id)) throw new HttpError('Use positive issue or work item numbers');
  return id;
}
function issueSuffix(connection, id) {
  externalId(connection, id);
  if (connection.provider === 'jira') return `/issue/${segment(id)}?fields=summary,status,description,priority,labels,issuetype`;
  if (connection.provider === 'github-issues') return `/issues/${id}`;
  return `/${segment(connection.project)}/_apis/wit/workitems/${id}?api-version=7.1`;
}
function normalized(connection, row) {
  if (!row || typeof row !== 'object') throw new HttpError('Provider returned an invalid ticket', 502);
  if (connection.provider === 'jira') {
    const id = externalId(connection, row.key); const fields = row.fields || {};
    return { externalId: id, title: text(fields.summary), state: text(fields.status?.name, 100), closed: fields.status?.statusCategory?.key === 'done',
      url: `${connection.baseUrl}/browse/${segment(id)}`, body: adfText(fields.description), severity: text(fields.priority?.name, 50) || 'UNSPECIFIED', issueType: text(fields.issuetype?.name, 200) };
  }
  if (connection.provider === 'github-issues') {
    if (row.pull_request) throw new HttpError('A pull request cannot be imported as a finding', 400);
    const id = externalId(connection, row.number);
    if (row.repository_url !== undefined && (typeof row.repository_url !== 'string' || row.repository_url.toLowerCase() !== ('https://api.github.com/repos/' + connection.repository).toLowerCase())) throw new HttpError('GitHub returned an issue outside this repository', 502);
    if (!['open', 'closed'].includes(row.state)) throw new HttpError('GitHub returned an invalid issue state', 502);
    return { externalId: id, title: text(row.title), state: row.state, closed: row.state === 'closed',
      url: `https://github.com/${connection.repository}/issues/${id}`, body: text(row.body, 100_000), severity: 'UNSPECIFIED' };
  }
  const id = externalId(connection, row.id), fields = row.fields || {};
  // Item IDs are organization-wide. Verify the project before returning or updating one.
  if (typeof fields['System.TeamProject'] !== 'string' || fields['System.TeamProject'].toLowerCase() !== connection.project.toLowerCase()) throw new HttpError('Azure Boards returned a work item outside this project', 502);
  return { externalId: id, title: text(fields['System.Title']), state: text(fields['System.State'], 100),
    closed: String(fields['System.State']).toLowerCase() === connection.closeState.toLowerCase(),
    url: `https://dev.azure.com/${segment(connection.organization)}/${segment(connection.project)}/_workitems/edit/${id}`,
    body: text(fields['System.Description'], 100_000), severity: 'UNSPECIFIED', revision: row.rev, issueType: text(fields['System.WorkItemType'], 200) };
}
async function getIssue(connection, id, { fetchImpl } = {}) {
  if (connection.provider === 'servicenow-avit') throw new HttpError('Use Pull issues to refresh ServiceNow AVIT records', 409);
  const expected = externalId(connection, id), issue = normalized(connection, await request(connection, issueSuffix(connection, expected), {}, fetchImpl));
  if (issue.externalId !== expected) throw new HttpError('Provider returned an unexpected ticket identity', 502);
  return issue;
}
async function testConnection(connection, { fetchImpl } = {}) {
  if (connection.provider === 'servicenow-avit') throw new HttpError('Check the current profile’s ServiceNow connection in Settings', 409);
  let suffix;
  if (connection.provider === 'jira') suffix = `/project/${segment(connection.project)}`;
  else if (connection.provider === 'github-issues') suffix = '';
  else if (connection.provider === 'github') suffix = '/user';
  else suffix = connection.provider === 'azure-boards' ? `/_apis/projects/${segment(connection.project)}?api-version=7.1` : '/_apis/projects?$top=1&api-version=7.1';
  await request(connection, suffix, {}, fetchImpl);
  return { ok: true };
}
async function createIssue(connection, finding, { fetchImpl, onCreated } = {}) {
  if (connection.provider === 'servicenow-avit') throw new HttpError('ServiceNow AVIT is a read-only issue source; use the dedicated AVIT workflow', 409);
  const title = text(`[ThreatLint] ${finding.title}`, 250), body = finding.body;
  let response;
  try {
    if (connection.provider === 'jira') response = await request(connection, '/issue', { method: 'POST', body: { fields: { project: { key: connection.project }, summary: title, description: adf(body), issuetype: { name: connection.issueType }, labels: ['threatlint'] } } }, fetchImpl);
    else if (connection.provider === 'github-issues') response = await request(connection, '/issues', { method: 'POST', body: { title, body } }, fetchImpl);
    else response = await request(connection, `/${segment(connection.project)}/_apis/wit/workitems/$${segment(connection.issueType)}?api-version=7.1`, { method: 'POST', contentType: 'application/json-patch+json', body: [
      { op: 'add', path: '/fields/System.Title', value: title }, { op: 'add', path: '/fields/System.Description', value: `<pre>${escapeHtml(body)}</pre>` }, { op: 'add', path: '/fields/System.Tags', value: 'ThreatLint' },
    ] }, fetchImpl);
  } catch (error) {
    // An explicit client rejection of the POST did not create a ticket. Readback errors below remain uncertain.
    if ([400, 401, 403, 404, 405, 409, 422, 429].includes(error.upstreamStatus)) error.safeToRetry = true;
    throw error;
  }
  const id = externalId(connection, connection.provider === 'jira' ? response.key : connection.provider === 'github-issues' ? response.number : response.id);
  if (onCreated) await onCreated(id);
  return getIssue(connection, id, { fetchImpl });
}
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
async function closeIssue(connection, id, note, { fetchImpl, onClosed } = {}) {
  if (connection.provider === 'servicenow-avit') throw new HttpError('Use the dedicated AVIT review workflow to update ServiceNow', 409);
  const before = await getIssue(connection, id, { fetchImpl });
  if (before.closed) return { ...before, alreadyClosed: true };
  if (connection.provider === 'jira') {
    if (!connection.closeTransitionId) throw new HttpError('Configure the Jira false-positive close transition ID before closing tickets', 409);
    const transitions = await request(connection, `/issue/${segment(id)}/transitions`, {}, fetchImpl);
    const transition = Array.isArray(transitions.transitions) && transitions.transitions.find(item => String(item.id) === connection.closeTransitionId);
    if (!transition || transition.to?.statusCategory?.key !== 'done') throw new HttpError('The configured Jira transition must be available and lead to a Done status', 409);
    await request(connection, `/issue/${segment(id)}/transitions`, { method: 'POST', body: { transition: { id: connection.closeTransitionId }, update: { comment: [{ add: { body: adf(note) } }] } } }, fetchImpl);
  } else if (connection.provider === 'github-issues') {
    await request(connection, `/issues/${id}/comments`, { method: 'POST', body: { body: note } }, fetchImpl);
    await request(connection, `/issues/${id}`, { method: 'PATCH', body: { state: 'closed', state_reason: 'not_planned' } }, fetchImpl);
  } else {
    if (!Number.isSafeInteger(before.revision)) throw new HttpError('Azure Boards did not return the work item revision', 502);
    await request(connection, `/${segment(connection.project)}/_apis/wit/workitems/${id}?api-version=7.1`, { method: 'PATCH', contentType: 'application/json-patch+json', body: [
      { op: 'test', path: '/rev', value: before.revision }, { op: 'add', path: '/fields/System.History', value: escapeHtml(note) }, { op: 'add', path: '/fields/System.State', value: connection.closeState },
    ] }, fetchImpl);
  }
  // Record only an acknowledged closing mutation. A failed or merely attempted request cannot
  // justify reclassifying a ticket that a later read finds closed by somebody else.
  if (onClosed) await onClosed();
  const after = await getIssue(connection, id, { fetchImpl });
  if (!after.closed) throw new HttpError('The provider did not confirm closure. Check its workflow or approval rules.', 409);
  return after;
}

const PAGE_SIZE = 100;
function pullFilters(connection, raw = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(key => !['state', 'issueType'].includes(key))) throw new HttpError('Use the supported issue state and type filters');
  const state = raw.state === undefined ? 'all' : raw.state;
  if (!['all', 'open', 'closed'].includes(state)) throw new HttpError('Choose all, open or closed issues');
  if (connection.provider === 'github-issues' && raw.issueType !== undefined) throw new HttpError('GitHub Issues does not use a work item type filter');
  return { state, ...(['jira', 'azure-boards'].includes(connection.provider) ? { issueType: input(raw.issueType ?? connection.issueType, 'issue type', 200) } : {}) };
}
function wiqlString(value) {
  // WIQL accepts either quote delimiter. Never splice an unquoted user expression.
  if (!value.includes("'")) return "'" + value + "'";
  if (!value.includes('"')) return '"' + value + '"';
  throw new HttpError('Azure project and work item type names cannot contain both quote styles');
}
function serviceNowIssue(connection, row) {
  if (!row || !/^AVIT\d{7,15}$/.test(row.number || '') || !/^[a-f0-9]{32}$/i.test(row.id || '')) throw new HttpError('ServiceNow returned an invalid AVIT identity', 502);
  const expected = connection.instance + '/nav_to.do?uri=sn_vul_app_vulnerable_item.do%3Fsys_id%3D' + row.id;
  if (row.url !== expected) throw new HttpError('ServiceNow returned an unexpected AVIT destination', 502);
  const state = text(row.state, 100);
  return { externalId: row.number, title: text(row.title), state, closed: /^(?:closed|resolved)$/i.test(state),
    url: expected, severity: text(row.riskRating, 50) || 'UNSPECIFIED', body: '', issueType: 'AVIT' };
}
/** One read-only page. All URLs are constructed from the saved scope, never a provider-supplied URL. */
async function pullIssues(connection, { filters, position = null, fetchImpl, signal, serviceNowPage } = {}) {
  if (connection.provider === 'servicenow-avit') {
    if (typeof serviceNowPage !== 'function') throw new HttpError('ServiceNow issue pull is unavailable in this runtime', 503);
    const selected = require('./servicenow.cjs').validateAggregateFilters(filters || {});
    if (position !== null && (!Number.isSafeInteger(position) || position < 0 || position > 10000000)) throw new HttpError('Invalid ServiceNow issue cursor');
    const page = await serviceNowPage(connection, { filters: selected, offset: position || 0 });
    if (!page || !Array.isArray(page.items) || page.items.length > PAGE_SIZE || (page.nextOffset !== null && (!Number.isSafeInteger(page.nextOffset) || page.nextOffset <= (position || 0) || page.nextOffset > 10000000))) throw new HttpError('ServiceNow returned an invalid issue page', 502);
    return { issues: page.items.map(row => serviceNowIssue(connection, row)), nextPosition: page.nextOffset, filters: selected };
  }
  const selected = pullFilters(connection, filters);
  if (connection.provider === 'jira') {
    if (position !== null && (typeof position !== 'string' || !position || position.length > 2048 || /[\p{Cc}\p{Cf}]/u.test(position))) throw new HttpError('Invalid Jira issue cursor');
    const quote = value => '"' + value.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
    const state = selected.state === 'all' ? '' : selected.state === 'closed' ? ' AND statusCategory = Done' : ' AND statusCategory != Done';
    const page = await request(connection, '/search/jql', { method: 'POST', signal, body: {
      jql: `project = ${quote(connection.project)} AND issuetype = ${quote(selected.issueType)}${state} ORDER BY key ASC`,
      maxResults: PAGE_SIZE, fields: ['summary', 'status', 'description', 'priority', 'issuetype'], ...(position ? { nextPageToken: position } : {}) } }, fetchImpl);
    if (!Array.isArray(page.issues) || page.issues.length > PAGE_SIZE || typeof page.isLast !== 'boolean' || (page.isLast === false && !page.nextPageToken)) throw new HttpError('Jira returned an invalid issue page', 502);
    for (const row of page.issues) if (![row.fields?.issuetype?.name, row.fields?.issuetype?.id].some(value => typeof value === 'string' && value.toLowerCase() === selected.issueType.toLowerCase())) throw new HttpError('Jira returned an issue outside the selected issue type', 502);
    const next = page.isLast === true ? null : page.nextPageToken ?? null;
    if (next !== null && (typeof next !== 'string' || !next || next.length > 2048 || next === position || /[\p{Cc}\p{Cf}]/u.test(next))) throw new HttpError('Jira returned an invalid next-page token', 502);
    return { issues: page.issues.map(row => normalized(connection, row)), nextPosition: next, filters: selected };
  }
  if (connection.provider === 'github-issues') {
    const pageNumber = position === null ? 1 : position;
    if (!Number.isSafeInteger(pageNumber) || pageNumber < 1 || pageNumber > 100000) throw new HttpError('Invalid GitHub issue cursor');
    const query = new URLSearchParams({ state: selected.state, sort: 'created', direction: 'asc', per_page: String(PAGE_SIZE), page: String(pageNumber) });
    const { data: rows, headers: responseHeaders } = await request(connection, '/issues?' + query, { signal, includeHeaders: true }, fetchImpl);
    if (!Array.isArray(rows) || rows.length > PAGE_SIZE) throw new HttpError('GitHub returned an invalid issue page', 502);
    const hasNext = /<[^>]+>\s*;\s*rel="next"/.test(responseHeaders?.get?.('link') || '') || rows.length === PAGE_SIZE;
    return { issues: rows.filter(row => !row.pull_request).map(row => normalized(connection, row)), nextPosition: hasNext ? pageNumber + 1 : null, filters: selected };
  }
  if (connection.provider !== 'azure-boards') throw new HttpError('Choose a supported issue source');
  if (position !== null && (!Number.isSafeInteger(position) || position < 1 || position > 2147483647)) throw new HttpError('Invalid Azure work item cursor');
  const state = selected.state === 'all' ? '' : ` AND [System.State] ${selected.state === 'closed' ? '=' : '<>'} ${wiqlString(connection.closeState)}`;
  const query = `SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = ${wiqlString(connection.project)} AND [System.WorkItemType] = ${wiqlString(selected.issueType)}${state}${position ? ` AND [System.Id] > ${position}` : ''} ORDER BY [System.Id] ASC`;
  const page = await request(connection, `/${segment(connection.project)}/_apis/wit/wiql?$top=${PAGE_SIZE + 1}&api-version=7.1`, { method: 'POST', signal, body: { query } }, fetchImpl);
  if (!Array.isArray(page.workItems) || page.workItems.length > PAGE_SIZE + 1) throw new HttpError('Azure Boards returned an invalid work item page', 502);
  const ids = page.workItems.map(row => row.id);
  if (ids.some((id, index) => !Number.isSafeInteger(id) || id < 1 || id > 2147483647 || (index ? id <= ids[index - 1] : position && id <= position))) throw new HttpError('Azure Boards returned invalid or repeated work item IDs', 502);
  const selectedIds = ids.slice(0, PAGE_SIZE);
  if (!selectedIds.length) return { issues: [], nextPosition: null, filters: selected };
  if (page.asOf !== undefined && (typeof page.asOf !== 'string' || page.asOf.length > 64 || !Number.isFinite(Date.parse(page.asOf)))) throw new HttpError('Azure Boards returned an invalid query timestamp', 502);
  const rows = await request(connection, `/${segment(connection.project)}/_apis/wit/workitemsbatch?api-version=7.1`, { method: 'POST', signal, body: { ids: selectedIds, errorPolicy: 'Fail', fields: ['System.Id', 'System.TeamProject', 'System.WorkItemType', 'System.Title', 'System.State', 'System.Description'], ...(typeof page.asOf === 'string' ? { asOf: page.asOf } : {}) } }, fetchImpl);
  if (!Array.isArray(rows.value) || rows.value.length !== selectedIds.length || new Set(rows.value.map(row => row.id)).size !== selectedIds.length || rows.value.some(row => !selectedIds.includes(row.id) || typeof row.fields?.['System.WorkItemType'] !== 'string' || row.fields['System.WorkItemType'].toLowerCase() !== selected.issueType.toLowerCase())) throw new HttpError('Azure Boards returned work items outside the selected scope', 502);
  return { issues: rows.value.map(row => normalized(connection, row)), nextPosition: ids.length > PAGE_SIZE ? selectedIds.at(-1) : null, filters: selected };
}

module.exports = { PROVIDERS, validateConnection, externalId, testConnection, getIssue, createIssue, closeIssue, text, pullFilters, pullIssues };
