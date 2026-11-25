'use strict';

const { HttpError } = require('../http.cjs');
const trackers = require('../issue-trackers.cjs');
const { createManagementStore, publicConnection, publicFinding, MAX_FINDINGS } = require('../integration-management.cjs');
const { hasFpEvidence, structure } = require('../finding-disposition.cjs');

function originalReference(body) {
  const references = [];
  for (const line of structure(body).split('\n')) {
    if (/^(?: {4}| {0,3}\t)/.test(line)) continue;
    const match = /^ {0,3}(?:[-*+]\s+)?(?:\*\*)?(?:Original finding|Original ID|Original finding ID|Ticket|Issue)(?:\*\*)?\s*:\s*(?:\*\*)?(.*)$/i.exec(line);
    if (match) references.push(match[1].trim().replace(/^`([^`]+)`$/, '$1'));
  }
  if (references.length !== 1) return '';
  return references[0];
}

function registerManagementRoutes(app, options = {}) {
  const stores = new Map(), integrations = options.integrations || {};
  const adapter = { fetchImpl: integrations.fetchImpl };
  const actor = req => options.actor ? options.actor(req) : 'local';
  async function storeFor(req) {
    const directory = options.scopeDirectory ? await options.scopeDirectory(req) : options.directory || null;
    const key = directory || 'memory';
    if (!stores.has(key)) stores.set(key, createManagementStore(directory));
    return stores.get(key);
  }
  function route(work) {
    return async (req, res) => {
      try { const store = await storeFor(req); res.json(await work(req, store)); }
      catch (error) { res.status(error instanceof HttpError ? error.status : 500).json({ error: error instanceof HttpError ? error.message : 'Integration management could not complete. Check server configuration.' }); }
    };
  }
  async function reviewedFinding(req, reportId, findingId, fp = false) {
    if (typeof reportId !== 'string' || !reportId || reportId.length > 100 || typeof findingId !== 'string' || !/^[A-Z][A-Z0-9]*-\d+$/.test(findingId)) throw new HttpError('Choose a saved report and finding');
    let located;
    if (options.resolveReport) located = await options.resolveReport(req, reportId);
    else {
      const result = options.reports?.find(reportId);
      if (result) located = { report: result.report, parsed: options.reports.read(result.report) };
    }
    if (!located?.report || located.report.id !== reportId || !Array.isArray(located.parsed?.findings)) throw new HttpError('Report not found in your current profile', 404);
    const matches = located.parsed.findings.filter(item => item.id === findingId);
    if (matches.length !== 1) throw new HttpError('Choose one unique finding from the saved report', 409);
    const finding = matches[0];
    if (fp && (located.report.agentId !== 'appsec-fp-reviewer' || finding.disposition !== 'FALSE POSITIVE' || finding.unverified || !hasFpEvidence(finding.body))) throw new HttpError('Closure requires a verified FALSE POSITIVE finding with Evidence and Verified Safe Behavior in a Finding Review report', 409);
    return { report: located.report, finding };
  }
  function issueIds(connection, raw) {
    const values = typeof raw === 'string' ? raw.split(/[\s,]+/).filter(Boolean) : raw;
    if (!Array.isArray(values) || !values.length || values.length > 100) throw new HttpError('Import between 1 and 100 issue IDs');
    return [...new Set(values.map(value => trackers.externalId(connection, value)))];
  }
  function findRow(store, id) {
    const row = store.state.findings.find(item => item.id === id);
    if (!row) throw new HttpError('Tracked finding not found', 404);
    return row;
  }
  function requireTicketActions(connection) {
    if (trackers.PROVIDERS.find(provider => provider.id === connection.provider)?.pullOnly) throw new HttpError('Use the dedicated AVIT workflow for ServiceNow ticket actions', 409);
  }
  async function serviceNowSource(req) {
    if (options.serviceNowSource) return options.serviceNowSource(req);
    try { const credentials = require('../servicenow.cjs').validateCredentials({}); return { instance: credentials.instance, available: true }; }
    catch { return { available: false }; }
  }
  async function serviceNowPage(req, connection, input) {
    if (options.serviceNowPage) {
      try { return await options.serviceNowPage(req, connection, input); }
      catch { throw new HttpError('ServiceNow issues could not be read. Check this profile’s Settings and filters.', 502); }
    }
    const serviceNow = require('../servicenow.cjs'), credentials = serviceNow.validateCredentials({});
    if (credentials.instance !== connection.instance) throw new HttpError('The current profile’s ServiceNow instance changed. Reload issue sources.', 409);
    try { return await serviceNow.fetchAvitPage(credentials, { ...input, fetchImpl: integrations.fetchImpl || fetch, signal: AbortSignal.timeout(25_000) }); }
    catch { throw new HttpError('ServiceNow issues could not be read. Check this profile’s Settings and filters.', 502); }
  }

  app.get('/api/management/issue-sources', route(async (req, store) => {
    const sources = store.listConnections().filter(item => item.kind === 'tracker' && item.provider !== 'servicenow-avit' && item.enabled)
      .map(item => ({ ...item, available: true }));
    let snow;
    try { snow = await serviceNowSource(req); } catch { snow = { available: false }; }
    sources.push({ id: 'servicenow-avit', provider: 'servicenow-avit', name: 'ServiceNow AVIT (current profile)', kind: 'tracker',
      credentialSource: 'servicenow-settings', pullOnly: true, available: snow.available === true,
      ...(snow.instance ? { instance: snow.instance } : {}), ...(snow.available ? {} : { error: 'Configure ServiceNow in this profile’s Settings to pull AVITs.' }) });
    return { sources, providers: trackers.PROVIDERS };
  }));
  app.post('/api/management/findings/pull', route((req, store) => store.mutate(async () => {
    const sources = req.body?.sources;
    if (!req.body || Object.keys(req.body).some(key => key !== 'sources') || !Array.isArray(sources) || !sources.length || sources.length > 10 ||
        sources.some(source => !source || typeof source !== 'object' || Array.isArray(source) || typeof source.connectionId !== 'string' || Object.keys(source).some(key => !['connectionId', 'cursor', 'filters'].includes(key))) ||
        new Set(sources.map(source => source.connectionId)).size !== sources.length) throw new HttpError('Choose between 1 and 10 unique issue sources');
    const pulled = [], results = [], signal = AbortSignal.timeout(60_000);
    for (const source of sources) {
      let connection;
      try {
        if (signal.aborted) throw new HttpError('Issue pull timed out; retry the remaining sources', 504);
        if (source.connectionId === 'servicenow-avit') {
          const saved = await serviceNowSource(req);
          if (!saved?.available || !saved.instance) throw new HttpError('Configure ServiceNow in this profile’s Settings before pulling AVITs', 409);
          connection = store.serviceNowConnection(saved.instance, { create: false });
        } else connection = store.connection(source.connectionId, { kind: 'tracker' });
        const filters = connection.provider === 'servicenow-avit' ? require('../servicenow.cjs').validateAggregateFilters(source.filters || {}) : trackers.pullFilters(connection, source.filters);
        const position = store.readPullCursor(connection, filters, source.cursor);
        const page = await trackers.pullIssues(connection, { filters, position, ...adapter, signal,
          serviceNowPage: async (selected, input) => serviceNowPage(req, selected, input) });
        if (new Set(page.issues.map(issue => issue.externalId)).size !== page.issues.length) throw new HttpError('Provider returned duplicate issues in this page', 502);
        const imported = store.transaction(() => {
          if (connection.provider === 'servicenow-avit') connection = store.serviceNowConnection(connection.instance);
          const findings = page.issues.map(issue => publicFinding(store.putFinding(connection, issue)));
          store.audit(actor(req), 'findings.pulled', `${connection.id}:${findings.length}`); return findings;
        });
        pulled.push(...imported);
        results.push({ connectionId: source.connectionId, provider: connection.provider, imported: imported.length,
          nextCursor: store.pullCursor(connection, filters, page.nextPosition) });
      } catch (error) {
        results.push({ connectionId: source.connectionId, ...(connection ? { provider: connection.provider } : {}), imported: 0, nextCursor: null,
          error: error instanceof HttpError ? error.message : 'Issue source could not be pulled. Previous issues were preserved.' });
      }
    }
    return { findings: pulled, sources: results };
  })));

  app.get('/api/management/connections', route(async (_req, store) => ({ connections: store.listConnections(), providers: trackers.PROVIDERS })));
  app.post('/api/management/connections', route((req, store) => store.mutate(async () => {
    const value = store.transaction(() => {
      const saved = store.upsert(req.body); store.audit(actor(req), 'connection.saved', saved.id); return saved;
    });
    return { connection: publicConnection(value), connections: store.listConnections() };
  })));
  app.delete('/api/management/connections/:id', route((req, store) => store.mutate(async () => {
    store.transaction(() => { store.remove(req.params.id); store.audit(actor(req), 'connection.removed', req.params.id); });
    return { ok: true, connections: store.listConnections() };
  })));
  app.post('/api/management/connections/:id/test', route((req, store) => store.mutate(async () => {
    const connection = store.connection(req.params.id, { enabled: false });
    const result = await trackers.testConnection(connection, adapter);
    store.audit(actor(req), 'connection.tested', connection.id); store.save(); return result;
  })));
  app.post('/api/management/connections/:id/activate', route((req, store) => store.mutate(async () => {
    const connection = store.connection(req.params.id, { kind: 'scm' });
    if (typeof options.activateSource !== 'function') throw new HttpError('Source activation is unavailable in this runtime', 503);
    const activated = await options.activateSource(req, { provider: connection.provider, token: connection.token, ...(connection.organization ? { organization: connection.organization } : {}) });
    store.audit(actor(req), 'source.activated', connection.id); store.save();
    return { ok: true, connection: activated.connection || activated };
  })));
  app.get('/api/management/findings', route(async (_req, store) => ({ findings: store.listFindings(), connections: store.listConnections() })));
  app.get('/api/management/audit', route(async (_req, store) => ({ audit: store.state.audit.slice().reverse() })));
  app.post('/api/management/findings/import', route((req, store) => store.mutate(async () => {
    const connection = store.connection(req.body?.connectionId, { kind: 'tracker' });
    requireTicketActions(connection);
    const ids = issueIds(connection, req.body?.ids);
    const errors = [], imported = [];
    for (const id of ids) {
      try {
        const issue = await trackers.getIssue(connection, id, adapter);
        // Recover an uncertain create only when its provider body contains the exact saved operation reference.
        const operation = store.state.operations.find(item => item.connectionId === connection.id && item.status !== 'completed' && issue.body.includes(`ThreatLint reference: ${item.reportId}/${item.findingId}`));
        const extra = operation ? { generated: true, reportId: operation.reportId, findingId: operation.findingId } : {};
        const row = store.putFinding(connection, issue, extra); imported.push(publicFinding(row));
        if (operation) { operation.status = 'completed'; operation.entryId = row.id; }
        store.save();
      } catch (error) { errors.push({ id, error: error instanceof HttpError ? error.message : 'Ticket import failed' }); }
    }
    store.audit(actor(req), 'findings.imported', `${connection.id}:${imported.length}`, errors.length ? 'partial' : 'success'); store.save();
    return { findings: imported, errors };
  })));
  app.post('/api/management/findings/create', route((req, store) => store.mutate(async () => {
    const connection = store.connection(req.body?.connectionId, { kind: 'tracker' });
    requireTicketActions(connection);
    const { report, finding } = await reviewedFinding(req, req.body?.reportId, req.body?.findingId);
    const previous = store.state.operations.find(item => item.connectionId === connection.id && item.reportId === report.id && item.findingId === finding.id);
    if (previous?.status === 'completed') return { finding: publicFinding(findRow(store, previous.entryId)), existing: true };
    if (previous) throw new HttpError('A previous ticket creation could not be confirmed. Check the provider for its ThreatLint reference and import that ticket to reconcile it before creating another.', 409);
    if (store.state.findings.length >= MAX_FINDINGS) throw new HttpError('The finding registry supports at most 10,000 tickets', 409);
    if (store.state.operations.length >= MAX_FINDINGS) throw new HttpError('The ticket operation registry supports at most 10,000 creation requests', 409);
    const operation = { connectionId: connection.id, reportId: report.id, findingId: finding.id, status: 'pending', timestamp: Date.now() };
    store.transaction(() => { store.state.operations.push(operation); });
    const body = [`ThreatLint reference: ${report.id}/${finding.id}`, `Report: ${report.title || report.label || report.agentId}`, `Finding: ${finding.id}`, `Severity: ${finding.severity || 'UNSPECIFIED'}`, '', finding.body].join('\n').slice(0, 100_000);
    try {
      const issue = await trackers.createIssue(connection, { title: finding.title, body }, { ...adapter,
        onCreated: externalId => { operation.externalId = externalId; store.save(); } });
      const row = store.putFinding(connection, issue, { generated: true, reportId: report.id, findingId: finding.id });
      operation.status = 'completed'; operation.entryId = row.id;
      store.audit(actor(req), 'finding.created', row.id); store.save();
      return { finding: publicFinding(row) };
    } catch (error) {
      if (error.safeToRetry === true) {
        store.state.operations = store.state.operations.filter(item => item !== operation);
        store.audit(actor(req), 'finding.create', `${connection.id}:${report.id}/${finding.id}`, 'rejected'); store.save(); throw error;
      }
      operation.status = 'unknown'; store.audit(actor(req), 'finding.create', `${connection.id}:${report.id}/${finding.id}`, 'unconfirmed'); store.save();
      throw new HttpError(`Ticket creation could not be confirmed.${operation.externalId ? ` The provider returned ticket ${operation.externalId}.` : ''} Check the provider before retrying; import the ticket containing this report’s ThreatLint reference to reconcile it.`, 502);
    }
  })));
  app.post('/api/management/findings/sync', route((req, store) => store.mutate(async () => {
    const connectionId = req.body?.connectionId;
    if (connectionId !== undefined) {
      const selected = store.connection(connectionId, { kind: 'tracker' });
      if (trackers.PROVIDERS.find(provider => provider.id === selected.provider)?.pullOnly) throw new HttpError('ServiceNow AVIT records are refreshed with Pull issues.', 409);
    }
    const candidates = store.state.findings.filter(row => !connectionId || row.connectionId === connectionId);
    const scoped = candidates.filter(row => !trackers.PROVIDERS.find(provider => provider.id === row.provider)?.pullOnly);
    const skippedReadOnly = candidates.length - scoped.length;
    const cursor = req.body?.cursor;
    if (cursor !== undefined && (typeof cursor !== 'string' || !scoped.some(row => row.id === cursor))) throw new HttpError('The sync cursor is invalid; start the sync again');
    const start = cursor ? scoped.findIndex(row => row.id === cursor) + 1 : 0;
    const rows = scoped.slice(start, start + 100);
    const errors = [], synced = [];
    for (const row of rows) {
      try {
        const connection = store.connection(row.connectionId, { kind: 'tracker' });
        synced.push(publicFinding(store.putFinding(connection, await trackers.getIssue(connection, row.externalId, adapter)))); store.save();
      } catch (error) { errors.push({ id: row.id, error: error instanceof HttpError ? error.message : 'Ticket sync failed' }); }
    }
    store.audit(actor(req), 'findings.synced', connectionId || 'all', errors.length ? 'partial' : 'success'); store.save();
    return { findings: synced, errors, nextCursor: start + rows.length < scoped.length ? rows.at(-1).id : null, total: scoped.length,
      skippedReadOnly, ...(skippedReadOnly ? { message: 'ServiceNow AVIT records are refreshed with Pull issues.' } : {}) };
  })));
  app.post('/api/management/findings/:id/close', route((req, store) => store.mutate(async () => {
    if (req.body?.confirm !== true) throw new HttpError('Confirm false-positive ticket closure before posting');
    const row = findRow(store, req.params.id), connection = store.connection(row.connectionId, { kind: 'tracker' });
    requireTicketActions(connection);
    const { report, finding } = await reviewedFinding(req, req.body?.reportId, req.body?.findingId, true);
    const original = originalReference(finding.body);
    // Native references include provider scope. Short repeated finding IDs and unscoped issue numbers never authorize closure.
    const exactOrigin = original === row.reviewReference || original === row.url || original === `[${row.reviewReference}](${row.url})`;
    const sameFinding = row.generated && row.reportId === report.id && row.findingId === finding.id;
    if (!sameFinding && !exactOrigin) throw new HttpError(`The review’s Original finding must identify exactly ${row.reviewReference} or its full ticket URL`, 409);
    const acknowledged = row.closureAcknowledgement?.reportId === report.id && row.closureAcknowledgement?.findingId === finding.id;
    const note = [`Closed as FALSE POSITIVE by ThreatLint.`, `Finding Review: ${report.id}; finding ${finding.id}.`, '', finding.body].join('\n').slice(0, 60_000);
    try {
      const issue = await trackers.closeIssue(connection, row.externalId, note, { ...adapter,
        onClosed: () => {
          row.closureAcknowledgement = { reportId: report.id, findingId: finding.id, actor: trackers.text(actor(req), 200), timestamp: Date.now() };
          store.save();
        } });
      if (issue.alreadyClosed && row.disposition !== 'FALSE POSITIVE' && !acknowledged) throw new HttpError('This ticket is already closed upstream; sync its status. ThreatLint has not reclassified it as a false positive.', 409);
      const closed = store.putFinding(connection, issue, { disposition: 'FALSE POSITIVE', reviewReportId: report.id, reviewFindingId: finding.id, closedAt: Date.now() });
      store.audit(actor(req), 'finding.closed-false-positive', row.id); store.save();
      return { finding: publicFinding(closed), verified: true };
    } catch (error) {
      store.audit(actor(req), 'finding.close-false-positive', row.id, 'unconfirmed'); store.save(); throw error;
    }
  })));
  return { stores, storeFor };
}

module.exports = { registerManagementRoutes };
