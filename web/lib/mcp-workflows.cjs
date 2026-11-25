'use strict';

const { AGENTS } = require('./agents.cjs');

function registerWorkflowTools({ tool, z, id, workspace, securityScanner, reviews, scanImports, designInputs, runtime, history, conversations, scannerBatch, avitRuns, integrations = {} }) {
  const mutate = { readOnly: false };
  const external = { readOnly: false, openWorld: true };
  const confirm = { confirm: z.literal(true) };
  const provider = z.enum(['claude', 'claude-code', 'bedrock', 'daybreak', 'daybreak-bedrock', 'openai', 'copilot', 'codex', 'lmstudio']);
  const options = z.record(z.unknown()).optional().describe('Additional existing Workbench request fields, such as provider credentials, ensemble consent, or integration options. Validated by the shared service; never overrides explicit IDs. Prefer environment credentials.');
  const execution = z.object({
    mode: z.enum(['auto', 'sequential']).optional(), maxConcurrency: z.number().int().min(1).max(8).optional(),
    roleWorkers: z.number().int().min(1).max(4).optional(), maxModelRuns: z.number().int().min(1).max(64).optional(),
    roleWorkerCounts: z.record(z.number().int().min(1).max(4)).optional(), dependencies: z.record(z.array(id)).optional(),
  }).strict().optional();
  const model = { provider: provider.optional(), model: z.string().max(200).optional(), options };
  const paging = { offset: z.number().int().min(0).optional(), limit: z.number().int().min(1).max(100).optional() };
  const page = (items, { offset = 0, limit = 25 }) => ({ items: items.slice(offset, offset + limit), total: items.length,
    nextOffset: offset + limit < items.length ? offset + limit : null });
  if (avitRuns) {
    const snapshot = () => {
      const subscriber = () => {};
      const result = avitRuns.attach(subscriber);
      avitRuns.detach(subscriber);
      return result;
    };
    const selected = runId => {
      const run = snapshot();
      if (!run.runId || run.runId !== runId) throw new Error('Finding triage run not found in this profile');
      return run;
    };
    tool('start_avit_review', 'Review ServiceNow AVIT/SCTASK/ISST references and WRITE BACK results using the existing batch workflow: attach reports, close proven false positives, tune eligible rules and finalize tasks. Optional fix PRs require createFixPr. Explicit write-back authorization is mandatory.', {
      references: z.string().min(1).max(64 * 1024), ...model,
      createFixPr: z.boolean().default(false), confirmWriteback: z.literal(true), ...confirm,
    }, ({ references, options, confirmWriteback, confirm, createFixPr, ...input }) => ({
      runId: avitRuns.start({ ...options, ...input, avits: references, createFixPr }),
    }), { readOnly: false, destructive: true, openWorld: true });
    tool('get_avit_review', 'Poll the current or most recent profile-wide ServiceNow batch. Event offsets are stable; only one batch is retained.', {
      runId: id.optional(), ...paging,
    }, ({ runId, ...input }) => {
      const run = runId ? selected(runId) : snapshot();
      return { runId: run.runId, active: run.active, ...page(run.events, input) };
    });
    tool('cancel_avit_review', 'Stop the selected ServiceNow batch; already-admitted external writes and cleanup drain before completion.', {
      runId: id, ...confirm,
    }, ({ runId }) => { selected(runId); return { accepted: avitRuns.cancel() }; }, mutate);
  }
  // Binding maps are owned by the service lifetime, never by a short-lived HTTP protocol server.
  if (securityScanner) {
    const scanFor = (sessionId, scanId) => {
      workspace(sessionId); const scan = securityScanner.get(scanId);
      if (scan.sessionId !== sessionId) throw new Error('Scan not found in this workspace');
      return scan;
    };
    tool('start_scan', 'Start a repository security scan; select optional installed Semgrep/Trivy engines and poll get_scan.', {
      sessionId: id, engines: z.array(z.enum(['semgrep', 'trivy'])).max(2).optional(), ...confirm,
    }, ({ sessionId, engines }) => { workspace(sessionId); return securityScanner.start({ sessionId, engines }); }, external);
    tool('list_scans', 'List scans in the selected workspace, with bounded pagination.', { sessionId: id, ...paging }, ({ sessionId, ...input }) => {
      workspace(sessionId); return page(securityScanner.list(sessionId).map(({ id, sessionId, status, startedAt, finishedAt, coverage, requestedEngines, findings }) =>
        ({ id, sessionId, status, startedAt, finishedAt, coverage, requestedEngines, findingCount: findings?.length || 0 })), input);
    });
    tool('get_scan', 'Read a workspace scan, or paginate its findings for large scans.', {
      sessionId: id, scanId: id, section: z.literal('findings').optional(), ...paging,
    }, ({ sessionId, scanId, section, ...input }) => {
      const scan = scanFor(sessionId, scanId);
      return section ? { scanId, section, ...page(scan.findings || [], input) } : scan;
    });
    tool('cancel_scan', 'Cancel a scan in the selected workspace.', { sessionId: id, scanId: id, ...confirm }, ({ sessionId, scanId }) => {
      scanFor(sessionId, scanId); return securityScanner.cancel(scanId);
    }, mutate);
    tool('propose_fix', 'Prepare an advisory diff bound to a completed scan and finding; does not edit source.', { sessionId: id, scanId: id, findingId: id, ...confirm }, async ({ sessionId, scanId, findingId }) => {
      scanFor(sessionId, scanId); return securityScanner.propose(scanId, { findingId });
    }, mutate);
    tool('apply_fix', 'Apply a reviewed supported fix to its bound source snapshot, then rescan. Explicit confirmation is required; this edits source.', {
      sessionId: id, proposalId: id, ...confirm,
    }, ({ sessionId, proposalId }) => {
      workspace(sessionId);
      return securityScanner.apply(proposalId, { sessionId, confirm: true });
    }, { readOnly: false, destructive: true, openWorld: true });
  }
  if (reviews) {
    tool('start_review', 'Start a background specialist review using a configured server-side provider. Returns a job ID; poll get_review. All source changes remain advisory.', {
      sessionId: id, agentIds: z.array(z.enum(Object.keys(AGENTS))).min(1).max(Object.keys(AGENTS).length),
      target: z.string().max(12000).optional(), ...model, execution,
      attachment: z.object({ name: z.string().max(240), content: z.string().max(5 * 1024 * 1024) }).strict().optional(),
      designInputsId: id.optional(), continueOnError: z.boolean().optional(), ...confirm,
    }, ({ options, confirm, ...input }) => { workspace(input.sessionId); return reviews.start({ ...options, ...input }); }, external);
    tool('list_reviews', 'List background review jobs in this workspace.', { sessionId: id, ...paging }, ({ sessionId, ...input }) => {
      workspace(sessionId); return reviews.list(sessionId, input);
    });
    tool('get_review', 'Poll a background job and bounded progress events. Pass after=nextCursor to continue; saved report IDs are returned on completion.', {
      sessionId: id, reviewId: id, after: z.number().int().min(0).optional(), limit: z.number().int().min(1).max(100).optional(),
    }, ({ sessionId, reviewId, ...input }) => { workspace(sessionId); return reviews.get(sessionId, reviewId, input); });
    tool('cancel_review', 'Stop a workspace review job and drain running provider work.', { sessionId: id, reviewId: id, ...confirm }, ({ sessionId, reviewId }) => {
      workspace(sessionId); return reviews.cancel(sessionId, reviewId);
    }, mutate);
    tool('start_scanner_review', 'Review selected DefectDojo or SonarQube findings with the existing scanner-review workflow. Poll get_review.', {
      sessionId: id, tool: z.enum(['dojo', 'sonar']), references: z.string().max(12000).optional(),
      filter: z.record(z.unknown()).optional().describe('Scanner-specific filter; a filter or explicit references is required by the shared service.'), ...model, options, ...confirm,
    }, ({ options, confirm, ...input }) => { workspace(input.sessionId); return reviews.start({ ...options, ...input }, 'scanner_review'); }, external);
    if (conversations) {
      tool('ask_question', 'Ask the security conversation assistant about a workspace or report; poll get_review, then get_conversation.', {
        sessionId: id, question: z.string().min(1).max(8000), conversationId: id.optional(), reportId: id.optional(), ...model, ...confirm,
      }, ({ options, confirm, reportId, ...input }) => {
        const session = workspace(input.sessionId);
        if (reportId && !session.reports?.some(report => report.id === reportId)) throw new Error('Report not found in this workspace');
        return reviews.start({ ...options, ...input, ...(reportId ? { context: { type: 'report', reportId } } : {}) }, 'conversation');
      }, external);
      tool('list_conversations', 'List saved conversations in a workspace.', { sessionId: id, ...paging }, ({ sessionId, ...input }) => {
        workspace(sessionId); return page(conversations.list(sessionId), input);
      });
      tool('get_conversation', 'Read one workspace conversation and its final answers.', { sessionId: id, conversationId: id }, ({ sessionId, conversationId }) => {
        workspace(sessionId); const item = conversations.get(conversationId);
        if (item.sessionId !== sessionId) throw new Error('Conversation not found in this workspace');
        return item;
      });
    }
  }
  if (scannerBatch) {
    tool('post_scanner_review', 'Post a completed Finding Review to its exact DefectDojo or SonarQube reference. Requires explicit confirmation and the existing evidence/tuning gates.', {
      sessionId: id, reportId: id, tool: z.enum(['dojo', 'sonar']), reference: z.string().min(1).max(200),
      reportUrl: z.string().url().max(4096).optional(), ...confirm,
    }, ({ sessionId, reportId, tool, reference, reportUrl }) => {
      if (!workspace(sessionId).reports?.some(report => report.id === reportId)) throw new Error('Report not found in this workspace');
      return scannerBatch.resolve(tool, { reportId, reference, reportUrl, confirm: true });
    }, { readOnly: false, destructive: true, openWorld: true });
  }
  if (designInputs) {
    tool('upload_design_inputs', 'Upload supporting diagrams, documents, specifications or images as base64; use the returned ID in start_review.', {
      files: z.array(z.object({ name: z.string().min(1).max(240), content: z.string().min(1) }).strict()).min(1).max(10), ...confirm,
    }, ({ files }) => designInputs.create(require('./routes/design-inputs.cjs').parseFiles({ files })), mutate);
    tool('remove_design_inputs', 'Forget a temporary design-input bundle.', { designInputsId: id, ...confirm }, ({ designInputsId }) => ({ removed: designInputs.remove(designInputsId) }), { readOnly: false, destructive: true });
  }
  if (scanImports) {
    tool('import_scan_report', 'Import a supported scanner report (including SARIF, JSON or PDF) as base64. Optionally review against a workspace using configured provider settings. Poll get_import.', {
      filename: z.string().min(1).max(240), content: z.string().min(1), sessionId: id.optional(), source: z.string().max(100).optional(), ...model, ...confirm,
    }, async ({ filename, content, sessionId, source, options, confirm, ...input }) => {
      if (sessionId) workspace(sessionId);
      const fields = { ...options, ...input, ...(source ? { source } : {}), ...(sessionId ? { workspaceId: sessionId } : {}) };
      const upload = require('./routes/scan-import.cjs').parseJsonUpload({ ...fields, filename, content });
      return (await scanImports.create(upload)).accepted;
    }, external);
    tool('list_imports', 'List scan-report import jobs in this profile.', paging, input => page(scanImports.list(), input));
    tool('get_import', 'Poll a scan-report import and read its report ID and triage status.', { importId: id }, ({ importId }) => scanImports.get(importId));
    tool('post_import_review', 'Post a completed import review to ServiceNow, DefectDojo or SonarQube after explicit authorization. Existing evidence and mapping checks apply.', {
      importId: id, destination: z.enum(['servicenow', 'dojo', 'sonar']), options, ...confirm,
    }, ({ importId, destination, options }) => destination === 'servicenow'
      ? scanImports.post(importId, { ...options, confirm: true }) : scanImports.postScanner(importId, { ...options, tool: destination, confirm: true }), { readOnly: false, destructive: true, openWorld: true });
    tool('triage_tickets', 'Pull explicit Jira, Azure Boards or GitHub issue references into the shared background findings-triage workflow.', {
      tracker: z.enum(['github', 'jira', 'azure-devops']), references: z.string().min(1).max(12000), sessionId: id.optional(), ...model, ...confirm,
    }, async ({ tracker, references, sessionId, options, confirm, ...input }) => {
      if (sessionId) workspace(sessionId);
      const tickets = require('./ticket-ingestion.cjs');
      const items = await tickets.fetchItems(tracker, { refs: references, fetchImpl: integrations.fetchImpl || fetch });
      return (await scanImports.create({ filename: `${tracker}-tickets.json`, content: Buffer.from(JSON.stringify({ threatlintFindings: items, target: tickets.LABELS[tracker], tracker })),
        fields: { ...options, ...input, source: 'tickets', ...(sessionId ? { workspaceId: sessionId } : {}) } })).accepted;
    }, external);
  }
  if (runtime) {
    tool('start_runtime_scan', 'Start an explicitly authorized bounded runtime scan of a target or source sandbox. Shared authorization and confirmBuild checks still apply.', {
      config: z.record(z.unknown()), ...confirm,
    }, async ({ config }) => { const result = await runtime.start(config); history.add(result.id); return result; }, external);
    tool('list_runtime_scans', 'List runtime scans in this profile.', {}, () => history.summaries());
    tool('get_runtime_scan', 'Read a runtime scan and its coverage limitations.', { scanId: id }, ({ scanId }) => runtime.get(scanId));
    tool('cancel_runtime_scan', 'Cancel a runtime scan.', { scanId: id, ...confirm }, ({ scanId }) => { runtime.cancel(scanId); return { ok: true }; }, mutate);
    tool('export_runtime_scan', 'Export a runtime scan as JSON, Markdown or HTML.', { scanId: id, format: z.enum(['json', 'md', 'html']).default('json') }, ({ scanId, format }) => runtime.exportScan(scanId, format));
    tool('start_browser_signin', 'Start interactive browser sign-in on the MCP server host for an authorized runtime scan.', { config: z.record(z.unknown()), ...confirm }, ({ config }) => runtime.startBrowser(config), external);
    tool('finish_browser_signin', 'Finish an existing runtime browser sign-in; authentication material remains server-side.', { browserId: id, ...confirm }, ({ browserId }) => runtime.finishBrowser(browserId), external);
  }
}

module.exports = { registerWorkflowTools };
