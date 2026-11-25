'use strict';

/** MCP adapters use the same evidence ledger and decision gates as the Workbench. */
const path = require('node:path');
const { ingestionFromReport } = require('./finding-intelligence.cjs');
const { serviceNowPreview, developerRiskPreview } = require('./finding-intelligence-previews.cjs');

function registerFindingTools({ tool, z, id, workspace, intelligence }) {
  const text = max => z.string().max(max);
  const required = max => z.string().trim().min(1).max(max);
  const at = z.union([z.number().min(0).max(8640000000000000), required(100)]).optional();
  const evidence = z.object({
    path: text(2000).optional(), reference: text(3000).optional(), line: z.number().int().min(1).max(100000000).nullable().optional(),
    quote: text(12000).optional(), kind: text(60).optional(), verification: z.enum(['reported', 'verified']).optional(),
    verificationMethod: text(2000).optional(), refutes: text(100).optional(),
  });
  const references = z.array(id).min(1).max(100);
  const review = z.object({
    disposition: z.enum(['TRUE POSITIVE', 'FALSE POSITIVE', 'REMEDIATED']), reason: required(8000),
    newEvidence: z.array(z.union([evidence, text(3000)])).max(100),
    basis: z.array(z.object({ claim: required(4000), evidenceIds: z.array(z.union([id, z.number().int().min(0).max(99)])).min(1).max(100) })).min(1).max(30),
    safeBehavior: text(8000).optional(), at,
  });
  const findingInput = z.object({
    id: text(300).optional(), ruleId: required(300), source: text(200).optional(), fingerprint: text(1000).optional(),
    title: required(1000), severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNSPECIFIED', 'UNKNOWN']).optional(),
    confidence: text(100).optional(), category: text(100).optional(), disposition: text(100).optional(),
    evidence: z.array(z.union([evidence, text(3000)])).max(100).optional(), path: text(2000).optional(),
    line: z.number().int().min(1).max(100000000).optional(), snippet: text(12000).optional(), recommendation: text(12000).optional(),
  });
  const selectedFinding = (sessionId, findingId) => {
    const selected = intelligence.getFinding(findingId);
    if (!selected || selected.provenance.repo.id !== workspace(sessionId).repoPath) throw new Error('Finding not found in this workspace');
    return selected;
  };
  const selectedComposite = (sessionId, compositeId) => {
    const selected = intelligence.getComposite(compositeId);
    if (!selected || selected.provenance.repo.id !== workspace(sessionId).repoPath) throw new Error('Composite not found in this workspace');
    for (const node of selected.contributors) selectedFinding(sessionId, node.findingId);
    return selected;
  };
  const write = { readOnly: false };
  // Mutations may touch records with long evidence histories. Return stable handles rather
  // than failing the response-size limit after the decision has already been committed.
  const reviewSummary = finding => ({ id: finding.id, disposition: finding.reviewHistory.at(-1)?.disposition || 'UNREVIEWED',
    reviewId: finding.reviewHistory.at(-1)?.id || null, reviewCount: finding.reviewHistory.length, evidenceCount: finding.evidence.length });

  tool('sync_reports', 'Ingest this workspace’s saved reports into findings history. Historical reports retain their recorded revision; this does not verify findings.', {
    sessionId: id, confirm: z.literal(true), reportIds: z.array(id).min(1).max(1000).optional(),
  }, ({ sessionId, reportIds }) => {
    const session = workspace(sessionId);
    const available = session.reports || [];
    if (reportIds?.some(reportId => !available.some(report => report.id === reportId))) throw new Error('Report not found in this workspace');
    const selected = reportIds ? available.filter(report => reportIds.includes(report.id)) : available;
    const errors = [];
    let imported = 0, duplicates = 0, errorCount = 0;
    for (const report of selected) {
      try { const result = intelligence.ingest(ingestionFromReport(report, session)); if (result.duplicate) duplicates++; else imported++; }
      catch (error) { errorCount++; if (errors.length < 100) errors.push({ reportId: report.id, error: String(error.message || 'Report import failed').slice(0, 500) }); }
    }
    return { imported, duplicates, errors,
      ...(errorCount > errors.length ? { errorCount, errorsTruncated: true } : {}) };
  }, write);

  tool('ingest_findings', 'Import revision-bound scanner or external observations into a workspace. Imported verification is always reported; a separate evidence-backed review is required.', {
    sessionId: id, confirm: z.literal(true), source: required(200), sourceId: required(200),
    branch: text(500).optional(), commit: text(200).optional(), contentDigest: text(200).optional(), observedAt: at,
    coverage: z.object({ status: z.enum(['complete', 'partial', 'unknown', 'failed']).optional(), scope: text(3000).optional(), limitations: z.array(text(2000)).max(50).optional() }).optional(),
    findings: z.array(findingInput).max(10000),
  }, ({ sessionId, confirm, ...input }) => {
    const session = workspace(sessionId);
    return intelligence.ingest({ ...input, repo: { id: session.repoPath, name: path.basename(session.repoPath) }, sessionId: session.id, origin: 'imported' });
  }, write);

  tool('review_finding', 'Record an explicitly attested, evidence-backed disposition. Verification must describe work actually performed. False-positive and remediation evidence gates remain enforced.', {
    sessionId: id, findingId: id, confirm: z.literal(true), review,
  }, ({ sessionId, findingId, review: input }) => reviewSummary(intelligence.review(selectedFinding(sessionId, findingId).id, input)), write);

  tool('resolve_findings', 'Atomically mark 1–100 selected workspace findings remediated, with new verified remediation evidence for every decision.', {
    sessionId: id, findingIds: z.array(id).min(1).max(100), confirm: z.literal(true), review: review.omit({ disposition: true }),
  }, ({ sessionId, findingIds, review: input }) => {
    workspace(sessionId);
    for (const findingId of findingIds) selectedFinding(sessionId, findingId);
    return { resolved: intelligence.resolveMany(findingIds, input).map(reviewSummary) };
  }, write);

  tool('correlate_findings', 'Save an evidence-backed attack chain without changing standalone dispositions or adding component severities. Contributors must belong to this workspace and the same known revision.', {
    sessionId: id, confirm: z.literal(true), title: required(1000),
    contributors: z.array(z.object({ findingId: id, role: z.enum(['vulnerability', 'context']), rationale: required(4000) })).min(2).max(30),
    links: z.array(z.object({ prerequisite: id, effect: id, rationale: required(4000), evidenceIds: references })).min(1).max(100),
    impact: z.object({ severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']), description: required(8000), evidenceIds: references }),
    complexity: z.object({ level: z.enum(['low', 'moderate', 'high']), rationale: required(8000) }),
    riskRationale: required(8000), uncertainty: z.array(required(3000)).max(30), coverage: required(8000), at,
  }, ({ sessionId, confirm, ...input }) => {
    workspace(sessionId);
    for (const node of input.contributors) selectedFinding(sessionId, node.findingId);
    return intelligence.correlate(input);
  }, write);

  tool('get_composite', 'Read one saved attack chain and its evidence links within the selected workspace.', {
    sessionId: id, compositeId: id,
  }, ({ sessionId, compositeId }) => selectedComposite(sessionId, compositeId));

  tool('preview_composite_servicenow', 'Build an offline ServiceNow mapping preview for a reviewed attack chain. No network writes occur; stale contributing decisions require reassessment.', {
    sessionId: id, compositeId: id,
  }, ({ sessionId, compositeId }) => serviceNowPreview(selectedComposite(sessionId, compositeId), intelligence.snapshot().findings));

  tool('preview_developer_risk', 'Build an explicitly opted-in private coaching preview using verified introduction evidence. Does not persist scores, rank people, or infer responsibility from authorship.', {
    sessionId: id, optIn: z.literal(true), subject: required(200), observedChangeCount: z.number().int().min(1).max(100000),
    observations: z.array(z.object({ findingId: id, introduced: z.boolean(), introductionEvidenceIds: z.array(id).max(100),
      exposure: z.enum(['internet', 'internal', 'local', 'unknown']), exposureEvidenceIds: z.array(id).max(100).optional() })).max(1000),
  }, ({ sessionId, ...input }) => {
    const selected = workspace(sessionId);
    for (const observation of input.observations) selectedFinding(sessionId, observation.findingId);
    return developerRiskPreview(intelligence.snapshot().findings.filter(item => item.provenance.repo.id === selected.repoPath), input);
  });
}

module.exports = { registerFindingTools };
