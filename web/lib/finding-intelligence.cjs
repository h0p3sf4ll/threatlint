'use strict';

/** Local, revision-bound evidence ledger. Scanner observations are not verified decisions. */
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { parseReport } = require('./reports.cjs');

const WEIGHTS = Object.freeze({ CRITICAL: 10, HIGH: 6, MEDIUM: 3, LOW: 1, INFO: 0, UNSPECIFIED: 0, UNKNOWN: 0 });
const clone = value => structuredClone(value);
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}
const hash = value => crypto.createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex').slice(0, 32);
function text(value, name, max = 1000, required = false) {
  if (value === undefined || value === null || value === '') {
    if (required) throw new Error(`${name} is required`);
    return '';
  }
  if (typeof value !== 'string' || value.length > max || /\u0000/.test(value)) throw new Error(`Invalid ${name}`);
  const normalized = value.trim();
  if (required && !normalized) throw new Error(`${name} is required`);
  return normalized;
}
function timestamp(value, fallback = Date.now()) {
  const time = value === undefined ? fallback : typeof value === 'number' ? value : Date.parse(value);
  if (!Number.isFinite(time) || time < 0 || time > 8640000000000000) throw new Error('Invalid observation timestamp');
  return time;
}
function normalizeEvidence(input, provenance, { allowVerified = false } = {}) {
  if (typeof input === 'string') {
    const match = /^(.*?):(\d+)(?:[-–]\d+)?$/.exec(input);
    input = match ? { path: match[1], line: Number(match[2]), reference: input } : { reference: input };
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Invalid evidence');
  const file = text(input.path, 'evidence path', 2000).replaceAll('\\', '/').replace(/^\.\//, '');
  const reference = text(input.reference || input.ref, 'evidence reference', 3000);
  if (!file && !reference) throw new Error('Evidence needs a path or reference');
  const line = input.line == null ? null : Number(input.line);
  if (line !== null && (!Number.isInteger(line) || line < 1 || line > 100000000)) throw new Error('Invalid evidence line');
  const evidence = { path: file, line, reference, quote: text(input.quote || input.snippet, 'evidence quote', 12000),
    kind: text(input.kind || 'source', 'evidence kind', 60),
    verification: allowVerified && input.verification === 'verified' ? 'verified' : 'reported',
    verificationMethod: allowVerified ? text(input.verificationMethod, 'verification method', 2000) : '',
    refutes: text(input.refutes, 'refuted decision basis', 100), provenance };
  if (evidence.verification === 'verified' && (!evidence.verificationMethod || !evidence.quote)) throw new Error('Verified evidence needs a quote and verification method');
  return { id: `ev_${hash(evidence)}`, ...evidence };
}
function normalizeIngestion(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('An ingestion object is required');
  const repo = { id: text(typeof input.repo === 'string' ? input.repo : input.repo?.id, 'repository id', 2000, true),
    name: text(input.repo?.name, 'repository name', 200) };
  repo.name ||= path.basename(repo.id) || repo.id;
  const provenance = { repo, branch: text(input.branch, 'branch', 500) || 'unknown', commit: text(input.commit, 'commit', 200) || 'unknown',
    contentDigest: text(input.contentDigest, 'content digest', 200) || 'unknown',
    source: text(input.source, 'source', 200, true), sourceId: text(input.sourceId, 'source id', 200, true),
    sessionId: text(input.sessionId, 'session id', 200), origin: input.origin === 'local-scan' ? 'local-scan' : input.origin === 'saved-report' ? 'saved-report' : 'imported' };
  const observedAt = timestamp(input.observedAt);
  if (!Array.isArray(input.findings) || input.findings.length > 10000) throw new Error('An ingestion accepts at most 10000 findings');
  const coverage = { status: ['complete', 'partial', 'unknown', 'failed'].includes(input.coverage?.status) ? input.coverage.status : 'unknown',
    scope: text(input.coverage?.scope, 'coverage scope', 3000) || 'Not recorded',
    limitations: Array.isArray(input.coverage?.limitations) ? input.coverage.limitations.slice(0, 50).map(item => text(item, 'coverage limitation', 2000)) : [] };
  const findings = input.findings.map(raw => {
    if (!raw || typeof raw !== 'object') throw new Error('Invalid finding');
    const title = text(raw.title, 'finding title', 1000, true);
    const ruleId = text(raw.ruleId || raw.rule || raw.id, 'rule id', 300, true);
    const source = text(raw.source || provenance.source, 'finding source', 200, true);
    const items = raw.evidence || (raw.path ? [{ path: raw.path, line: raw.line, quote: raw.snippet }] : []);
    if (!Array.isArray(items) || items.length > 100) throw new Error('A finding accepts at most 100 evidence references');
    const evidence = items.map(item => normalizeEvidence(item, provenance));
    // A provider fingerprint is namespaced, not a global cross-tool or cross-repository identity.
    const identity = text(raw.fingerprint, 'fingerprint', 1000) || hash({ ruleId, title,
      locations: evidence.map(item => `${item.path || item.reference}:${item.line || ''}`).sort() });
    const lineageId = `fl_${hash([repo.id, source, ruleId, identity])}`;
    // Unknown revisions are source-bound: an old report cannot inherit today's checkout identity.
    const revision = provenance.commit === 'unknown' || provenance.contentDigest === 'unknown'
      ? [provenance.commit, provenance.contentDigest, provenance.sourceId] : [provenance.commit, provenance.contentDigest];
    const id = `fi_${hash([lineageId, provenance.branch, revision])}`;
    const severity = String(raw.severity || 'UNSPECIFIED').toUpperCase().replace('INFORMATIONAL', 'INFO');
    if (!Object.hasOwn(WEIGHTS, severity)) throw new Error('Invalid finding severity');
    return { id, lineageId, sourceFindingId: text(raw.id, 'source finding id', 300), ruleId, source, title, severity,
      confidence: text(raw.confidence || 'UNSPECIFIED', 'confidence', 100), category: text(raw.category || 'analysis', 'category', 100),
      reportedDisposition: text(raw.disposition || raw.status, 'reported disposition', 100) || 'OPEN',
      provenance, evidence, recommendation: text(raw.recommendation || raw.remediation, 'recommendation', 12000),
      firstObservedAt: observedAt, lastObservedAt: observedAt, observationIds: [], reviewHistory: [] };
  });
  const id = `in_${hash([repo.id, provenance.branch, provenance.commit, provenance.contentDigest, provenance.source, provenance.sourceId])}`;
  const payloadDigest = hash({ provenance, coverage, findings: findings.map(({ firstObservedAt, lastObservedAt, ...finding }) => finding) });
  return { id, payloadDigest, provenance, observedAt, coverage, findings };
}

function effectiveDisposition(finding, at = Infinity) {
  const events = finding.reviewHistory.filter(event => event.at <= at);
  return events.at(-1)?.disposition || 'UNREVIEWED';
}
function observedSeverity(finding, at = Infinity) {
  const values = [...new Set((finding.observations || []).filter(item => item.at <= at).map(item => item.severity))];
  const observedSeverities = values.length ? values : [finding.severity];
  return { severity: [...observedSeverities].sort((a, b) => WEIGHTS[b] - WEIGHTS[a] || a.localeCompare(b))[0],
    observedSeverities, severityConflict: observedSeverities.length > 1 };
}
function selectedFindings(state, filters = {}, at = Infinity) {
  return state.findings.filter(finding => finding.firstObservedAt <= at &&
    matchesScope(finding.provenance, filters));
}
function matchesScope(provenance, filters) {
  return (!filters.repoId || provenance.repo.id === filters.repoId) &&
    ['branch', 'commit', 'contentDigest'].every(key => !filters[key] || provenance[key] === filters[key]);
}
function latestFindings(state, filters = {}, at = Infinity) {
  const latest = new Map();
  for (const finding of selectedFindings(state, filters, at)) {
    const key = `${finding.lineageId}|${finding.provenance.branch}`;
    const time = Math.max(...state.ingestions.filter(ingestion => ingestion.observedAt <= at && finding.observationIds.includes(ingestion.id)).map(ingestion => ingestion.observedAt));
    if (!latest.has(key) || latest.get(key).observedAt <= time) latest.set(key, { finding, observedAt: time });
  }
  return [...latest.values()].map(({ finding, observedAt }) => ({ ...finding, ...observedSeverity(finding, at), disposition: effectiveDisposition(finding, at), observedAt }));
}
function summarize(findings) {
  const open = findings.filter(finding => !['FALSE POSITIVE', 'REMEDIATED'].includes(finding.disposition));
  return { findings: findings.length, open: open.length, critical: open.filter(finding => finding.severity === 'CRITICAL').length,
    high: open.filter(finding => finding.severity === 'HIGH').length, medium: open.filter(finding => finding.severity === 'MEDIUM').length,
    verifiedRemediated: findings.filter(finding => finding.disposition === 'REMEDIATED').length,
    falsePositives: findings.filter(finding => finding.disposition === 'FALSE POSITIVE').length,
    unknownSeverity: open.filter(finding => ['UNKNOWN', 'UNSPECIFIED'].includes(finding.severity)).length,
    openRiskPoints: open.reduce((sum, finding) => sum + WEIGHTS[finding.severity], 0) };
}
function overview(state, filters = {}) {
  const findings = latestFindings(state, filters);
  const ingestions = state.ingestions.filter(item => matchesScope(item.provenance, filters));
  const repositories = [];
  for (const id of new Set(ingestions.map(item => item.provenance.repo.id))) {
    const records = ingestions.filter(item => item.provenance.repo.id === id);
    repositories.push({ repo: records[0].provenance.repo, branches: [...new Set(records.map(item => item.provenance.branch))].map(branch => {
      const scans = records.filter(item => item.provenance.branch === branch).sort((a, b) => a.observedAt - b.observedAt);
      const current = findings.filter(item => item.provenance.repo.id === id && item.provenance.branch === branch);
      return { branch, commits: [...new Set(scans.map(item => item.provenance.commit))], ...summarize(current), coverage: scans.at(-1).coverage,
        lastObservedAt: scans.at(-1).observedAt, notReobserved: current.filter(item => item.observedAt < scans.at(-1).observedAt).length };
    }) });
  }
  const eventTimes = [...new Set([...ingestions.map(item => item.observedAt), ...selectedFindings(state, filters).flatMap(item => item.reviewHistory.map(event => event.at))])].sort((a, b) => a - b);
  const trends = eventTimes.map(at => {
    const recent = ingestions.filter(item => item.observedAt <= at).sort((a, b) => a.observedAt - b.observedAt).at(-1);
    return { at, ...summarize(latestFindings(state, filters, at)), coverage: recent?.coverage.status || 'unknown',
      resolutionPolicy: 'An evidence-backed remediation or false-positive decision closes a finding. Absence is unknown; false positives are not counted as verified fixes.' };
  });
  const ids = new Set(selectedFindings(state, filters).map(item => item.id));
  // Selecting an older revision must not promote a historical chain back to current.
  const currentIds = new Set(latestFindings(state, { repoId: filters.repoId, branch: filters.branch }).map(item => item.id));
  const composites = state.composites.filter(item => item.contributors.every(node => ids.has(node.findingId))).map(item => ({ ...item,
    assessmentStatus: item.contributors.some(node => state.findings.find(finding => finding.id === node.findingId)?.reviewHistory.at(-1)?.id !== node.reviewId)
      ? 'needs-reassessment' : item.contributors.some(node => !currentIds.has(node.findingId)) ? 'historical-revision' : 'current' }));
  const activeChains = composites.filter(item => item.assessmentStatus === 'current');
  const chainSummary = { current: activeChains.length, criticalImpact: activeChains.filter(item => item.severity === 'CRITICAL').length,
    highImpact: activeChains.filter(item => item.severity === 'HIGH').length, provisional: activeChains.filter(item => item.riskAssessment?.provisional).length,
    maxContextualPriorityPoints: Math.max(0, ...activeChains.map(item => item.riskAssessment?.points || 0)),
    countingPolicy: 'Highest active chain priority is shown separately; chains and components are never summed together.' };
  return { summary: summarize(findings), repositories, findings,
    observations: ingestions.map(({ id, provenance, observedAt, coverage }) => ({ id, provenance, observedAt, coverage })),
    revisionFindings: selectedFindings(state, filters).map(item => ({ ...item, ...observedSeverity(item), disposition: effectiveDisposition(item) })), composites, chainSummary, trends,
    riskModel: { label: 'Open finding priority points', weights: WEIGHTS, cvss: false, compositesAddedToStandaloneTotal: false },
    limitations: ['Reported scanner evidence is unverified until reviewed.', 'A scan missing a finding does not prove remediation.',
      'Unknown revisions remain isolated; cross-tool correlation requires explicit evidence links.', 'Unknown severities are unscored, not evidence of low risk.',
      'Conflicting severity observations retain their history and use the highest recorded priority at each point in time.', 'Composite impact is assessed separately; ordinal severities are never summed into a CVSS score.'] };
}

function createFindingIntelligenceStore({ directory } = {}) {
  const file = directory ? path.join(directory, 'finding-intelligence.json') : null;
  let state = { version: 1, ingestions: [], findings: [], composites: [] };
  if (file && fs.existsSync(file)) {
    const loaded = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (loaded.version !== 1 || !['ingestions', 'findings', 'composites'].every(key => Array.isArray(loaded[key]))) throw new Error('Invalid finding intelligence ledger');
    state = loaded;
  }
  function save(next) {
    if (file) {
      fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
      const temporary = `${file}.${crypto.randomUUID()}.tmp`;
      try { fs.writeFileSync(temporary, JSON.stringify(next), { mode: 0o600 }); fs.renameSync(temporary, file); }
      finally { if (fs.existsSync(temporary)) fs.unlinkSync(temporary); }
    }
    state = next;
  }
  return {
    snapshot: () => clone(state), overview: filters => clone(overview(state, filters)),
    getFinding: id => clone(state.findings.find(item => item.id === id)),
    getComposite: id => clone(state.composites.find(item => item.id === id)),
    ingest(input) {
      const record = normalizeIngestion(input);
      const existing = state.ingestions.find(item => item.id === record.id);
      if (existing) {
        if (existing.payloadDigest !== record.payloadDigest) throw new Error('This source revision was already ingested with different content; use a new source id');
        return { ingestion: clone(existing), duplicate: true };
      }
      if (state.ingestions.length >= 10000 || state.findings.length + record.findings.length > 50000) throw new Error('Local evidence ledger capacity reached');
      const next = clone(state);
      for (const finding of record.findings) {
        const observation = { ingestionId: record.id, at: record.observedAt, severity: finding.severity, confidence: finding.confidence,
          reportedDisposition: finding.reportedDisposition };
        const prior = next.findings.find(item => item.id === finding.id);
        if (prior) {
          prior.firstObservedAt = Math.min(prior.firstObservedAt, record.observedAt);
          prior.lastObservedAt = Math.max(prior.lastObservedAt, record.observedAt);
          prior.observationIds = [...new Set([...prior.observationIds, record.id])];
          prior.evidence = [...new Map([...prior.evidence, ...finding.evidence].map(item => [item.id, item])).values()];
          prior.observations = [...(prior.observations || [{ ingestionId: prior.observationIds[0], at: prior.firstObservedAt, severity: prior.severity, confidence: prior.confidence, reportedDisposition: prior.reportedDisposition }]), observation];
          Object.assign(prior, observedSeverity(prior));
        } else next.findings.push({ ...finding, observationIds: [record.id], observations: [observation] });
      }
      const { findings, ...saved } = record;
      saved.findingIds = [...new Set(findings.map(item => item.id))];
      next.ingestions.push(saved); save(next);
      return { ingestion: clone(saved), duplicate: false };
    },
    review(id, input) {
      const { reviewFinding } = require('./finding-intelligence-graph.cjs');
      const next = clone(state), finding = next.findings.find(item => item.id === id);
      if (!finding) throw new Error('Finding not found');
      const reviewed = reviewFinding(finding, input);
      next.findings[next.findings.indexOf(finding)] = reviewed; save(next);
      return clone(reviewed);
    },
    correlate(input) {
      const { buildComposite } = require('./finding-intelligence-graph.cjs');
      const composite = buildComposite(state.findings, input);
      const previous = state.composites.find(item => item.id === composite.id);
      if (previous) return clone(previous);
      const next = clone(state); next.composites.push(composite); save(next); return clone(composite);
    },
  };
}

function ingestionFromScan(scan, session) {
  if (!scan || !session || !['completed', 'partial', 'failed', 'cancelled'].includes(scan.status)) throw new Error('A finished scan and session are required');
  return { repo: { id: session.repoPath, name: path.basename(session.repoPath) }, sessionId: session.id,
    branch: scan.binding?.branch, commit: scan.binding?.commit, contentDigest: scan.binding?.contentDigest,
    source: 'security-scan', sourceId: scan.id, origin: 'local-scan', observedAt: scan.observedAt || scan.finishedAt || scan.completedAt || scan.startedAt,
    coverage: { status: scan.coverage?.status || (scan.status === 'completed' ? 'complete' : scan.status === 'partial' ? 'partial' : 'failed'),
      scope: [scan.coverage?.scope, `Engines with results: ${(scan.engines || []).filter(engine => ['completed', 'partial'].includes(engine.status)).map(engine => engine.id).join(', ') || 'none'}`].filter(Boolean).join('. '),
      limitations: [...(scan.coverage?.limitations || []), ...(scan.engines || []).filter(engine => engine.status !== 'completed').map(engine => `${engine.id}: ${engine.status}${engine.detail ? ` — ${engine.detail}` : ''}`)] },
    findings: scan.findings || [] };
}
function ingestionFromReport(report, session) {
  const findings = Array.isArray(report.findings) ? report.findings : parseReport(report.markdown || '', report.agentId).findings;
  return { repo: { id: session.repoPath, name: path.basename(session.repoPath) }, sessionId: session.id,
    branch: report.provenance?.branch, commit: report.provenance?.commit, contentDigest: report.provenance?.contentDigest,
    source: report.agentId || 'saved-report', sourceId: report.id, origin: 'saved-report', observedAt: report.timestamp,
    coverage: { status: 'unknown', scope: report.label || report.agentId || 'Saved report', limitations: ['Historical reports may not record the reviewed branch, commit, or complete scanner coverage.'] }, findings };
}
module.exports = { createFindingIntelligenceStore, normalizeIngestion, normalizeEvidence, ingestionFromScan, ingestionFromReport,
  effectiveDisposition, overview, WEIGHTS, hash, text, timestamp };
