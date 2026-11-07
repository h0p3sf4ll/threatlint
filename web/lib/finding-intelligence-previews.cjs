'use strict';

/** Deliberately offline integrations: no transport, credentials, employee roster, or write-back. */
const { effectiveDisposition, hash, text, WEIGHTS } = require('./finding-intelligence.cjs');

function serviceNowPreview(composite, findings) {
  if (!composite) throw new Error('Composite not found');
  const related = composite.contributors.map(node => {
    const finding = findings.find(item => item.id === node.findingId);
    if (!finding) throw new Error('Composite evidence is incomplete');
    if ((finding.reviewHistory.at(-1)?.id || null) !== node.reviewId) throw new Error('A contributing disposition changed; reassess the chain before export');
    return { idempotencyKey: `threatlint:finding:${finding.id}`, findingId: finding.id, short_description: finding.title,
      severity: finding.severity, standaloneDisposition: effectiveDisposition(finding), role: node.role, contextualRelevance: node.relevance,
      evidence: finding.evidence.map(item => ({ id: item.id, path: item.path, line: item.line, reference: item.reference, verification: item.verification })),
      relation: { parentKey: `threatlint:chain:${composite.id}`, type: 'contributes-to' },
      work_notes: `${node.rationale}\nOriginal finding retained. Chain assessment does not overwrite the standalone disposition.\nRepository: ${finding.provenance.repo.id}\nBranch: ${finding.provenance.branch}\nCommit: ${finding.provenance.commit}` };
  });
  return { mode: 'preview-only', liveWritesEnabled: false, destination: 'ServiceNow',
    mappingStatus: 'Stub: configure and validate instance table/field mapping before implementing an authenticated connector.',
    parent: { idempotencyKey: `threatlint:chain:${composite.id}`, short_description: composite.title, severity: composite.severity,
      contextualPriority: composite.riskAssessment || null,
      description: composite.impact.description, disposition: composite.disposition, contributingFindingKeys: related.map(item => item.idempotencyKey),
      work_notes: `${composite.riskRationale}\nAttack complexity (${composite.complexity.level}): ${composite.complexity.rationale}\n${composite.riskAssessment?.rationale || 'No contextual priority rubric recorded.'}\nCoverage: ${composite.coverage}\nUncertainty: ${composite.uncertainty.join('; ') || 'None recorded by reviewer'}\n${composite.scoring}\nEvidence: ${composite.evidenceIds.join(', ')}` },
    related, exportDigest: hash([composite.id, related.map(item => [item.findingId, item.standaloneDisposition])]),
    idempotencyPolicy: 'Upsert the parent by its key and each contributing finding by its own key; previewing repeatedly never creates records.' };
}

function developerRiskPreview(findings, input) {
  if (input?.optIn !== true) return { mode: 'private-coaching-stub', optedIn: false, score: null, reason: 'Explicit personal opt-in is required. No coaching assessment was created.' };
  const subject = text(input.subject, 'private subject label', 200, true);
  if (!Number.isInteger(input.observedChangeCount) || input.observedChangeCount < 1 || input.observedChangeCount > 100000) throw new Error('Record the observed change sample size');
  if (!Array.isArray(input.observations) || input.observations.length > 1000) throw new Error('Provide at most 1000 observed issue records');
  const accepted = [], excluded = [], seen = new Set();
  for (const observation of input.observations) {
    const finding = findings.find(item => item.id === observation.findingId);
    if (!finding || seen.has(finding.lineageId)) { excluded.push({ findingId: observation.findingId, reason: finding ? 'Duplicate logical issue' : 'Unknown finding' }); continue; }
    const evidence = Array.isArray(observation.introductionEvidenceIds) ? observation.introductionEvidenceIds.map(id => finding.evidence.find(item => item.id === id)) : [];
    if (observation.introduced !== true || !evidence.length || evidence.some(item => !item || item.verification !== 'verified' || item.kind !== 'introduction')) {
      excluded.push({ findingId: finding.id, reason: 'No verified evidence of an introduced issue; commit authorship is insufficient' }); continue;
    }
    const disposition = effectiveDisposition(finding);
    if (!['TRUE POSITIVE', 'REMEDIATED'].includes(disposition)) { excluded.push({ findingId: finding.id, reason: 'No verified actionable issue' }); continue; }
    if (['UNKNOWN', 'UNSPECIFIED'].includes(finding.severity)) { excluded.push({ findingId: finding.id, reason: 'Severity is unknown; the issue cannot be assigned coaching points' }); continue; }
    const exposure = observation.exposure;
    if (!['internet', 'internal', 'local', 'unknown'].includes(exposure)) throw new Error('Exposure must be internet, internal, local, or unknown');
    const exposureEvidence = (observation.exposureEvidenceIds || []).map(id => finding.evidence.find(item => item.id === id));
    if (exposure !== 'unknown' && (!exposureEvidence.length || exposureEvidence.some(item => !item || item.verification !== 'verified'))) {
      excluded.push({ findingId: finding.id, reason: 'Asserted exposure lacks verified evidence' }); continue;
    }
    seen.add(finding.lineageId);
    accepted.push({ findingId: finding.id, lineageId: finding.lineageId, ruleId: finding.ruleId, severity: finding.severity,
      disposition, exposure, evidenceIds: evidence.map(item => item.id), exposureEvidenceIds: exposureEvidence.map(item => item.id),
      improvement: finding.recommendation || 'Review the recorded finding and add a regression assertion for the violated security invariant.' });
  }
  if (accepted.length > input.observedChangeCount) throw new Error('The observed change sample must cover the included issue records');
  const frequency = new Map();
  for (const item of accepted) frequency.set(item.ruleId, (frequency.get(item.ruleId) || 0) + 1);
  const details = accepted.map(item => {
    const exposureFactor = item.exposure === 'internet' ? 1.5 : item.exposure === 'local' ? 0.75 : 1;
    const recurrenceFactor = frequency.get(item.ruleId) > 1 ? 1.25 : 1;
    const remediationFactor = item.disposition === 'REMEDIATED' ? 0.25 : 1;
    return { ...item, severityWeight: WEIGHTS[item.severity], exposureFactor, recurrenceFactor, remediationFactor,
      points: Number((WEIGHTS[item.severity] * exposureFactor * recurrenceFactor * remediationFactor).toFixed(3)) };
  });
  const enoughData = input.observedChangeCount >= 5 && accepted.length > 0;
  return { mode: 'private-coaching-stub', optedIn: true, subject, visibility: 'private', persisted: false,
    score: enoughData ? Math.min(100, Math.round(10 * details.reduce((sum, item) => sum + item.points, 0) / input.observedChangeCount)) : null,
    scoreLabel: 'Coaching priority index (not employee performance)', confidence: !enoughData ? 'insufficient-data' : input.observedChangeCount >= 20 && !excluded.length && details.every(item => item.exposure !== 'unknown') ? 'moderate' : 'low',
    observedChangeCount: input.observedChangeCount, includedIssues: details.length, excluded, details,
    formula: 'min(100, round(10 × sum(severity weight × exposure factor × observed recurrence factor × remediation factor) / observed change count)). Severity: Critical 10, High 6, Medium 3, Low 1, Info/unspecified 0. Exposure: internet 1.5, internal/unknown 1, local 0.75. Repeated verified rule: 1.25, otherwise 1. Verified remediation: 0.25, otherwise 1.',
    improvementSteps: [...new Set(details.map(item => item.improvement))],
    limitations: ['Opt-in preview only; identities and scores are not persisted.', 'Only explicit verified introduction evidence is eligible; commit authorship never establishes responsibility.',
      'Unknown exposure is neutral and lowers confidence. Partial scanner coverage and sample selection limit interpretation.',
      'No employee ranking, peer comparison, or employment decision is supported.', 'A null score means insufficient observations, not absence of risk.'] };
}
module.exports = { serviceNowPreview, developerRiskPreview };
