'use strict';

/** A graph is an explicit assessed attack path, never a severity accumulator. */
const { effectiveDisposition, normalizeEvidence, hash, text, timestamp, WEIGHTS } = require('./finding-intelligence.cjs');

function references(value, available, label, { verified = true } = {}) {
  if (!Array.isArray(value) || !value.length || value.length > 100 || new Set(value).size !== value.length) throw new Error(`${label} needs distinct evidence ids`);
  const records = value.map(id => available.find(item => item.id === id));
  if (records.some(item => !item)) throw new Error(`${label} references unknown evidence`);
  if (verified && records.some(item => item.verification !== 'verified')) throw new Error(`${label} requires verified evidence`);
  return [...value].sort();
}

/** Local prioritization heuristic, deliberately distinct from impact severity and CVSS. */
function assessChainPriority(impactSeverity, complexity, uncertainty) {
  const factor = { low: 1, moderate: 0.75, high: 0.5 }[complexity];
  const impactWeight = WEIGHTS[impactSeverity];
  const points = Number((impactWeight * factor).toFixed(2));
  const priority = points >= 9 ? 'CRITICAL' : points >= 4.5 ? 'HIGH' : points >= 2 ? 'MEDIUM' : 'LOW';
  return { rubricVersion: 'local-chain-priority-v1', label: 'Contextual priority points', cvss: false, points, maximum: 10, priority,
    impactSeverity, impactWeight, complexity, complexityFactor: factor, provisional: uncertainty.length > 0,
    rationale: `${impactSeverity} terminal impact (${impactWeight}) × ${complexity} complexity (${factor}) = ${points}/10 contextual priority points (${priority}).${uncertainty.length ? ' Provisional: unresolved assumptions require validation.' : ''} Component counts and severities do not enter this calculation.`,
    calibration: 'Local triage heuristic, not CVSS, exploit probability, or a reduction in the stated impact severity. Bands: ≥9 Critical, ≥4.5 High, ≥2 Medium, otherwise Low.' };
}

function reviewFinding(finding, input) {
  if (!input || !['TRUE POSITIVE', 'FALSE POSITIVE', 'REMEDIATED'].includes(input.disposition)) throw new Error('Choose TRUE POSITIVE, FALSE POSITIVE, or REMEDIATED');
  const reason = text(input.reason, 'decision rationale', 8000, true);
  if (!Array.isArray(input.newEvidence) || input.newEvidence.length > 100) throw new Error('Provide newEvidence as an array');
  const evidence = input.newEvidence.map(item => normalizeEvidence(item, finding.provenance, { allowVerified: true }));
  const newEvidence = evidence.filter(item => !finding.evidence.some(prior => prior.id === item.id));
  const available = [...finding.evidence, ...newEvidence];
  if (!Array.isArray(input.basis) || !input.basis.length || input.basis.length > 30) throw new Error('Record the decision basis with evidence');
  // Callers can refer to a newly submitted evidence item by its zero-based position.
  const resolveIds = values => Array.isArray(values) ? values.map(value => Number.isInteger(value) ? evidence[value]?.id : value) : values;
  const basis = input.basis.map(item => {
    const claim = text(item.claim, 'decision basis claim', 4000, true);
    const evidenceIds = references(resolveIds(item.evidenceIds), available, 'Decision basis');
    return { id: `basis_${hash([claim, evidenceIds])}`, claim, evidenceIds };
  });
  const previous = finding.reviewHistory.at(-1);
  if (previous && ['FALSE POSITIVE', 'REMEDIATED'].includes(previous.disposition) && input.disposition !== previous.disposition) {
    const closedRun = finding.reviewHistory.slice(finding.reviewHistory.findLastIndex(event => event.disposition !== previous.disposition) + 1);
    const originalBasis = closedRun[0].basis;
    // Evidence purpose and reviewer metadata do not make an old observation new.
    const substantive = item => hash([item.path, item.line, item.reference, item.quote]);
    const relevant = newEvidence.filter(item => item.verification === 'verified' && originalBasis.some(claim => claim.id === item.refutes) &&
      !finding.evidence.some(prior => substantive(prior) === substantive(item)));
    if (!relevant.length) throw new Error('Changing a closed decision requires new verified evidence refuting its original decision basis');
    if (!basis.some(claim => claim.evidenceIds.some(id => relevant.some(item => item.id === id)))) throw new Error('The new decision basis must cite the refuting evidence');
  }
  const safeBehavior = text(input.safeBehavior, 'verified safe behavior', 8000);
  if (input.disposition === 'FALSE POSITIVE' && !safeBehavior) throw new Error('A false positive decision needs verified safe behavior');
  if (input.disposition === 'REMEDIATED') {
    const remediation = newEvidence.filter(item => item.verification === 'verified' && item.kind === 'remediation');
    if (!remediation.length) throw new Error('Remediation requires new verified remediation evidence');
    if (!basis.some(claim => claim.evidenceIds.some(id => remediation.some(item => item.id === id)))) throw new Error('The remediation decision basis must cite the new remediation evidence');
  }
  const at = timestamp(input.at);
  if (at < finding.firstObservedAt || (previous && at < previous.at)) throw new Error('Review timestamps must follow the observation and prior decisions');
  const event = { id: `rv_${hash([finding.id, input.disposition, reason, basis, newEvidence.map(item => item.id), safeBehavior])}`,
    at, disposition: input.disposition, reason, basis, evidenceIds: newEvidence.map(item => item.id), safeBehavior,
    verificationNote: 'Evidence verification was explicitly attested by the local reviewer; no exploit or regression test was run by this API.' };
  if (finding.reviewHistory.some(item => item.id === event.id)) return structuredClone(finding);
  return { ...finding, evidence: available, reviewHistory: [...finding.reviewHistory, event] };
}

function buildComposite(findings, input) {
  if (!input || !Array.isArray(input.contributors) || input.contributors.length < 2 || input.contributors.length > 30) throw new Error('A composite needs 2–30 contributing findings');
  const contributors = input.contributors.map(node => {
    const finding = findings.find(item => item.id === node.findingId);
    if (!finding) throw new Error('Unknown contributing finding');
    const disposition = effectiveDisposition(finding);
    const role = text(node.role, 'contributor role', 100, true);
    if (!['vulnerability', 'context'].includes(role)) throw new Error('Contributor role is vulnerability or context');
    if (role === 'vulnerability' && disposition !== 'TRUE POSITIVE') throw new Error('Vulnerability contributors require an evidence-backed true positive review');
    if (role === 'context' && !finding.evidence.some(item => item.verification === 'verified')) throw new Error('Contextual contributors require verified evidence');
    if (disposition === 'REMEDIATED') throw new Error('Remediated findings cannot support a current attack path');
    return { findingId: finding.id, role, rationale: text(node.rationale, 'contributor rationale', 4000, true), standaloneDisposition: disposition,
      relevance: disposition === 'FALSE POSITIVE' ? 'contextual-false-positive' : role === 'vulnerability' ? 'standalone-true-positive' : 'contextual',
      reviewId: finding.reviewHistory.at(-1)?.id || null };
  });
  if (new Set(contributors.map(item => item.findingId)).size !== contributors.length) throw new Error('Duplicate contributors');
  if (!contributors.some(item => item.role === 'vulnerability')) throw new Error('A chain requires at least one verified vulnerability');
  const selected = contributors.map(node => findings.find(item => item.id === node.findingId));
  const first = selected[0].provenance;
  if (first.commit === 'unknown' || first.branch === 'unknown' || first.contentDigest === 'unknown') throw new Error('A chain requires a known branch, commit, and content digest');
  if (selected.some(item => ['branch', 'commit', 'contentDigest'].some(key => item.provenance[key] !== first[key]) || item.provenance.repo.id !== first.repo.id)) throw new Error('A chain cannot cross repository, branch, or revision boundaries');
  const available = [...new Map(selected.flatMap(item => item.evidence).map(item => [item.id, item])).values()];
  if (!Array.isArray(input.links) || !input.links.length || input.links.length > 100) throw new Error('Record prerequisite-to-effect evidence links');
  const ids = new Set(contributors.map(item => item.findingId));
  const edges = new Set();
  const links = input.links.map(link => {
    if (!ids.has(link.prerequisite) || !ids.has(link.effect) || link.prerequisite === link.effect) throw new Error('Invalid prerequisite-to-effect link');
    const key = `${link.prerequisite}|${link.effect}`;
    if (edges.has(key)) throw new Error('Duplicate evidence link');
    edges.add(key);
    const endpointEvidence = selected.filter(item => [link.prerequisite, link.effect].includes(item.id)).flatMap(item => item.evidence);
    return { prerequisite: link.prerequisite, effect: link.effect, rationale: text(link.rationale, 'link rationale', 4000, true),
      evidenceIds: references(link.evidenceIds, endpointEvidence, 'Attack link') };
  });
  // A disconnected collection of risks is not a chain. Require a DAG with one terminal effect.
  const outgoing = id => links.filter(link => link.prerequisite === id).map(link => link.effect);
  const terminals = [...ids].filter(id => !outgoing(id).length);
  if (terminals.length !== 1) throw new Error('An attack chain needs one terminal effect');
  const visited = new Set(), active = new Set();
  function visit(id) {
    if (active.has(id)) throw new Error('Attack chains cannot contain cycles');
    if (visited.has(id)) return;
    active.add(id); for (const next of outgoing(id)) visit(next); active.delete(id); visited.add(id);
  }
  for (const id of ids) visit(id);
  // Every nonterminal must connect to that terminal, including contextual contributors.
  function reaches(id) { return id === terminals[0] || outgoing(id).some(reaches); }
  if ([...ids].some(id => !reaches(id))) throw new Error('Every contributor must reach the assessed impact');
  const severity = text(input.impact?.severity, 'impact severity', 30, true).toUpperCase();
  if (!Object.hasOwn(WEIGHTS, severity) || ['INFO', 'UNSPECIFIED', 'UNKNOWN'].includes(severity)) throw new Error('Specify an assessed impact severity');
  const terminal = selected.find(item => item.id === terminals[0]);
  const impactEvidence = terminal.evidence.filter(item => item.kind === 'impact');
  const impact = { severity, description: text(input.impact?.description, 'terminal impact', 8000, true),
    evidenceIds: references(input.impact?.evidenceIds, impactEvidence, 'Terminal impact') };
  const complexity = { level: text(input.complexity?.level, 'attack complexity', 30, true), rationale: text(input.complexity?.rationale, 'complexity rationale', 8000, true) };
  if (!['low', 'moderate', 'high'].includes(complexity.level)) throw new Error('Attack complexity is low, moderate, or high');
  const riskRationale = text(input.riskRationale, 'risk rationale', 8000, true);
  if (!Array.isArray(input.uncertainty) || input.uncertainty.length > 30) throw new Error('Record uncertainty explicitly as an array');
  const uncertainty = input.uncertainty.map(value => text(value, 'uncertainty', 3000, true));
  const coverage = text(input.coverage, 'chain coverage', 8000, true);
  const riskAssessment = assessChainPriority(severity, complexity.level, uncertainty);
  const composite = { title: text(input.title, 'composite title', 1000, true), provenance: { repo: first.repo, branch: first.branch, commit: first.commit, contentDigest: first.contentDigest },
    contributors: contributors.sort((a, b) => a.findingId.localeCompare(b.findingId)), links: links.sort((a, b) => `${a.prerequisite}|${a.effect}`.localeCompare(`${b.prerequisite}|${b.effect}`)),
    impact, severity, complexity, riskAssessment, riskRationale, uncertainty, coverage, confidence: uncertainty.length ? 'PLAUSIBLE' : 'REVIEWED',
    disposition: 'CHAIN TRUE POSITIVE', scoring: 'Assessed terminal impact; component severities are retained and never added.',
    evidenceIds: [...new Set([...links.flatMap(link => link.evidenceIds), ...impact.evidenceIds])].sort() };
  return { id: `chain_${hash(composite)}`, ...composite, createdAt: timestamp(input.at) };
}

module.exports = { buildComposite, reviewFinding, assessChainPriority };
