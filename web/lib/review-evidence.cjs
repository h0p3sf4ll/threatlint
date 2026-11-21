'use strict';

const fs = require('node:fs');
const { safeResolvePath } = require('./tools.cjs');

const SEVERITIES = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const CONFIDENCES = ['THEORETICAL', 'PLAUSIBLE', 'CONFIRMED'];
const DISPOSITIONS = ['', 'TRUE POSITIVE', 'FALSE POSITIVE', 'REMEDIATED', 'PARTIALLY FIXED', 'STILL PRESENT', 'REGRESSED', 'RESOLVED', 'NEW'];
const MAX_CANDIDATES = 64;

function fail(message) { throw new Error(`Invalid structured review: ${message}`); }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value); }
function string(value, name, max = 6000, empty = false) {
  if (typeof value !== 'string' || value.length > max || (!empty && !value.trim())) fail(`${name} must be bounded text`);
  return value;
}
function strings(value, name, maxItems = 40) {
  if (!Array.isArray(value) || value.length > maxItems) fail(`${name} must be a bounded list`);
  return value.map(item => string(item, name, 2000));
}
function decode(output) {
  if (typeof output !== 'string' || output.length > 256_000) fail('expected a JSON response shorter than 256,000 characters');
  // Accept one enclosing JSON fence, never extract a convenient object from surrounding prose.
  const text = output.trim().replace(/^```(?:json)?\s*\n([\s\S]*?)\n```$/, '$1');
  let value;
  try { value = JSON.parse(text); } catch { fail('response is not a single JSON object'); }
  if (!object(value)) fail('response must be an object');
  return value;
}
function parseEvidence(value) {
  if (!Array.isArray(value) || value.length > 12) fail('evidence must contain at most 12 citations');
  return value.map(item => {
    if (!object(item)) fail('citation must be an object');
    const file = string(item.path, 'citation path', 1000);
    if (file.startsWith('/') || file.includes('\\') || file.split('/').some(part => part === '..' || part === '.' || !part) || file.includes('\0')) fail('citation path must be repository relative');
    if (!Number.isInteger(item.line) || item.line < 1 || item.line > 10_000_000) fail('citation line must be a positive integer');
    return { path: file, line: item.line, quote: string(item.quote, 'citation quote', 2000) };
  });
}

function parseAssessment(output, scope) {
  const data = decode(output);
  if (data.schemaVersion !== 1) fail('schemaVersion must be 1');
  const summary = string(data.summary, 'summary');
  const report = string(data.report, 'complete role report', 96_000);
  if (!object(data.coverage)) fail('coverage is required');
  const reviewedFiles = strings(data.coverage.reviewedFiles, 'reviewedFiles', 2000);
  const owned = scope.files && new Set(scope.files);
  if (owned && reviewedFiles.some(file => !owned.has(file))) fail('reviewedFiles includes an unassigned primary file');
  if (!Array.isArray(data.findings) || data.findings.length > 40) fail('findings must contain at most 40 candidates');
  const ids = new Set();
  const findings = data.findings.map(finding => {
    if (!object(finding)) fail('finding must be an object');
    const id = string(finding.id, 'finding ID', 100);
    if (ids.has(id)) fail('duplicate finding ID');
    ids.add(id);
    if (!SEVERITIES.includes(finding.severity) || !CONFIDENCES.includes(finding.confidence)) fail('invalid severity or confidence');
    const cwe = finding.cwe ?? '';
    if (typeof cwe !== 'string' || (cwe && !/^CWE-[1-9]\d{0,5}$/.test(cwe))) fail('invalid CWE identifier');
    const disposition = finding.disposition ?? '';
    if (!DISPOSITIONS.includes(disposition)) fail('invalid disposition');
    const evidence = parseEvidence(finding.evidence);
    if (owned && evidence.length && !evidence.some(item => owned.has(item.path))) fail('finding has no citation in its primary scope');
    return { id, title: string(finding.title, 'title', 500), severity: finding.severity, confidence: finding.confidence, cwe, disposition,
      evidence, assumptions: strings(finding.assumptions, 'assumptions'),
      rationale: string(finding.rationale, 'rationale'), remediation: string(finding.remediation, 'remediation'), validation: string(finding.validation, 'validation') };
  });
  return { summary, report, findings, coverage: { reviewedFiles: [...new Set(reviewedFiles)], limitations: strings(data.coverage.limitations, 'coverage limitations') } };
}

/** Literal quote/location checking establishes a citation, never exploitability or control effectiveness. */
function verifyEvidence(evidence, repoPath, ledger = { files: new Map(), bytes: 0 }) {
  return evidence.map(item => {
    let verified = false;
    try {
      if (!ledger.files.has(item.path)) {
        const resolved = safeResolvePath(repoPath, item.path);
        const stats = resolved && fs.statSync(resolved);
        let lines = null;
        if (stats?.isFile() && stats.size <= 2 * 1024 * 1024 && ledger.files.size < 512 && ledger.bytes + stats.size <= 32 * 1024 * 1024) {
          ledger.bytes += stats.size;
          lines = fs.readFileSync(resolved, 'utf8').replaceAll('\r\n', '\n').split('\n');
        }
        ledger.files.set(item.path, lines);
      }
      const lines = ledger.files.get(item.path);
      if (lines) {
        const quote = item.quote.replaceAll('\r\n', '\n');
        verified = lines.slice(item.line - 1, item.line - 1 + quote.split('\n').length).join('\n').includes(quote);
      }
    } catch { /* Missing, changed or unreadable evidence stays explicitly unverified. */ }
    return { ...item, verified };
  });
}

function sameCandidate(left, right) {
  const locationOverlap = left.evidence.some(item => right.evidence.some(other => item.path === other.path && item.line === other.line));
  if (!locationOverlap) return false;
  if (left.cwe && right.cwe) return left.cwe === right.cwe;
  return left.title.trim().toLowerCase() === right.title.trim().toLowerCase();
}

/** Source-order grouping; citations/CWE identify possible duplicates, never majority vote. */
function groupFindings(assessments, repoPath) {
  const groups = [], ledger = { files: new Map(), bytes: 0 };
  for (const assessment of assessments) for (const raw of assessment.findings) {
    const finding = { ...raw, evidence: verifyEvidence(raw.evidence, repoPath, ledger), participantId: assessment.participant.id, provider: assessment.participant.provider,
      model: assessment.participant.model, workerId: assessment.scope.id };
    let matches = groups.filter(group => group.observations.some(existing => sameCandidate(existing, finding))
      && group.observations.every(existing => !existing.cwe || !finding.cwe || existing.cwe === finding.cwe));
    // An unclassified observation must not bridge explicitly different weakness classes.
    // Keep the ambiguous observation separate instead of collapsing unrelated candidates.
    if (new Set(matches.flatMap(group => group.observations.map(item => item.cwe)).filter(Boolean)).size > 1) matches = [];
    let group = matches[0];
    if (!group) { group = { observations: [] }; groups.push(group); }
    group.observations.push(finding);
    // Join transitively when an additional citation bridges two existing groups.
    for (const other of matches.slice(1)) { group.observations.push(...other.observations); groups.splice(groups.indexOf(other), 1); }
  }
  if (groups.length > MAX_CANDIDATES) throw new Error(`Structured review produced more than ${MAX_CANDIDATES} distinct candidates; narrow the scope before challenging them.`);
  return groups.map((group, index) => ({ id: `OR-${String(index + 1).padStart(3, '0')}`, ...group }));
}

function parseChallenge(output, groups, repoPath) {
  const data = decode(output);
  if (data.schemaVersion !== 1 || !Array.isArray(data.responses) || data.responses.length !== groups.length) fail('challenge must address every candidate exactly once');
  const ids = new Set(groups.map(group => group.id));
  const ledger = { files: new Map(), bytes: 0 };
  const responses = data.responses.map(response => {
    if (!object(response) || !ids.delete(response.findingId)) fail('challenge has a duplicate or unknown finding ID');
    if (!['supported', 'disputed', 'unresolved'].includes(response.assessment)) fail('invalid challenge assessment');
    return { findingId: response.findingId, assessment: response.assessment, reason: string(response.reason, 'challenge reason'),
      evidence: verifyEvidence(parseEvidence(response.evidence), repoPath, ledger), assumptions: strings(response.assumptions, 'challenge assumptions') };
  });
  if (!object(data.coverage) || !['adequate', 'incomplete', 'unresolved'].includes(data.coverage.assessment)) fail('challenge must assess coverage, including when no findings were reported');
  return { responses, coverage: { assessment: data.coverage.assessment, reason: string(data.coverage.reason, 'coverage challenge reason'), assumptions: strings(data.coverage.assumptions, 'coverage challenge assumptions') } };
}

function consolidate(groups, challenges, agentId) {
  return groups.map(group => {
    const observations = group.observations;
    const responses = challenges.map(challenge => ({ participantId: challenge.participant.id, provider: challenge.participant.provider, model: challenge.participant.model,
      ...challenge.responses.find(item => item.findingId === group.id) }));
    const evidence = [...new Map(observations.flatMap(item => item.evidence).map(item => [`${item.path}:${item.line}:${item.quote}`, item])).values()];
    const confidence = observations.some(item => item.confidence === 'THEORETICAL') || !evidence.length || evidence.some(item => !item.verified) ? 'THEORETICAL' : 'PLAUSIBLE';
    const confidenceConflict = new Set(observations.map(item => item.confidence)).size > 1;
    const severityConflict = new Set(observations.map(item => item.severity)).size > 1;
    const dispositionConflict = new Set(observations.map(item => item.disposition).filter(Boolean)).size > 1;
    const disputed = responses.some(item => item.assessment === 'disputed') || dispositionConflict;
    const unresolved = responses.some(item => item.assessment === 'unresolved') || confidence === 'THEORETICAL' || observations.some(item => item.assumptions.length) || responses.some(item => item.assumptions.length);
    // Every candidate remains open. Neither votes nor a matching quote authorizes suppression/remediation.
    const disposition = agentId === 'appsec-fp-reviewer' ? 'TRUE POSITIVE' : '';
    return { id: group.id, title: observations[0].title, cwe: observations.find(item => item.cwe)?.cwe || '',
      severity: observations.reduce((highest, item) => SEVERITIES.indexOf(item.severity) > SEVERITIES.indexOf(highest) ? item.severity : highest, 'INFO'),
      confidence, disposition, status: disputed ? 'disputed' : unresolved ? 'unresolved' : 'requires-verification',
      conflicts: { confidence: confidenceConflict, severity: severityConflict, disposition: dispositionConflict }, evidence, observations, challenges: responses,
      assumptions: [...new Set([...observations.flatMap(item => item.assumptions), ...responses.flatMap(item => item.assumptions)])] };
  });
}

const inline = value => String(value).replaceAll(/[\r\n]/g, ' ').replaceAll('`', "'");
// Model prose cannot introduce authoritative report headings or override host-computed fields.
const quoted = value => String(value).split('\n').map(line => `> ${line}`).join('\n');
function renderConsolidated({ agentId, participants, assessments, findings, inventory, scopePlan, challenges = [] }) {
  const lines = [`# Consolidated Security Review: ${agentId}`, '', `**Date**: ${new Date().toISOString().slice(0, 10)}`, '**Reviewed by**: deterministic orchestration of independent model assessments', '',
    '## TIER 1 — EXECUTIVE SUMMARY', '',
    findings.length ? `${findings.length} distinct candidate finding(s) retained for verification. ${findings.filter(item => item.status === 'disputed').length} disputed; ${findings.filter(item => item.status === 'unresolved').length} unresolved.`
      : 'No candidate findings were reported within the declared reviewed scope. This is not security clearance or proof that the repository is secure.', '',
    'Model agreement is not proof. Confidence never exceeds PLAUSIBLE in this consolidation. Literal source quotes are checked against the current working tree; exploitability, fixes, and proposed tests are not validated by that check. No candidate is suppressed or marked remediated by model votes. Citation checks are bounded to 512 files, 2 MiB per file and 32 MiB total per stage; missing, mismatched, or over-budget citations stay UNVERIFIED.', '',
    '## TIER 2 — EVIDENCE AND COVERAGE', '', `Requested workers per participant: ${scopePlan.requested}; actual primary scopes per participant: ${scopePlan.scopes.length}.`,
    scopePlan.reason || '', 'Primary file assignments are disjoint. Other files may be read as supporting context; reported inspection coverage is model-declared, not independently proven.', '',
    '### Model provenance', '', ...participants.map(item => `- ${inline(item.id)}: provider ${inline(item.provider)}, model ${inline(item.model || '(provider default)')}`), '',
    '### Coverage limits', '', ...(inventory?.limitations || []).map(item => `- ${item}`)];
  for (const assessment of assessments) {
    const missing = assessment.scope.files?.filter(file => !assessment.coverage.reviewedFiles.includes(file));
    lines.push(`- ${inline(assessment.participant.id)} / ${assessment.scope.id}: ${assessment.coverage.reviewedFiles.length} primary files reported inspected; ${missing ? `${missing.length} assigned files not reported inspected` : 'shared upstream/capture scope; file coverage not inferred'}.`);
    lines.push(...assessment.coverage.limitations.map(item => `  - ${inline(item)}`));
  }
  for (const challenge of challenges) lines.push(`- Coverage challenge by ${inline(challenge.participant.id)}: ${challenge.coverage.assessment}. ${inline(challenge.coverage.reason)}`,
    ...challenge.coverage.assumptions.map(item => `  - ${inline(item)}`));
  for (const finding of findings) {
    lines.push('', `### [${finding.id}] — ${inline(finding.title)}`, '', `**Severity**: ${finding.severity}`, `**Confidence**: ${finding.confidence}`, `**Consensus status**: ${finding.status}`);
    if (finding.disposition) lines.push(`**Disposition**: ${finding.disposition}`, '**Decision basis**: CONSERVATIVE DEFAULT — UNVERIFIED; model consensus does not prove a false positive.');
    if (finding.cwe) lines.push(`**CWE**: ${finding.cwe}`);
    lines.push(`**Conflicts**: severity=${finding.conflicts.severity}; confidence=${finding.conflicts.confidence}; disposition=${finding.conflicts.disposition}`, '', '**Source citations**');
    if (!finding.evidence.length) lines.push('- No source citation supplied; finding remains THEORETICAL.');
    for (const item of finding.evidence) lines.push(`- \`${inline(item.path)}:${item.line}\` — ${item.verified ? 'literal quote matched (not exploit proof)' : 'UNVERIFIED citation'}: ${JSON.stringify(item.quote)}`);
    lines.push('', '**Assumptions and blocking evidence**', ...(finding.assumptions.length ? finding.assumptions.map(item => `- ${inline(item)}`) : ['- Independent exploit/control verification remains required.']));
    for (const observation of finding.observations) lines.push('', `**Assessment: ${inline(observation.participantId)} / ${observation.workerId}; original ID ${inline(observation.id)}**`,
      `Reported severity ${observation.severity}; confidence ${observation.confidence}; disposition ${observation.disposition || '(none)'}.`, quoted(observation.rationale),
      '', '**Proposed remediation**', quoted(observation.remediation), '', '**Regression / acceptance criteria — NOT RUN**', quoted(observation.validation));
    for (const challenge of finding.challenges) {
      lines.push('', `**Challenge: ${inline(challenge.participantId)} — ${challenge.assessment}**`, quoted(challenge.reason));
      lines.push(...challenge.evidence.map(item => `- \`${inline(item.path)}:${item.line}\` — ${item.verified ? 'literal quote matched' : 'UNVERIFIED citation'}: ${JSON.stringify(item.quote)}`));
    }
  }
  lines.push('', '## Assessment summaries', '');
  for (const assessment of assessments) lines.push(`### ${inline(assessment.participant.id)} / ${assessment.scope.id}`, quoted(assessment.summary), '');
  lines.push('## Complete specialist assessments', '', 'The following role reports are attributed model outputs, preserved for their system models, matrices, diagrams, and advisory detail. They do not override the consolidated dispositions or coverage limits above.', '');
  for (const assessment of assessments) lines.push(`### ${inline(assessment.participant.id)} / ${assessment.scope.id}`, quoted(assessment.report), '');
  return lines.join('\n');
}

module.exports = { parseAssessment, verifyEvidence, groupFindings, parseChallenge, consolidate, renderConsolidated, MAX_CANDIDATES };
