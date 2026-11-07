'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const express = require('express');
const { createFindingIntelligenceStore, normalizeIngestion, ingestionFromScan, ingestionFromReport } = require('../lib/finding-intelligence.cjs');
const { serviceNowPreview, developerRiskPreview } = require('../lib/finding-intelligence-previews.cjs');
const { assessChainPriority } = require('../lib/finding-intelligence-graph.cjs');
const { registerFindingIntelligenceRoutes } = require('../lib/routes/finding-intelligence.cjs');

function ingestion(overrides = {}) {
  return { repo: { id: '/repos/shop', name: 'shop' }, branch: 'main', commit: 'abc123', contentDigest: 'clean-digest',
    source: 'guard', sourceId: 'scan-1', observedAt: 1000, coverage: { status: 'partial', scope: 'SAST baseline' },
    findings: [{ id: 'a', ruleId: 'missing-auth', fingerprint: 'stable-a', title: 'Missing authorization', severity: 'MEDIUM',
      confidence: 'PATTERN_MATCH', path: 'api.js', line: 10, snippet: 'readObject(id)', recommendation: 'Enforce resource ownership.' }], ...overrides };
}
function verified(quote, extra = {}) {
  return { path: 'api.js', line: 10, quote, verification: 'verified', verificationMethod: 'Manual source and caller review in the bound revision', ...extra };
}
function review(store, id, overrides = {}) {
  return store.review(id, { disposition: 'TRUE POSITIVE', reason: 'Source and caller demonstrate the missing control.',
    newEvidence: [verified('No ownership check precedes this read.')], basis: [{ claim: 'The route is reachable without ownership verification.', evidenceIds: [0] }], at: 2000, ...overrides });
}
function chainFixture() {
  const store = createFindingIntelligenceStore();
  const raw = ingestion().findings[0];
  store.ingest(ingestion({ findings: [raw, { ...raw, id: 'b', fingerprint: 'stable-b', ruleId: 'leaked-id', title: 'Identifier disclosed', line: 20 },
    { ...raw, id: 'c', fingerprint: 'stable-c', ruleId: 'object-read', title: 'Sensitive object readable', line: 30 }] }));
  const findings = store.snapshot().findings.map((finding, index) => review(store, finding.id, {
    newEvidence: [verified(`Verified component ${index} with its reachability.`, { line: (index + 1) * 10 }),
      verified(`Observed impact for component ${index}: one sensitive object read.`, { line: (index + 1) * 10, kind: 'impact' })],
  }));
  const evidence = index => findings[index].evidence.find(item => item.verification === 'verified' && item.kind === 'source').id;
  const input = { title: 'Reach and read another object', contributors: findings.map(finding => ({ findingId: finding.id, role: 'vulnerability', rationale: 'Enables the next step.' })),
    links: [{ prerequisite: findings[0].id, effect: findings[1].id, rationale: 'The route exposes the identifier.', evidenceIds: [evidence(0)] },
      { prerequisite: findings[1].id, effect: findings[2].id, rationale: 'The identifier reaches the object read.', evidenceIds: [evidence(1)] }],
    impact: { severity: 'MEDIUM', description: 'Read one sensitive object with the disclosed identifier.', evidenceIds: [findings[2].evidence.find(item => item.kind === 'impact').id] },
    complexity: { level: 'moderate', rationale: 'The attacker needs the disclosed identifier and two requests.' },
    riskRationale: 'The terminal impact is a scoped disclosure; component count does not determine impact.', coverage: 'Route, identifier response, and object read reviewed.',
    uncertainty: ['Production authorization gateway is not observable in source.'], at: 3000 };
  return { store, findings, input };
}

describe('Finding intelligence provenance and deduplication', () => {
  it('deduplicates repeated observations but retains repository, branch, revision and engine boundaries', () => {
    const store = createFindingIntelligenceStore();
    assert.equal(store.ingest(ingestion()).duplicate, false);
    assert.equal(store.ingest(ingestion({ observedAt: 9000 })).duplicate, true);
    store.ingest(ingestion({ sourceId: 'scan-2', observedAt: 2000 }));
    assert.equal(store.snapshot().findings.length, 1);
    assert.equal(store.snapshot().findings[0].observationIds.length, 2);
    store.ingest(ingestion({ sourceId: 'scan-3', commit: 'def456' }));
    store.ingest(ingestion({ sourceId: 'scan-4', branch: 'release' }));
    store.ingest(ingestion({ sourceId: 'scan-5', contentDigest: 'dirty-files' }));
    store.ingest(ingestion({ sourceId: 'scan-6', repo: { id: '/other/shop' } }));
    store.ingest(ingestion({ sourceId: 'scan-7', source: 'other-engine' }));
    assert.equal(store.snapshot().findings.length, 6);
    assert.equal(new Set(store.snapshot().findings.slice(0, 4).map(finding => finding.lineageId)).size, 1);
  });
  it('isolates unknown revisions and refuses silent replacement of a source revision', () => {
    const store = createFindingIntelligenceStore();
    store.ingest(ingestion({ commit: undefined }));
    store.ingest(ingestion({ commit: undefined, sourceId: 'scan-2' }));
    assert.equal(store.snapshot().findings.length, 2);
    assert.throws(() => store.ingest(ingestion({ commit: undefined, findings: [] })), /different content/);
  });
  it('never trusts scanner verification or imports a historical report into the current revision', () => {
    const raw = ingestion();
    raw.findings[0].evidence = [verified('A scanner cannot attest a reviewed decision.')];
    assert.equal(normalizeIngestion(raw).findings[0].evidence[0].verification, 'reported');
    const session = { id: 'session', repoPath: '/repos/shop', branch: 'today', commit: 'today' };
    const normalized = normalizeIngestion(ingestionFromReport({ id: 'report', timestamp: 1000, findings: raw.findings }, session));
    assert.equal(normalized.provenance.branch, 'unknown');
    assert.equal(normalized.provenance.commit, 'unknown');
  });
  it('preserves unavailable engine coverage and incomplete scan state', () => {
    const result = normalizeIngestion(ingestionFromScan({ id: 'scan', status: 'partial', startedAt: 1000,
      binding: { branch: 'main', commit: 'abc', contentDigest: 'digest' }, findings: [],
      observedAt: '2026-11-07T12:00:00.000Z', coverage: { status: 'partial', scope: 'Supported current text files', limitations: ['Excluded and oversized files were not scanned.'] },
      engines: [{ id: 'guard', status: 'completed' }, { id: 'trivy', status: 'unavailable', detail: 'Not installed' }] }, { id: 'session', repoPath: '/repos/shop' }));
    assert.equal(result.coverage.status, 'partial');
    assert.match(result.coverage.limitations.join(' '), /trivy: unavailable/);
    assert.match(result.coverage.limitations.join(' '), /Excluded and oversized/);
    assert.match(result.coverage.scope, /Supported current text files/);
    assert.equal(result.observedAt, Date.parse('2026-11-07T12:00:00.000Z'));
  });
  it('retains unknown severities and conflicting observations without rewriting historical priority', () => {
    const store = createFindingIntelligenceStore(), raw = ingestion().findings[0];
    store.ingest(ingestion({ findings: [{ ...raw, severity: 'UNKNOWN' }] }));
    assert.equal(store.overview().summary.unknownSeverity, 1);
    store.ingest(ingestion({ sourceId: 'scan-2', observedAt: 2000, findings: [{ ...raw, severity: 'LOW' }] }));
    store.ingest(ingestion({ sourceId: 'scan-3', observedAt: 3000, findings: [{ ...raw, severity: 'HIGH' }] }));
    store.ingest(ingestion({ sourceId: 'scan-4', observedAt: 4000, findings: [{ ...raw, severity: 'LOW' }] }));
    assert.equal(store.snapshot().findings.length, 1);
    assert.equal(store.snapshot().findings[0].observations.length, 4);
    assert.equal(store.overview().findings[0].severity, 'HIGH');
    assert.equal(store.overview().findings[0].severityConflict, true);
    assert.deepEqual(store.overview().trends.map(point => point.openRiskPoints), [0, 1, 6, 6]);
  });
  it('persists immutable decisions and returns detached snapshots', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'intelligence-test-'));
    try {
      const store = createFindingIntelligenceStore({ directory });
      store.ingest(ingestion());
      review(store, store.snapshot().findings[0].id);
      const snapshot = store.snapshot(); snapshot.findings[0].reviewHistory.length = 0;
      assert.equal(createFindingIntelligenceStore({ directory }).snapshot().findings[0].reviewHistory.length, 1);
      assert.equal(fs.statSync(path.join(directory, 'finding-intelligence.json')).mode & 0o777, 0o600);
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  });
});

describe('Evidence-gated reviews and attack chains', () => {
  it('calculates all impact/complexity priority combinations without lowering impact or boosting uncertainty', () => {
    const matrix = { CRITICAL: [['CRITICAL', 10], ['HIGH', 7.5], ['HIGH', 5]], HIGH: [['HIGH', 6], ['HIGH', 4.5], ['MEDIUM', 3]],
      MEDIUM: [['MEDIUM', 3], ['MEDIUM', 2.25], ['LOW', 1.5]], LOW: [['LOW', 1], ['LOW', 0.75], ['LOW', 0.5]] };
    for (const [impact, cells] of Object.entries(matrix)) for (const [index, complexity] of ['low', 'moderate', 'high'].entries()) {
      const result = assessChainPriority(impact, complexity, []);
      assert.equal(result.impactSeverity, impact); assert.equal(result.cvss, false);
      assert.deepEqual([result.priority, result.points], cells[index]); assert.equal(result.provisional, false);
      const uncertain = assessChainPriority(impact, complexity, ['Runtime prerequisite is unknown.']);
      assert.equal(uncertain.points, result.points); assert.equal(uncertain.priority, result.priority); assert.equal(uncertain.provisional, true);
    }
  });
  it('requires new substantive refuting evidence to reopen a false positive and preserves the original decision', () => {
    const store = createFindingIntelligenceStore(); store.ingest(ingestion());
    const id = store.snapshot().findings[0].id;
    const original = review(store, id, { disposition: 'FALSE POSITIVE', safeBehavior: 'The reviewed caller enforces ownership.',
      newEvidence: [verified('Caller enforces owner === principal.')], basis: [{ claim: 'All callers enforce ownership.', evidenceIds: [0] }] });
    assert.throws(() => review(store, id, { at: 3000 }), /refuting its original decision basis/);
    assert.throws(() => review(store, id, { at: 3000, newEvidence: [verified('Caller enforces owner === principal.', { refutes: original.reviewHistory[0].basis[0].id })] }), /refuting/);
    assert.throws(() => review(store, id, { at: 3000, newEvidence: [verified('Caller enforces owner === principal.', {
      kind: 'impact', verificationMethod: 'A renamed review method', refutes: original.reviewHistory[0].basis[0].id })] }), /refuting/,
    'changing purpose or verification metadata must not turn an old quote into substantively new evidence');
    const updated = review(store, id, { at: 3000, newEvidence: [verified('An additional reachable caller lacks ownership enforcement.', { refutes: original.reviewHistory[0].basis[0].id })] });
    assert.equal(updated.reviewHistory.length, 2);
    assert.deepEqual(updated.reviewHistory[0], original.reviewHistory[0]);
    assert.equal(updated.reviewHistory[1].disposition, 'TRUE POSITIVE');
  });
  it('does not permit reported evidence, unknown evidence, or a safe-behavior label alone to close a finding', () => {
    const store = createFindingIntelligenceStore(); store.ingest(ingestion());
    const finding = store.snapshot().findings[0];
    assert.throws(() => review(store, finding.id, { disposition: 'FALSE POSITIVE', safeBehavior: 'safe', newEvidence: [], basis: [{ claim: 'safe', evidenceIds: [finding.evidence[0].id] }] }), /verified evidence/);
    assert.throws(() => review(store, finding.id, { basis: [{ claim: 'safe', evidenceIds: ['missing'] }] }), /unknown evidence/);
    assert.throws(() => review(store, finding.id, { disposition: 'FALSE POSITIVE' }), /verified safe behavior/);
    assert.throws(() => review(store, finding.id, { disposition: 'REMEDIATED' }), /remediation evidence/);
    const reviewed = review(store, finding.id);
    assert.throws(() => review(store, finding.id, { at: 3000, disposition: 'REMEDIATED', newEvidence: [verified('The fixed revision passes the ownership assertion.', { kind: 'remediation' })],
      basis: [{ claim: 'The old source demonstrated the issue, not its remediation.', evidenceIds: [reviewed.evidence.find(item => item.verification === 'verified').id] }] }), /basis must cite/);
    assert.throws(() => review(store, finding.id, { reason: '   ' }), /decision rationale is required/);
    assert.throws(() => review(store, finding.id, { basis: [{ claim: '   ', evidenceIds: [0] }] }), /basis claim is required/);
  });
  it('retains the three medium contributors and assesses terminal impact without severity inflation', () => {
    const { store, findings, input } = chainFixture();
    const before = store.overview().summary.openRiskPoints;
    const composite = store.correlate(input);
    assert.equal(composite.severity, 'MEDIUM');
    assert.equal(composite.confidence, 'PLAUSIBLE');
    assert.equal(composite.riskAssessment.points, 2.25);
    assert.equal(composite.riskAssessment.provisional, true);
    assert.equal(composite.contributors.length, 3);
    assert.ok(store.snapshot().findings.every(item => item.severity === 'MEDIUM'));
    assert.equal(store.overview().summary.openRiskPoints, before);
    assert.equal(store.correlate({ ...input, contributors: [...input.contributors].reverse(), links: [...input.links].reverse() }).id, composite.id);
    assert.throws(() => store.correlate({ ...input, impact: { ...input.impact, evidenceIds: [findings[0].evidence[0].id] } }), /unknown evidence/);
    assert.throws(() => store.correlate({ ...input, impact: null }), /impact severity/);
    const criticalImpact = store.correlate({ ...input, impact: { ...input.impact, severity: 'CRITICAL' },
      riskRationale: 'Explicit reviewer assessment of critical terminal impact, independent from medium component scores.' });
    assert.equal(criticalImpact.severity, 'CRITICAL'); assert.equal(criticalImpact.riskAssessment.priority, 'HIGH');
    assert.ok(store.snapshot().findings.every(item => item.severity === 'MEDIUM'));
    assert.equal(store.overview().chainSummary.criticalImpact, 1);
    assert.equal(store.overview().chainSummary.maxContextualPriorityPoints, 7.5);
    assert.equal(store.overview().summary.openRiskPoints, before);
  });
  it('rejects cyclic, disconnected, unverified, and cross-revision chains', () => {
    const { store, findings, input } = chainFixture();
    assert.throws(() => store.correlate({ ...input, links: [input.links[0]] }), /terminal effect/);
    assert.throws(() => store.correlate({ ...input, links: [...input.links, { ...input.links[0], prerequisite: findings[2].id, effect: findings[0].id }] }), /terminal effect|cycles/);
    assert.throws(() => store.correlate({ ...input, links: [{ ...input.links[0], evidenceIds: [findings[0].evidence[0].id] }, input.links[1]] }), /verified evidence/);
    store.ingest(ingestion({ sourceId: 'later-scan', commit: 'other' }));
    const other = store.snapshot().findings.at(-1); review(store, other.id);
    assert.throws(() => store.correlate({ ...input, contributors: [input.contributors[0], { ...input.contributors[1], findingId: other.id }] }), /revision boundaries/);
  });
  it('keeps standalone FP and contextual relevance distinct from chain true positive', () => {
    const { store, findings, input } = chainFixture();
    review(store, findings[0].id, { disposition: 'FALSE POSITIVE', at: 2500, safeBehavior: 'Identifier disclosure is intended for this caller.',
      newEvidence: [verified('Identifier is public context, not sensitive alone.')], basis: [{ claim: 'No standalone sensitive-data disclosure.', evidenceIds: [0] }] });
    assert.throws(() => store.correlate(input), /true positive review/);
    const composite = store.correlate({ ...input, contributors: input.contributors.map((node, index) => ({ ...node, role: index ? 'vulnerability' : 'context' })) });
    assert.equal(composite.disposition, 'CHAIN TRUE POSITIVE');
    assert.equal(composite.contributors.find(node => node.findingId === findings[0].id).relevance, 'contextual-false-positive');
    assert.equal(store.getFinding(findings[0].id).reviewHistory.at(-1).disposition, 'FALSE POSITIVE');
  });
});

describe('Conservative trends and offline previews', () => {
  it('scopes summaries, trends, and chains to branch and revision without making historical chains current', () => {
    const { store, input } = chainFixture(); const chain = store.correlate(input);
    store.ingest(ingestion({ sourceId: 'next-revision', commit: 'next', observedAt: 4000 }));
    store.ingest(ingestion({ sourceId: 'release-empty', branch: 'release', commit: 'release', observedAt: 5000, findings: [] }));
    const old = store.overview({ repoId: '/repos/shop', branch: 'main', commit: 'abc123', contentDigest: 'clean-digest' });
    assert.equal(old.summary.open, 3); assert.equal(old.composites[0].id, chain.id);
    assert.equal(old.composites[0].assessmentStatus, 'historical-revision'); assert.equal(old.chainSummary.current, 0);
    assert.ok(old.trends.every(point => point.at < 4000));
    const current = store.overview({ branch: 'main', commit: 'next', contentDigest: 'clean-digest' });
    assert.equal(current.summary.open, 1); assert.equal(current.composites.length, 0);
    assert.deepEqual(current.trends.map(point => point.openRiskPoints), [3]);
    const release = store.overview({ branch: 'release' });
    assert.equal(release.summary.open, 0); assert.equal(release.observations.length, 1);
    assert.equal(release.observations[0].provenance.commit, 'release', 'empty scans retain selectable revision metadata');
  });
  it('never treats scan absence as remediation and shows only evidenced improvement', () => {
    const store = createFindingIntelligenceStore(); store.ingest(ingestion());
    store.ingest(ingestion({ sourceId: 'scan-2', commit: 'next', observedAt: 3000, findings: [], coverage: { status: 'complete', scope: 'SAST' } }));
    assert.equal(store.overview().summary.open, 1);
    assert.equal(store.overview().repositories[0].branches[0].notReobserved, 1);
    assert.ok(store.overview().trends.every(point => point.openRiskPoints === 3));
    const finding = store.snapshot().findings[0];
    review(store, finding.id, { disposition: 'REMEDIATED', at: 4000, newEvidence: [verified('Ownership regression assertion passes for the corrected dataflow.', { kind: 'remediation' })] });
    assert.equal(store.overview().summary.verifiedRemediated, 1);
    assert.equal(store.overview().trends.at(-1).openRiskPoints, 0);
    assert.equal(store.overview().trends[0].openRiskPoints, 3);
    store.ingest(ingestion({ sourceId: 'scan-3', commit: 'newer', observedAt: 5000 }));
    assert.equal(store.overview().summary.open, 1, 'remediation on an older occurrence cannot close a recurrence');
  });
  it('exports stable parent and related keys without changing state or making network writes', () => {
    const { store, input } = chainFixture(); const composite = store.correlate(input);
    const before = store.snapshot();
    const first = serviceNowPreview(composite, before.findings);
    assert.deepEqual(first, serviceNowPreview(composite, before.findings));
    assert.equal(first.liveWritesEnabled, false);
    assert.equal(first.related.length, 3);
    assert.equal(first.parent.contextualPriority.points, 2.25);
    assert.equal(first.parent.attackPath.length, 2);
    assert.equal(first.parent.attackPath[0].prerequisiteFindingKey, `threatlint:finding:${input.links.slice().sort((a, b) => `${a.prerequisite}|${a.effect}`.localeCompare(`${b.prerequisite}|${b.effect}`))[0].prerequisite}`);
    for (const link of input.links) {
      assert.match(first.parent.work_notes, new RegExp(link.rationale.replaceAll('.', '\\.')));
      assert.ok(first.related.find(item => item.findingId === link.prerequisite).work_notes.includes(link.effect));
      assert.ok(first.related.find(item => item.findingId === link.effect).work_notes.includes(link.prerequisite));
    }
    assert.deepEqual(first.parent.provenance, composite.provenance);
    assert.ok(first.related.every(item => item.evidence.every(evidence => !Object.hasOwn(evidence, 'quote'))));
    assert.equal(new Set(first.related.map(item => item.idempotencyKey)).size, 3);
    assert.deepEqual(store.snapshot(), before);
    const changedFindings = structuredClone(before.findings); changedFindings[0].severity = 'HIGH';
    assert.notEqual(serviceNowPreview(composite, changedFindings).exportDigest, first.exportDigest, 'the digest covers exported data, not only record keys');
    review(store, before.findings[0].id, { at: 4000, reason: 'Additional caller reviewed.' });
    assert.throws(() => serviceNowPreview(composite, store.snapshot().findings), /reassess/);
  });
  it('requires opt-in and verified introduction evidence, deduplicates inputs, and returns confidence limits', () => {
    const store = createFindingIntelligenceStore(); store.ingest(ingestion()); const finding = store.snapshot().findings[0];
    assert.equal(developerRiskPreview([finding], {}).score, null);
    const reviewed = review(store, finding.id, { newEvidence: [verified('Observed before/after change introduced the missing ownership check.', { kind: 'introduction' }), verified('Route is reachable from the public gateway.')] });
    const introduction = reviewed.evidence.find(item => item.kind === 'introduction');
    const exposure = reviewed.evidence.find(item => item.verification === 'verified' && item.kind === 'source');
    const record = { findingId: finding.id, introduced: true, introductionEvidenceIds: [introduction.id], exposure: 'internet', exposureEvidenceIds: [exposure.id] };
    const input = { optIn: true, subject: 'My private coaching preview', observedChangeCount: 10, observations: [record, record] };
    const result = developerRiskPreview(store.snapshot().findings, input);
    assert.equal(result.includedIssues, 1); assert.equal(result.excluded.length, 1); assert.equal(result.score, 5);
    assert.equal(result.confidence, 'low'); assert.equal(result.persisted, false);
    assert.equal(developerRiskPreview(store.snapshot().findings, { ...input, observedChangeCount: 2 }).score, null);
    assert.equal(developerRiskPreview(store.snapshot().findings, { ...input, observations: [{ ...record, introductionEvidenceIds: [] }] }).score, null);
    assert.equal(developerRiskPreview(store.snapshot().findings, { ...input, observations: [{ ...record, introductionEvidenceIds: [] }, record] }).includedIssues, 1,
      'an invalid duplicate cannot hide a later eligible observation');
    review(store, finding.id, { disposition: 'REMEDIATED', at: 4000, newEvidence: [verified('The authorization regression passes.', { kind: 'remediation' })] });
    assert.ok(developerRiskPreview(store.snapshot().findings, input).score < result.score);
  });
  it('allows multiple issues per reviewed change and does not treat cross-engine rule-name collisions as recurrence', () => {
    const store = createFindingIntelligenceStore(), raw = ingestion().findings[0];
    store.ingest(ingestion({ findings: [{ ...raw, source: 'one' }, { ...raw, source: 'two' }] }));
    const findings = store.snapshot().findings.map(finding => review(store, finding.id, { newEvidence: [verified('Verified introducing change.', { kind: 'introduction' })] }));
    const input = { optIn: true, subject: 'My private preview', observedChangeCount: 1, observations: findings.map(finding => ({ findingId: finding.id, introduced: true,
      introductionEvidenceIds: finding.evidence.filter(item => item.kind === 'introduction').map(item => item.id), exposure: 'unknown' })) };
    const result = developerRiskPreview(findings, input);
    assert.equal(result.includedIssues, 2); assert.equal(result.score, null);
    assert.ok(result.details.every(item => item.recurrenceFactor === 1));
  });
});

describe('Intelligence routes bind repository scope to workspace sessions', () => {
  it('overrides imported repository identity and rejects reads/reviews through a different workspace', async () => {
    const intelligence = createFindingIntelligenceStore();
    const store = { sessions: new Map([['shop', { id: 'shop', repoPath: '/repos/shop', reports: [] }], ['other', { id: 'other', repoPath: '/repos/other', reports: [] }]]) };
    const app = express(); app.use(express.json()); registerFindingIntelligenceRoutes(app, { intelligence, store });
    const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const post = (url, body) => fetch(`${base}${url}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    try {
      const response = await post('/api/intelligence/ingestions', { ...ingestion({ repo: { id: '/forged/repo' } }), sessionId: 'shop' });
      assert.equal(response.status, 201);
      const finding = intelligence.snapshot().findings[0];
      assert.equal(finding.provenance.repo.id, '/repos/shop'); assert.equal(finding.provenance.origin, 'imported');
      assert.equal((await fetch(`${base}/api/intelligence/findings/${finding.id}?sessionId=other`)).status, 404);
      assert.equal((await post(`/api/intelligence/findings/${finding.id}/reviews`, { sessionId: 'other' })).status, 404);
      assert.equal((await fetch(`${base}/api/intelligence/overview?sessionId=missing`)).status, 404);
      assert.equal((await post('/api/intelligence/sync', { sessionId: 'shop' })).status, 200);
      intelligence.ingest(ingestion({ sourceId: 'release-import', branch: 'release', findings: [] }));
      const filtered = await (await fetch(`${base}/api/intelligence/overview?sessionId=shop&branch=release&commit=abc123&contentDigest=clean-digest`)).json();
      assert.equal(filtered.summary.findings, 0); assert.equal(filtered.observations.length, 1);
      assert.equal(filtered.observations[0].provenance.branch, 'release');
    } finally { await new Promise(resolve => server.close(resolve)); }
  });
});
