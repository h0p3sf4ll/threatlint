'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const { z } = require('zod');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
const { createFindingIntelligenceStore } = require('../lib/finding-intelligence.cjs');
const { registerFindingTools } = require('../lib/mcp-findings.cjs');

async function fixture(t) {
  const intelligence = createFindingIntelligenceStore();
  const sessions = new Map([['one', { id: 'one', repoPath: '/repo/one', reports: [] }], ['two', { id: 'two', repoPath: '/repo/two', reports: [] }]]);
  const server = new McpServer({ name: 'finding-test', version: '1' });
  const tool = (name, description, inputSchema, action, options = {}) => server.registerTool(name, {
    description, inputSchema, annotations: { readOnlyHint: options.readOnly !== false },
  }, async input => {
    try { const result = await action(input); return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: { result } }; }
    catch (error) { return { isError: true, content: [{ type: 'text', text: error.message }] }; }
  });
  registerFindingTools({ tool, z, id: z.string().min(1).max(200), intelligence,
    workspace: id => { if (!sessions.has(id)) throw new Error('Workspace not found'); return sessions.get(id); } });
  const client = new Client({ name: 'test', version: '1' });
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  t.after(async () => { await client.close(); await server.close(); });
  await server.connect(serverTransport); await client.connect(clientTransport);
  return { intelligence, sessions, client,
    call: (name, args) => client.callTool({ name, arguments: args }),
    result: async (name, args) => {
      const response = await client.callTool({ name, arguments: args });
      assert.notEqual(response.isError, true, JSON.stringify(response));
      return response.structuredContent.result;
    } };
}
const ingestion = overrides => ({ sessionId: 'one', confirm: true, source: 'guard', sourceId: 'scan-1', branch: 'main', commit: 'abc', contentDigest: 'clean', observedAt: 1000,
  findings: [{ id: 'a', ruleId: 'missing-auth', title: 'Missing authorization', severity: 'MEDIUM', evidence: [{ path: 'api.js', line: 10, quote: 'readObject(id)', verification: 'verified', verificationMethod: 'Untrusted scanner attestation' }] },
    { id: 'b', ruleId: 'read-object', title: 'Sensitive object read', severity: 'MEDIUM', path: 'api.js', line: 20 }], ...overrides });
const verified = (quote, extra = {}) => ({ path: 'api.js', line: 10, quote, verification: 'verified', verificationMethod: 'Manual source and caller inspection in the bound revision', ...extra });
const review = overrides => ({ disposition: 'TRUE POSITIVE', reason: 'Source and caller demonstrate the missing control.', at: 2000,
  newEvidence: [verified('Caller reaches the read without an ownership check.'), verified('A sensitive object is readable.', { kind: 'impact' })],
  basis: [{ claim: 'This route lacks the required ownership check.', evidenceIds: [0] }], ...overrides });

it('MCP imports bind observations to the selected workspace and never trust scanner verification', async t => {
  const f = await fixture(t);
  assert.equal((await f.call('ingest_findings', ingestion({ confirm: undefined }))).isError, true);
  assert.equal(f.intelligence.snapshot().findings.length, 0);
  const accepted = await f.result('ingest_findings', ingestion({ repo: { id: '/forged/path' }, origin: 'local-scan' }));
  assert.equal(accepted.duplicate, false);
  const finding = f.intelligence.snapshot().findings[0];
  assert.equal(finding.provenance.repo.id, '/repo/one');
  assert.equal(finding.provenance.sessionId, 'one');
  assert.equal(finding.provenance.origin, 'imported');
  assert.equal(finding.provenance.contentDigest, 'clean');
  assert.equal(finding.evidence[0].verification, 'reported');
  assert.equal((await f.result('ingest_findings', ingestion())).duplicate, true);
  assert.equal((await f.call('ingest_findings', ingestion({ sessionId: 'missing' }))).isError, true);
});

it('MCP review and resolution preserve evidence gates and reject cross-workspace batches before mutation', async t => {
  const f = await fixture(t); await f.result('ingest_findings', ingestion());
  const findings = f.intelligence.snapshot().findings;
  const args = { sessionId: 'one', findingId: findings[0].id, confirm: true, review: review() };
  assert.equal((await f.call('review_finding', { ...args, sessionId: 'two' })).isError, true);
  assert.equal((await f.call('review_finding', { ...args, confirm: undefined })).isError, true);
  assert.equal((await f.call('review_finding', { ...args, review: review({ disposition: 'FALSE POSITIVE' }) })).isError, true);
  assert.equal((await f.call('review_finding', { ...args, review: review({ newEvidence: [], basis: [{ claim: 'Scanner said it was verified.', evidenceIds: [findings[0].evidence[0].id] }] }) })).isError, true);
  assert.equal(f.intelligence.getFinding(findings[0].id).reviewHistory.length, 0);
  await f.result('review_finding', args);
  await f.result('ingest_findings', ingestion({ sessionId: 'two', sourceId: 'other' }));
  const foreign = f.intelligence.snapshot().findings.find(item => item.provenance.repo.id === '/repo/two');
  const resolution = { reason: 'The corrected ownership check passed the regression assertion.', newEvidence: [verified('Ownership assertion passes on the corrected source.', { kind: 'remediation' })],
    basis: [{ claim: 'Unauthorized reads are rejected in the corrected source.', evidenceIds: [0] }], at: 3000 };
  assert.equal((await f.call('resolve_findings', { sessionId: 'one', findingIds: [findings[0].id, foreign.id], confirm: true, review: resolution })).isError, true);
  assert.equal(f.intelligence.getFinding(findings[0].id).reviewHistory.length, 1);
  assert.equal((await f.call('resolve_findings', { sessionId: 'one', findingIds: findings.map(item => item.id), confirm: true, review: { ...resolution, newEvidence: [] } })).isError, true);
  const result = await f.result('resolve_findings', { sessionId: 'one', findingIds: findings.map(item => item.id), confirm: true, review: resolution });
  assert.equal(result.resolved.length, 2);
  assert.ok(result.resolved.every(item => item.disposition === 'REMEDIATED' && item.reviewId));
  assert.ok(result.resolved.every(item => !Object.hasOwn(item, 'evidence') && !Object.hasOwn(item, 'reviewHistory')));
});

it('MCP attack chains and offline previews enforce workspace and current decision boundaries', async t => {
  const f = await fixture(t); await f.result('ingest_findings', ingestion());
  const findings = [];
  for (const finding of f.intelligence.snapshot().findings) {
    const saved = await f.result('review_finding', { sessionId: 'one', findingId: finding.id, confirm: true, review: review() });
    assert.equal(saved.disposition, 'TRUE POSITIVE'); assert.ok(saved.reviewId);
    assert.equal(Object.hasOwn(saved, 'evidence'), false);
    findings.push(f.intelligence.getFinding(saved.id));
  }
  const input = { sessionId: 'one', confirm: true, title: 'Reach a sensitive object',
    contributors: findings.map(item => ({ findingId: item.id, role: 'vulnerability', rationale: 'Enables the object read.' })),
    links: [{ prerequisite: findings[0].id, effect: findings[1].id, rationale: 'The uncontrolled identifier reaches the sensitive read.', evidenceIds: [findings[0].evidence.find(item => item.verification === 'verified').id] }],
    impact: { severity: 'MEDIUM', description: 'A single sensitive object can be read.', evidenceIds: [findings[1].evidence.find(item => item.kind === 'impact').id] },
    complexity: { level: 'moderate', rationale: 'Requires the identifier and two requests.' }, riskRationale: 'Terminal impact remains scoped disclosure.',
    coverage: 'Source route and read inspected.', uncertainty: [], at: 3000 };
  assert.equal((await f.call('correlate_findings', { ...input, sessionId: 'two' })).isError, true);
  const composite = await f.result('correlate_findings', input);
  assert.equal(composite.severity, 'MEDIUM');
  const args = { sessionId: 'one', compositeId: composite.id };
  assert.equal((await f.result('get_composite', args)).id, composite.id);
  assert.equal((await f.call('get_composite', { ...args, sessionId: 'two' })).isError, true);
  assert.equal((await f.call('preview_composite_servicenow', { ...args, sessionId: 'two' })).isError, true);
  const before = f.intelligence.snapshot();
  assert.equal((await f.result('preview_composite_servicenow', args)).liveWritesEnabled, false);
  assert.deepEqual(f.intelligence.snapshot(), before);
  await f.result('review_finding', { sessionId: 'one', findingId: findings[0].id, confirm: true, review: review({ at: 4000, reason: 'Additional caller inspected.' }) });
  assert.equal((await f.call('preview_composite_servicenow', args)).isError, true);
});

it('MCP report synchronization preserves historical provenance and private previews require explicit opt-in', async t => {
  const f = await fixture(t);
  f.sessions.get('one').reports.push({ id: 'old', agentId: 'appsec-code-reviewer', label: 'Code Review', timestamp: 1000, findings: [ingestion().findings[0]], mdPath: '/private/report.md' });
  assert.equal((await f.call('sync_reports', { sessionId: 'one' })).isError, true);
  assert.equal((await f.call('sync_reports', { sessionId: 'two', reportIds: ['old'], confirm: true })).isError, true);
  const synced = await f.result('sync_reports', { sessionId: 'one', confirm: true });
  assert.deepEqual(synced, { imported: 1, duplicates: 0, errors: [] });
  assert.equal(JSON.stringify(synced).includes('/private/'), false);
  const finding = f.intelligence.snapshot().findings[0];
  assert.equal(finding.provenance.commit, 'unknown');
  assert.equal((await f.result('sync_reports', { sessionId: 'one', confirm: true, reportIds: ['old'] })).duplicates, 1);
  const args = { sessionId: 'one', optIn: true, subject: 'My private preview', observedChangeCount: 10,
    observations: [{ findingId: finding.id, introduced: true, introductionEvidenceIds: [], exposure: 'unknown' }] };
  assert.equal((await f.call('preview_developer_risk', { ...args, optIn: undefined })).isError, true);
  assert.equal((await f.call('preview_developer_risk', { ...args, sessionId: 'two' })).isError, true);
  const before = f.intelligence.snapshot();
  const preview = await f.result('preview_developer_risk', args);
  assert.equal(preview.persisted, false); assert.equal(preview.score, null);
  assert.deepEqual(f.intelligence.snapshot(), before);
  const tools = (await f.client.listTools()).tools;
  assert.equal(tools.find(item => item.name === 'review_finding').annotations.readOnlyHint, false);
  assert.equal(tools.find(item => item.name === 'preview_developer_risk').annotations.readOnlyHint, true);
});
