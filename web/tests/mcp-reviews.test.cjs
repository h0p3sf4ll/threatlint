'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createMcpReviews } = require('../lib/mcp-reviews.cjs');
const { createWorkspaces } = require('../lib/workspaces.cjs');
const { createPipeline } = require('../lib/pipeline.cjs');
const { createStore } = require('../lib/store.cjs');
const { createReportWriter } = require('../lib/report-writer.cjs');
const { createConversations } = require('../lib/chat.cjs');
const { convertToWord } = require('./helpers/docx.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => { let resolve; const promise = new Promise(yes => { resolve = yes; }); return { promise, resolve }; };
const settings = { provider: 'lmstudio', model: 'fixture' };

function fixture(t, override, limits = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-mcp-review-'));
  const store = createStore(root), workspaces = createWorkspaces({ store });
  const { sessionId } = workspaces.open({ repoPath: root });
  const reports = createReportWriter(store, { convertToWord });
  const pipeline = createPipeline({ sessions: store.sessions, reports, override });
  const jobs = createMcpReviews({ store, pipeline, ...limits });
  t.after(async () => { await jobs.close(); await pipeline.close(); fs.rmSync(root, { recursive: true, force: true }); });
  return { root, store, sessionId, reports, pipeline, jobs, workspaces };
}
async function finished(jobs, sessionId, id) {
  for (let i = 0; i < 100; i++) {
    const job = jobs.get(sessionId, id);
    if (job.finishedAt !== null) return job;
    await tick();
  }
  assert.fail('Background review did not settle');
}

test('a fresh profile can open a folder, review source and retrieve saved report references without a UI', async t => {
  const observed = [];
  const { sessionId, reports, jobs, workspaces } = fixture(t, async args => {
    observed.push(args);
    args.onEvent({ type: 'tool_executing', tool: 'Read', input: { file_path: 'private-source' }, id: 'tool-1' });
    args.onEvent({ type: 'text_chunk', text: 'Raw intermediate model output' });
    return '# Code review\nNo material findings in the synthetic fixture.\n';
  });
  const started = jobs.start({ sessionId, agentIds: ['appsec-code-reviewer'], ...settings });
  assert.equal(started.status, 'running');
  const result = await finished(jobs, sessionId, started.id);
  assert.equal(result.status, 'completed');
  assert.equal(observed.length, 1);
  assert.match(observed[0].systemPrompt, /no changes may be applied/i);
  assert.equal(result.reports.length, 1);
  assert.equal(result.reports[0].sessionId, sessionId);
  assert.match(reports.read(reports.find(result.reports[0].id).report).markdown, /synthetic fixture/);
  assert.equal(workspaces.get(sessionId).reportCount, 1);
  assert.equal(JSON.stringify(result).includes('private-source'), false);
  assert.equal(JSON.stringify(result).includes('Raw intermediate'), false);
  assert.ok(result.events.some(event => event.type === 'tool_executing' && event.tool === 'Read'));
});

test('provider validation failures become terminal jobs; secrets and raw tool payloads are never retained', async t => {
  const secret = 'synthetic-provider-secret';
  const { sessionId, jobs } = fixture(t, async args => {
    args.onEvent({ type: 'tool_executing', tool: 'Read', input: { content: secret }, apiKey: secret });
    throw new Error(`Provider rejected ${secret}`);
  });
  const failed = jobs.start({ sessionId, agentIds: ['appsec-code-reviewer'], ...settings, apiKey: secret });
  const result = await finished(jobs, sessionId, failed.id);
  assert.equal(result.status, 'failed');
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.ok(result.events.some(event => event.type === 'agent_error' && event.message.includes('[REDACTED]')));
  const invalid = jobs.start({ sessionId, agentIds: ['appsec-code-reviewer'], provider: 'unknown' });
  assert.match((await finished(jobs, sessionId, invalid.id)).error, /Unknown model provider/);
});

test('workspace boundaries, pipeline busy guards, cancellation and shutdown remain effective', async t => {
  const gate = deferred();
  const { sessionId, jobs, store } = fixture(t, async () => { await gate.promise; return '# Review\nNo findings.\n'; });
  const other = store.create(store.sessions.get(sessionId).repoPath);
  const first = jobs.start({ sessionId, agentIds: ['appsec-code-reviewer'], ...settings });
  await tick();
  assert.throws(() => jobs.get(other, first.id), /not found in this workspace/);
  assert.throws(() => jobs.cancel(other, first.id), /not found in this workspace/);
  const duplicate = jobs.start({ sessionId: other, agentIds: ['appsec-code-reviewer'], ...settings });
  assert.match((await finished(jobs, other, duplicate.id)).error, /active review/);
  assert.equal(jobs.cancel(sessionId, first.id).status, 'cancelling');
  await tick();
  assert.equal(jobs.get(sessionId, first.id).finishedAt, null, 'cancellation waits for the provider to drain');
  gate.resolve();
  assert.equal((await finished(jobs, sessionId, first.id)).status, 'cancelled');
  await jobs.close();
  assert.throws(() => jobs.start({ sessionId, agentIds: ['appsec-code-reviewer'], ...settings }), /closing/);
});

test('event and job history are bounded with explicit cursors and pagination', async t => {
  const { sessionId, jobs } = fixture(t, async args => {
    for (let n = 0; n < 10; n++) args.onEvent({ type: 'iteration', n });
    return '# Review\nNo findings.\n';
  }, { maxEvents: 3, maxJobs: 2 });
  const first = jobs.start({ sessionId, agentIds: ['appsec-code-reviewer'], ...settings });
  await finished(jobs, sessionId, first.id);
  const page = jobs.get(sessionId, first.id, { limit: 1 });
  assert.equal(page.eventsTruncated, true);
  assert.equal(page.events.length, 1);
  assert.equal(page.hasMore, true);
  const next = jobs.get(sessionId, first.id, { after: page.nextCursor });
  assert.equal(next.eventsTruncated, false);
  assert.equal(next.events.length, 2);
  assert.throws(() => jobs.get(sessionId, first.id, { after: next.latestCursor + 1 }), /beyond/);
  for (let n = 0; n < 2; n++) {
    const job = jobs.start({ sessionId, agentIds: ['appsec-code-reviewer'], ...settings });
    await finished(jobs, sessionId, job.id);
  }
  assert.equal(jobs.list(sessionId).total, 2);
  assert.throws(() => jobs.get(sessionId, first.id), /not found/);
  assert.equal(jobs.list(sessionId, { limit: 1 }).nextOffset, 1);
});

test('conversation jobs expose a workspace-bound conversation reference and omit tool arguments', async t => {
  const { store, reports, sessionId, pipeline } = fixture(t, async () => '# unused');
  const conversations = createConversations({ store, reports, runtime: {}, override: async args => {
    args.onEvent({ type: 'tool_executing', tool: 'Read', input: { file_path: 'sensitive-source-path' } });
    return 'Answer cites app.py:1. Proposed tests are NOT RUN.';
  } });
  const jobs = createMcpReviews({ store, pipeline, conversations });
  t.after(() => jobs.close());
  const started = jobs.start({ sessionId, question: 'Explain the current code', ...settings }, 'conversation');
  const result = await finished(jobs, sessionId, started.id);
  assert.equal(result.kind, 'conversation'); assert.equal(result.status, 'completed');
  assert.match(conversations.get(result.conversationId).messages.at(-1).content, /app.py:1/);
  assert.equal(JSON.stringify(result).includes('sensitive-source-path'), false);
  const other = store.create(store.sessions.get(sessionId).repoPath);
  assert.throws(() => jobs.start({ sessionId: other, conversationId: result.conversationId, question: 'Continue', ...settings }, 'conversation'), /not found in this workspace/);
});

test('scanner reviews share the bounded job lifecycle and preserve actual report workspace references', async () => {
  const store = { sessions: new Map([['workspace', {}]]) };
  const jobs = createMcpReviews({ store, scannerBatch: { run: async (_message, send) => {
    send({ type: 'scanner_item', stage: 'reported', report: { id: 'report', sessionId: 'scanner-session', agentId: 'appsec-fp-reviewer' } });
    send({ type: 'scanner_batch_complete', cancelled: false });
  } } });
  const result = await finished(jobs, 'workspace', jobs.start({ sessionId: 'workspace' }, 'scanner_review').id);
  assert.equal(result.status, 'completed'); assert.equal(result.reports[0].sessionId, 'scanner-session');
  await jobs.close();
});
