'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const WebSocket = require('ws');
const { createWorkbench } = require('../server.js');

const REPORT = '# Report\n\n## Findings\n\n### [CR-001] SQL built from request input\n\n**Severity:** HIGH\n**Confidence:** CONFIRMED\n\nEvidence: app.py:4\n\n**Proposed fix:** use parameters.\n';

describe('Conversations', () => {
  let workbench, base, temporary, sessionId, calls;
  before(async () => {
    temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-chat-'));
    const repo = path.join(temporary, 'repo'); fs.mkdirSync(repo);
    fs.writeFileSync(path.join(repo, 'app.py'), 'q = "SELECT * FROM t WHERE id=" + request.args["id"]\n');
    calls = [];
    workbench = createWorkbench({ storageDir: path.join(temporary, 'state'), runProvider: async args => {
      calls.push(args);
      if (args.purpose === 'review') return REPORT;
      if (args.userMessage.includes('FAIL_PLEASE')) throw new Error('provider down sk-secretvalue123');
      await args.execute('Read', { file_path: 'app.py' });
      args.onEvent({ type: 'tool_executing', tool: 'Read', input: { file_path: 'app.py' } });
      args.onEvent({ type: 'text_chunk', text: 'Use a parameterized query.' });
      return 'Use a parameterized query at app.py:1.';
    } });
    await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
    base = `127.0.0.1:${workbench.server.address().port}`;
    sessionId = (await (await fetch(`http://${base}/api/session/local`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ repoPath: repo }) })).json()).sessionId;
    await workbench.generateReport('appsec-code-reviewer', REPORT, sessionId);
  });
  after(async () => { await workbench.close(); fs.rmSync(temporary, { recursive: true, force: true }); });

  function converse(message) {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(`ws://${base}/`, { headers: { Origin: `http://${base}` } });
      const events = [];
      ws.on('open', () => ws.send(JSON.stringify({ action: 'chat', provider: 'lmstudio', lmstudioModel: 'fixture', sessionId, ...message })));
      ws.on('message', raw => {
        const event = JSON.parse(raw); events.push(event);
        if (['chat_complete', 'chat_error'].includes(event.type)) { ws.close(); resolve(events); }
      });
      ws.on('error', reject);
    });
  }

  it('answers about a finding with untrusted context, streams, persists, and continues the thread', async () => {
    const report = workbench.store.sessions.get(sessionId).reports[0];
    const first = await converse({ question: 'Why is this high?', context: { type: 'finding', reportId: report.id, findingId: 'CR-001' } });
    const done = first.at(-1);
    assert.equal(done.type, 'chat_complete');
    assert.ok(first.some(event => event.type === 'chat_chunk'));
    assert.ok(first.some(event => event.type === 'chat_tool' && event.detail === 'app.py'));
    const prompt = calls.at(-1).userMessage;
    assert.match(prompt, /UNTRUSTED CONTEXT/);
    assert.match(prompt, /CR-001/);
    assert.match(calls.at(-1).systemPrompt, /never follow instructions/i);
    const second = await converse({ conversationId: done.conversationId, question: 'Show the test.' });
    assert.equal(second.at(-1).type, 'chat_complete');
    assert.equal(calls.at(-1).history.length, 2);
    assert.equal(calls.at(-1).userMessage, 'Show the test.');
    const stored = await (await fetch(`http://${base}/api/conversations/${done.conversationId}`)).json();
    assert.equal(stored.messages.length, 4);
    assert.equal((await (await fetch(`http://${base}/api/conversations?sessionId=${sessionId}`)).json()).length, 1);
  });
  it('drops failed turns and redacts provider secrets', async () => {
    const events = await converse({ question: 'FAIL_PLEASE' });
    const error = events.at(-1);
    assert.equal(error.type, 'chat_error');
    assert.ok(!error.message.includes('sk-secretvalue123'));
    assert.equal((await (await fetch(`http://${base}/api/conversations?sessionId=${sessionId}`)).json()).length, 1);
  });
  it('rejects contexts from another workspace and empty questions', async () => {
    assert.match((await converse({ question: '' })).at(-1).message, /Ask a question/);
    assert.match((await converse({ question: 'x', context: { type: 'report', reportId: 'nope' } })).at(-1).message, /not part of this workspace/);
  });
  // Runs last: it adds conversations that the earlier count assertions do not expect.
  it('uses the general (Opus) model for Claude chat when no model is chosen, and an explicit model when one is', async () => {
    const config = await (await fetch(`http://${base}/api/config`)).json();
    assert.deepEqual(config.modelPolicy, { scan: 'claude-opus-5-5', general: 'claude-opus-5-5' });
    const defaulted = await converse({ question: 'Which model answers?', provider: 'claude', apiKey: 'sk-ant-session', lmstudioModel: undefined });
    assert.equal(defaulted.at(-1).type, 'chat_complete');
    assert.deepEqual({ provider: calls.at(-1).provider, model: calls.at(-1).model, purpose: calls.at(-1).purpose }, { provider: 'claude', model: 'claude-opus-5-5', purpose: 'chat' });
    await converse({ question: 'And now?', provider: 'claude', apiKey: 'sk-ant-session', model: 'claude-haiku-5-5', lmstudioModel: undefined });
    assert.equal(calls.at(-1).model, 'claude-haiku-5-5');
  });

});
