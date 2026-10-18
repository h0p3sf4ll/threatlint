'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { runOpenAi, validateBaseUrl } = require('../lib/providers.cjs');

let server, base;
const requests = [];
before(async () => {
  server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', chunk => { raw += chunk; });
    req.on('end', () => {
      const body = JSON.parse(raw); requests.push(body);
      res.setHeader('Content-Type', 'text/event-stream');
      const send = choice => res.write(`data: ${JSON.stringify({ choices: [choice] })}\n\n`);
      if (body.model === 'truncated') { send({ delta: { content: 'Incomplete report' }, finish_reason: 'length' }); res.end('data: [DONE]\n\n'); return; }
      if (body.model === 'cancel') { res.flushHeaders(); return; }
      if (!body.messages.some(message => message.role === 'tool')) {
        send({ delta: { content: 'Investigation commentary, not the report.' } });
        send({ delta: { tool_calls: [{ index: 0, id: 'call_1', function: { name: 'Read', arguments: '{"file_path":' } }] } });
        send({ delta: { tool_calls: [{ index: 0, function: { arguments: '"src/example.js"}' } }] }, finish_reason: 'tool_calls' });
      } else send({ delta: { content: '# Final Findings Report\nNo material findings in the inspected fixture.' }, finish_reason: 'stop' });
      res.end('data: [DONE]\n\n');
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });

describe('Provider streaming integration', () => {
  it('assembles fragmented tool calls and saves only the final report', async () => {
    const calls = []; const events = [];
    const report = await runOpenAi({ baseUrl: base, model: 'fixture', systemPrompt: 'required skills', userMessage: 'inspect fixture', onEvent: event => events.push(event), execute: async (name, input) => { calls.push({ name, input }); return '1\tfixture'; } });
    assert.deepEqual(calls, [{ name: 'Read', input: { file_path: 'src/example.js' } }]);
    assert.match(report, /^# Final Findings Report/);
    assert.doesNotMatch(report, /Investigation commentary/);
    assert.ok(events.some(event => event.type === 'tool_executing'));
    assert.equal(requests[0].messages[0].content, 'required skills');
  });
  it('does not save token-truncated content as a completed report', async () => {
    await assert.rejects(() => runOpenAi({ baseUrl: base, model: 'truncated', systemPrompt: 'skills', userMessage: 'fixture', onEvent: () => {}, execute: async () => '' }), /before completing/);
  });
  it('aborts an active model request', async () => {
    const controller = new AbortController();
    const pending = runOpenAi({ baseUrl: base, model: 'cancel', systemPrompt: 'skills', userMessage: 'fixture', signal: controller.signal, onEvent: () => {}, execute: async () => '' });
    controller.abort();
    await assert.rejects(() => pending, /abort|Cancelled/i);
  });
  it('rejects credential-bearing and insecure remote model-server URLs', () => {
    assert.equal(validateBaseUrl('http://localhost:1234/v1/'), 'http://localhost:1234/v1');
    assert.throws(() => validateBaseUrl('http://remote.example/v1'), /HTTPS/);
    assert.throws(() => validateBaseUrl('https://token:secret@remote.example/v1'), /without credentials/);
  });
});