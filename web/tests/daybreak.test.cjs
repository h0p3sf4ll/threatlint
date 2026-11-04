'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { runModel, providerRequest } = require('../lib/pipeline.cjs');

function streamResponse(output) {
  const event = { type: 'response.completed', response: { status: 'completed', output } };
  return new Response(`data: ${JSON.stringify(event)}\n\n`,
    { status: 200, headers: { 'Content-Type': 'text/event-stream' } });
}

async function exerciseToolRoundtrip(provider) {
  const bedrock = provider === 'daybreak-bedrock';
  const settings = providerRequest({ provider, [bedrock ? 'bedrockApiKey' : 'openaiApiKey']: 'test-key' });
  const requests = [];
  const originalFetch = global.fetch;
  global.fetch = async (url, options) => {
    requests.push({ url, options, body: JSON.parse(options.body) });
    return requests.length === 1
      ? streamResponse([
        { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'Investigating.' }] },
        { type: 'function_call', name: 'Read', call_id: 'call_1', arguments: '{"file_path":"README.md"}' },
      ])
      : streamResponse([{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: '# Verified report' }] }]);
  };
  try {
    const progress = [];
    const report = await runModel({ settings, systemPrompt: 'Specialist instructions', userMessage: 'Review the code',
      repoPath: path.resolve(__dirname, '../..'), onEvent: event => progress.push(event),
      override: undefined, maxIterations: 3 });
    assert.equal(report, '# Verified report');
    assert.equal(requests.length, 2);
    assert.equal(requests[0].url, `${bedrock ? 'https://bedrock-mantle.us-east-2.api.aws/openai/v1' : 'https://api.openai.com/v1'}/responses`);
    assert.equal(requests[0].options.headers.Authorization, 'Bearer test-key');
    assert.equal(requests[0].body.model, bedrock ? 'openai.gpt-daybreak-blue-5.6-sol' : 'gpt-6-sol');
    assert.equal(requests[0].body.store, false);
    assert.equal(requests[0].body.access_programs?.cyber, bedrock ? undefined : 'daybreak_blue');
    assert.equal(requests[1].body.access_programs?.cyber, bedrock ? undefined : 'daybreak_blue');
    const toolResult = requests[1].body.input.at(-1);
    assert.equal(toolResult.type, 'function_call_output');
    assert.equal(toolResult.call_id, 'call_1');
    assert.match(toolResult.output, /README/i);
    assert.ok(progress.some(event => event.type === 'tool_executing' && event.tool === 'Read'));
  } finally { global.fetch = originalFetch; }
}

test('OpenAI Daybreak Blue uses Responses with its access program through a tool roundtrip', async () => {
  await exerciseToolRoundtrip('daybreak');
});

test('Bedrock Daybreak Blue uses Mantle Responses without OpenAI access_programs through a tool roundtrip', async () => {
  await exerciseToolRoundtrip('daybreak-bedrock');
});

test('Daybreak replays a reasoning-only turn before accepting a final report', async () => {
  const originalFetch = global.fetch;
  const requests = [];
  global.fetch = async (_url, options) => {
    requests.push(JSON.parse(options.body));
    return requests.length === 1
      ? streamResponse([{ type: 'reasoning', id: 'rs_1', encrypted_content: 'opaque' }])
      : streamResponse([{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: '# Complete report' }] }]);
  };
  try {
    const report = await runModel({ settings: providerRequest({ provider: 'daybreak', openaiApiKey: 'test-key' }),
      systemPrompt: 'Rules', userMessage: 'Review', repoPath: path.resolve(__dirname, '../..'),
      onEvent: () => {}, maxIterations: 3 });
    assert.equal(report, '# Complete report');
    assert.deepEqual(requests[1].input.at(-1), { type: 'reasoning', id: 'rs_1', encrypted_content: 'opaque' });
  } finally { global.fetch = originalFetch; }
});

test('Codex provider needs no API key or explicit model and forwards Daybreak selection', async () => {
  const ordinary = providerRequest({ provider: 'codex' });
  assert.equal(ordinary.model, '');
  assert.equal(ordinary.key, null);
  assert.equal(ordinary.daybreakBlue, false);
  const daybreak = providerRequest({ provider: 'codex', codexDaybreak: true });
  assert.equal(daybreak.model, 'gpt-6-sol');
  assert.equal(daybreak.daybreakBlue, true);
  const override = providerRequest({ provider: 'codex', model: 'gpt-6.1-sol', codexDaybreak: true });
  let passed;
  const value = await runModel({ settings: override, systemPrompt: 'rules', userMessage: 'review',
    repoPath: '/repo', override: args => { passed = args; return '# Report'; } });
  assert.equal(value, '# Report');
  assert.equal(passed.model, 'gpt-6.1-sol');
  assert.equal(passed.daybreakBlue, true);
});
