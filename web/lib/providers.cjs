'use strict';

const Anthropic = require('@anthropic-ai/sdk');

const TOOL_SCHEMAS = [
  { name: 'Read', description: 'Read numbered lines from a file within the selected repository.', input_schema: { type: 'object', required: ['file_path'], properties: { file_path: { type: 'string' }, offset: { type: 'integer' }, limit: { type: 'integer' } } } },
  { name: 'Grep', description: 'Search repository files using a bounded regex; no symlinks are followed.', input_schema: { type: 'object', required: ['pattern'], properties: { pattern: { type: 'string' }, path: { type: 'string' }, flags: { type: 'string' } } } },
  { name: 'Glob', description: 'Find repository-relative file paths by glob, excluding dependency and build directories.', input_schema: { type: 'object', required: ['pattern'], properties: { pattern: { type: 'string' } } } },
  { name: 'Bash', description: 'Execute one read-only inspection command, without a shell. Prefer Read/Grep/Glob. Git log/show/diff/status/blame/ls-files are supported. No writes, interpreters, pipes, redirects, or command substitution.', input_schema: { type: 'object', required: ['command'], properties: { command: { type: 'string' } } } },
];

const DEFAULT_ITERATIONS = 80;
const MAX_OUTPUT_TOKENS = 16000;
// Claude streams, so multi-finding FP reports (several thousand tokens per finding) get more room.
const CLAUDE_MAX_OUTPUT_TOKENS = 64000;

function checkAbort(signal) { if (signal?.aborted) throw new Error('Cancelled'); }

function validateBaseUrl(value) {
  const url = new URL(value || 'http://localhost:1234/v1');
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error('Use an HTTP(S) model-server URL without credentials or query parameters');
  if (url.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) throw new Error('Remote model servers must use HTTPS');
  return url.toString().replace(/\/$/, '');
}

async function openAiTurn({ baseUrl, model, messages, key, signal, onEvent }) {
  checkAbort(signal);
  const response = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST', signal, redirect: 'error', headers: { 'Content-Type': 'application/json', ...(key ? { Authorization: `Bearer ${key}` } : {}) },
    body: JSON.stringify({ model, messages, tools: TOOL_SCHEMAS.map(tool => ({ type: 'function', function: { name: tool.name, description: tool.description, parameters: tool.input_schema } })), stream: true, max_tokens: MAX_OUTPUT_TOKENS }),
  });
  if (!response.ok) throw new Error(`Model request failed (HTTP ${response.status}). Check the model, credentials, and provider availability.`);
  const decoder = new TextDecoder();
  let buffer = '', text = '', finishReason = '', done = false;
  const calls = new Map();
  function consume(line) {
    if (!line.startsWith('data:')) return;
    const raw = line.slice(5).trim();
    if (raw === '[DONE]') { done = true; return; }
    let event;
    try { event = JSON.parse(raw); } catch { throw new Error('The model server returned an invalid streaming response'); }
    if (event.error) throw new Error('The model provider returned an error while generating the report');
    const choice = event.choices?.[0];
    if (!choice) return;
    if (choice.finish_reason) finishReason = choice.finish_reason;
    if (choice.delta?.content) { text += choice.delta.content; onEvent({ type: 'text_chunk', text: choice.delta.content }); }
    for (const call of choice.delta?.tool_calls || []) {
      if (!calls.has(call.index)) calls.set(call.index, { id: call.id || `call_${call.index}`, name: '', arguments: '' });
      const current = calls.get(call.index);
      if (call.id) current.id = call.id;
      if (call.function?.name) current.name += call.function.name;
      if (call.function?.arguments) current.arguments += call.function.arguments;
    }
  }
  for await (const chunk of response.body) {
    checkAbort(signal);
    buffer += decoder.decode(chunk, { stream: true });
    const lines = buffer.split('\n'); buffer = lines.pop();
    for (const line of lines) consume(line.trimEnd());
  }
  buffer += decoder.decode();
  if (buffer.trim()) consume(buffer.trimEnd());
  if (!done && !finishReason) throw new Error('The model stream ended unexpectedly; no complete report was saved');
  if (['length', 'content_filter'].includes(finishReason)) throw new Error(`The model stopped before completing the report (${finishReason}). Try a model with a larger output budget.`);
  return { text, calls: [...calls.values()], finishReason };
}

// `history` holds prior plain-text turns ({ role, content }) for multi-turn conversations.
async function runOpenAi({ systemPrompt, userMessage, history = [], baseUrl, model, key, onEvent, signal, execute, maxIterations = DEFAULT_ITERATIONS }) {
  const messages = [{ role: 'system', content: systemPrompt }, ...history, { role: 'user', content: userMessage }];
  for (let iteration = 1; iteration <= maxIterations; iteration++) {
    checkAbort(signal);
    onEvent({ type: 'iteration', n: iteration });
    const turn = await openAiTurn({ baseUrl, model, messages, key, signal, onEvent });
    messages.push({ role: 'assistant', content: turn.text || null, ...(turn.calls.length ? { tool_calls: turn.calls.map(call => ({ id: call.id, type: 'function', function: { name: call.name, arguments: call.arguments } })) } : {}) });
    if (!turn.calls.length) return turn.text; // Save only the final report, never investigation chatter.
    for (const call of turn.calls) {
      checkAbort(signal);
      let input;
      try { input = JSON.parse(call.arguments || '{}'); } catch { throw new Error(`Invalid ${call.name} tool arguments from the model`); }
      onEvent({ type: 'tool_executing', tool: call.name, input, id: call.id });
      const result = await execute(call.name, input);
      onEvent({ type: 'tool_result', tool: call.name, id: call.id, preview: 'Inspection completed' });
      messages.push({ role: 'tool', tool_call_id: call.id, content: result });
    }
  }
  throw new Error('Inspection budget reached; analysis is incomplete and was not saved as a final report');
}

async function runClaude({ systemPrompt, userMessage, history = [], model, key, onEvent, signal, execute, maxIterations = DEFAULT_ITERATIONS }) {
  const client = new Anthropic({ apiKey: key });
  const messages = [...history, { role: 'user', content: userMessage }];
  for (let iteration = 1; iteration <= maxIterations; iteration++) {
    checkAbort(signal);
    onEvent({ type: 'iteration', n: iteration });
    const stream = client.messages.stream({ model, max_tokens: CLAUDE_MAX_OUTPUT_TOKENS, system: systemPrompt, tools: TOOL_SCHEMAS, messages }, { signal });
    for await (const event of stream) {
      checkAbort(signal);
      if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') onEvent({ type: 'text_chunk', text: event.delta.text });
    }
    const final = await stream.finalMessage();
    if (final.stop_reason === 'max_tokens') throw new Error('Model output limit reached; the report is incomplete');
    messages.push({ role: 'assistant', content: final.content });
    if (final.stop_reason !== 'tool_use') return final.content.filter(block => block.type === 'text').map(block => block.text).join('\n');
    const results = [];
    for (const block of final.content.filter(block => block.type === 'tool_use')) {
      checkAbort(signal);
      onEvent({ type: 'tool_executing', tool: block.name, input: block.input, id: block.id });
      const result = await execute(block.name, block.input);
      onEvent({ type: 'tool_result', tool: block.name, id: block.id, preview: 'Inspection completed' });
      results.push({ type: 'tool_result', tool_use_id: block.id, content: result });
    }
    messages.push({ role: 'user', content: results });
  }
  throw new Error('Inspection budget reached; analysis remains incomplete');
}

module.exports = { runClaude, runOpenAi, validateBaseUrl, openAiTurn, TOOL_SCHEMAS };