'use strict';

const Anthropic = require('@anthropic-ai/sdk');
const { mapBounded, environmentLimit } = require('./concurrency.cjs');

const TOOL_SCHEMAS = [
  { name: 'Read', description: 'Read numbered lines from a file within the selected repository.', input_schema: { type: 'object', required: ['file_path'], properties: { file_path: { type: 'string' }, offset: { type: 'integer' }, limit: { type: 'integer' } } } },
  { name: 'Grep', description: 'Search repository files using a bounded regex; no symlinks are followed.', input_schema: { type: 'object', required: ['pattern'], properties: { pattern: { type: 'string' }, path: { type: 'string' }, flags: { type: 'string' } } } },
  { name: 'Glob', description: 'Find repository-relative file paths by glob, excluding dependency and build directories.', input_schema: { type: 'object', required: ['pattern'], properties: { pattern: { type: 'string' } } } },
  { name: 'Bash', description: 'Execute one read-only inspection command, without a shell. Prefer Read/Grep/Glob. Git log/show/diff/status/blame/ls-files are supported. No writes, interpreters, pipes, redirects, or command substitution.', input_schema: { type: 'object', required: ['command'], properties: { command: { type: 'string' } } } },
];

const DEFAULT_ITERATIONS = 80;
const MAX_OUTPUT_TOKENS = 16000;
// Claude responses are streamed, so they can use a larger cap; on current models thinking counts toward it.
const CLAUDE_MAX_OUTPUT_TOKENS = 64000;
const MAX_CONTINUATIONS = 3;
const TOOL_CONCURRENCY = environmentLimit('THREATLINT_TOOL_CONCURRENCY', 4);
const MAX_TOOL_CALLS = 64;

function checkAbort(signal) { if (signal?.aborted) throw new Error('Cancelled'); }

/** Calls from one model turn are independent read-only inspections. Validate all before dispatch. */
async function executeInspectionCalls(calls, { execute, onEvent, signal }) {
  if (calls.length > MAX_TOOL_CALLS) throw new Error('The model requested too many inspection tools in one turn');
  const ids = new Set();
  for (const call of calls) {
    if (!TOOL_SCHEMAS.some(tool => tool.name === call.name) || typeof call.id !== 'string' || !call.id || ids.has(call.id)
      || !call.input || typeof call.input !== 'object' || Array.isArray(call.input)) throw new Error('Invalid inspection tool call from the model');
    ids.add(call.id);
  }
  return mapBounded(calls, async call => {
    checkAbort(signal);
    onEvent({ type: 'tool_executing', tool: call.name, input: call.input, id: call.id });
    const result = await execute(call.name, call.input);
    checkAbort(signal);
    onEvent({ type: 'tool_result', tool: call.name, id: call.id, preview: 'Inspection completed' });
    return result;
  }, { concurrency: TOOL_CONCURRENCY, signal });
}

function parseToolInput(call) {
  try { return JSON.parse(call.arguments || '{}'); } catch { throw new Error(`Invalid ${call.name} tool arguments from the model`); }
}

function validateBaseUrl(value) {
  const url = new URL(value || 'http://localhost:1234/v1');
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error('Use an HTTP(S) model-server URL without credentials or query parameters');
  if (url.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) throw new Error('Remote model servers must use HTTPS');
  return url.toString().replace(/\/$/, '');
}

async function openAiTurn({ baseUrl, model, messages, key, signal, onEvent, headers = {} }) {
  checkAbort(signal);
  const response = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST', signal, redirect: 'error', headers: { 'Content-Type': 'application/json', ...headers, ...(key ? { Authorization: `Bearer ${key}` } : {}) },
    body: JSON.stringify({ model, messages, tools: TOOL_SCHEMAS.map(tool => ({ type: 'function', function: { name: tool.name, description: tool.description, parameters: tool.input_schema } })), stream: true, max_tokens: MAX_OUTPUT_TOKENS }),
  });
  if (response.status === 429) throw new Error('The model provider rate-limited this request or the plan quota is used up (HTTP 429). Wait, or choose another model or provider.');
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
/** OpenAI-compatible user content: plain text, or text plus data-URL image parts. */
const openAiContent = (text, images = []) => (images.length
  ? [{ type: 'text', text }, ...images.map(image => ({ type: 'image_url', image_url: { url: `data:${image.mediaType};base64,${image.data}` } }))] : text);

/** Anthropic user content: plain text, or text plus base64 image blocks. */
const claudeContent = (text, images = []) => (images.length
  ? [{ type: 'text', text }, ...images.map(image => ({ type: 'image', source: { type: 'base64', media_type: image.mediaType, data: image.data } }))] : text);

async function runOpenAi({ systemPrompt, userMessage, images = [], history = [], baseUrl, model, key, onEvent, signal, execute, maxIterations = DEFAULT_ITERATIONS, headers }) {
  const messages = [{ role: 'system', content: systemPrompt }, ...history, { role: 'user', content: openAiContent(userMessage, images) }];
  for (let iteration = 1; iteration <= maxIterations; iteration++) {
    checkAbort(signal);
    onEvent({ type: 'iteration', n: iteration });
    const turn = await openAiTurn({ baseUrl, model, messages, key, signal, onEvent, headers });
    messages.push({ role: 'assistant', content: turn.text || null, ...(turn.calls.length ? { tool_calls: turn.calls.map(call => ({ id: call.id, type: 'function', function: { name: call.name, arguments: call.arguments } })) } : {}) });
    if (!turn.calls.length) return turn.text; // Save only the final report, never investigation chatter.
    const results = await executeInspectionCalls(turn.calls.map(call => ({ ...call, input: parseToolInput(call) })), { execute, onEvent, signal });
    messages.push(...turn.calls.map((call, index) => ({ role: 'tool', tool_call_id: call.id, content: results[index] })));
  }
  throw new Error('Inspection budget reached; analysis is incomplete and was not saved as a final report');
}

/** OpenAI's Daybreak access selector is a Responses API field, not a Chat Completions field.
 * Bedrock Daybreak uses the same API shape but must omit the OpenAI selector. */
async function responsesTurn({ baseUrl, model, input, systemPrompt, key, signal, onEvent, accessProgram = 'daybreak_blue' }) {
  checkAbort(signal);
  const response = await fetch(`${baseUrl}/responses`, {
    method: 'POST', signal, redirect: 'error',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` },
    body: JSON.stringify({ model, instructions: systemPrompt, input, store: false, stream: true,
      ...(accessProgram ? { access_programs: { cyber: accessProgram } } : {}), max_output_tokens: CLAUDE_MAX_OUTPUT_TOKENS,
      tools: TOOL_SCHEMAS.map(tool => ({ type: 'function', name: tool.name, description: tool.description,
        parameters: tool.input_schema, strict: false })) }),
  });
  if (response.status === 429) throw new Error('The model provider rate-limited this request or the plan quota is used up (HTTP 429). Wait, or choose another model or provider.');
  if (!response.ok) throw new Error(`Model request failed (HTTP ${response.status}). ${accessProgram
    ? 'Check Daybreak Blue access, the OpenAI project API key, and model availability.'
    : 'Check Bedrock Daybreak Blue access, the Bedrock API key, and region availability.'}`);
  if (!response.body) throw new Error('The model returned no response stream');
  const decoder = new TextDecoder();
  let buffer = '', completed = null;
  function consume(frame) {
    const raw = frame.split(/\r?\n/).filter(line => line.startsWith('data:')).map(line => line.slice(5).trimStart()).join('\n');
    if (!raw || raw === '[DONE]') return;
    let event;
    try { event = JSON.parse(raw); } catch { throw new Error('The model returned an invalid streaming response'); }
    if (event.type === 'response.output_text.delta' && typeof event.delta === 'string') onEvent({ type: 'text_chunk', text: event.delta });
    if (event.type === 'response.completed') completed = event.response;
    if (event.type === 'response.failed' || event.type === 'response.incomplete' || event.type === 'error') {
      throw new Error('The model stopped before completing the report. Check Daybreak Blue access and the selected model.');
    }
  }
  for await (const chunk of response.body) {
    checkAbort(signal);
    buffer += decoder.decode(chunk, { stream: true });
    const frames = buffer.split(/\r?\n\r?\n/);
    buffer = frames.pop();
    for (const frame of frames) consume(frame);
  }
  buffer += decoder.decode();
  if (buffer.trim()) consume(buffer);
  if (!completed || completed.status !== 'completed' || !Array.isArray(completed.output)) {
    throw new Error('The model stream ended before a complete response was received');
  }
  return completed;
}

function responseText(output) {
  return output.filter(item => item.type === 'message').flatMap(item => item.content || [])
    .filter(part => part.type === 'output_text').map(part => part.text || '').join('');
}

async function runResponses({ systemPrompt, userMessage, images = [], history = [], baseUrl, model, key, onEvent, signal, execute, maxIterations = DEFAULT_ITERATIONS, accessProgram = 'daybreak_blue' }) {
  const content = images.length ? [{ type: 'input_text', text: userMessage },
    ...images.map(image => ({ type: 'input_image', image_url: `data:${image.mediaType};base64,${image.data}` }))] : userMessage;
  const input = [...history, { role: 'user', content }];
  for (let iteration = 1; iteration <= maxIterations; iteration++) {
    checkAbort(signal);
    onEvent({ type: 'iteration', n: iteration });
    const turn = await responsesTurn({ baseUrl, model, input, systemPrompt, key, signal, onEvent, accessProgram });
    // In stateless mode, replay every output item, including encrypted reasoning state.
    input.push(...turn.output);
    const calls = turn.output.filter(item => item.type === 'function_call');
    if (!calls.length) {
      const final = responseText(turn.output);
      if (final.trim()) return final;
      // A reasoning-only response can complete without a final message. Replay
      // its reasoning items and let the model finish within the iteration cap.
      continue;
    }
    const results = await executeInspectionCalls(calls.map(call => ({ id: call.call_id, name: call.name, input: parseToolInput(call) })), { execute, onEvent, signal });
    input.push(...calls.map((call, index) => ({ type: 'function_call_output', call_id: call.call_id, output: results[index] })));
  }
  throw new Error('Inspection budget reached; analysis is incomplete and was not saved as a final report');
}

async function runClaude({ systemPrompt, userMessage, images = [], history = [], model, key, bearer = false, baseUrl, onEvent, signal, execute, maxIterations = DEFAULT_ITERATIONS }) {
  // ANTHROPIC_AUTH_TOKEN-style credentials are bearer tokens; baseUrl is ANTHROPIC_BASE_URL when a gateway is configured.
  const client = new Anthropic({ ...(bearer ? { apiKey: null, authToken: key } : { apiKey: key, authToken: null }),
    ...(baseUrl ? { baseURL: baseUrl } : {}), fetchOptions: { redirect: 'error' } });
  const messages = [...history, { role: 'user', content: claudeContent(userMessage, images) }];
  const partial = [];   // report text from turns cut off at the output limit, joined with the final turn
  let continuations = 0;
  for (let iteration = 1; iteration <= maxIterations; iteration++) {
    checkAbort(signal);
    onEvent({ type: 'iteration', n: iteration });
    const stream = client.messages.stream({ model, max_tokens: CLAUDE_MAX_OUTPUT_TOKENS, system: systemPrompt, tools: TOOL_SCHEMAS, messages }, { signal });
    let final;
    try {
      for await (const event of stream) {
        checkAbort(signal);
        if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') onEvent({ type: 'text_chunk', text: event.delta.text });
      }
      final = await stream.finalMessage();
    } catch (error) {
      if (signal?.aborted) throw new Error('Cancelled');
      // Provider error bodies may echo request headers or context. Keep them out of reports and UI events.
      if (error.status === 429) throw new Error('The model provider rate-limited this request or the plan quota is used up (HTTP 429). Wait, or choose another model or provider.');
      const status = Number.isInteger(error.status) ? ` (HTTP ${error.status})` : '';
      throw new Error(`Model request failed${status}. Check the model, credentials, region, and provider availability.`);
    }
    if (!['end_turn', 'stop_sequence', 'tool_use', 'max_tokens'].includes(final.stop_reason)) {
      throw new Error('The model stopped before completing the report. Check the selected model and provider.');
    }
    const text = final.content.filter(block => block.type === 'text').map(block => block.text).join('\n');
    if (final.stop_reason === 'max_tokens') {
      // A long report ran past the cap: keep what was written and ask for the rest, rather than discarding it.
      if (++continuations > MAX_CONTINUATIONS) throw new Error('Model output limit reached; the report is incomplete');
      const content = final.content.filter(block => block.type !== 'tool_use');
      if (content.length) messages.push({ role: 'assistant', content });
      partial.push(text);
      messages.push({ role: 'user', content: 'Your response was cut off at the output limit. Continue exactly where it stopped, without repeating anything already written.' });
      continue;
    }
    messages.push({ role: 'assistant', content: final.content });
    if (final.stop_reason !== 'tool_use') return [...partial, text].join('');
    const calls = final.content.filter(block => block.type === 'tool_use');
    const contents = await executeInspectionCalls(calls, { execute, onEvent, signal });
    const results = calls.map((block, index) => ({ type: 'tool_result', tool_use_id: block.id, content: contents[index] }));
    messages.push({ role: 'user', content: results });
  }
  throw new Error('Inspection budget reached; analysis remains incomplete');
}

module.exports = { runClaude, runOpenAi, runResponses, validateBaseUrl, openAiTurn, responsesTurn, TOOL_SCHEMAS, executeInspectionCalls };
