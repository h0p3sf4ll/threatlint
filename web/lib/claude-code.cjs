'use strict';

/**
 * Claude Code provider: run an agent through the user's own Claude Code login (`claude -p`) instead of an API key.
 *
 * Threatlint never reads or handles the login: it starts the installed `claude` CLI, which authenticates itself.
 * Every run is locked down because the repository under review is untrusted:
 *   --restricted              no command- or code-running tools; user, project, and local settings files are ignored
 *                             (so a scanned repo's .claude/settings.json hooks never run); file tools stay inside cwd
 *   --tools Read,Grep,Glob    the only tools available, so nothing can be written
 *   --strict-mcp-config       no MCP servers
 *   --permission-mode dontAsk anything not allowed is denied instead of prompting
 *   --no-session-persistence  nothing is saved to Claude Code's session history
 * API keys, provider-selection flags, and endpoint overrides are removed from the child environment so the
 * Claude Code login is used even when the parent process also has Bedrock or another cloud provider configured.
 * The system prompt goes through a 0600 temp file and the user message through stdin, so neither appears in argv.
 */

const { spawn, execFile } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const READ_ONLY_TOOLS = ['Read', 'Grep', 'Glob'];
const STATUS_TIMEOUT_MS = 15_000;
const RUN_TIMEOUT_MS = Number(process.env.THREATLINT_CLAUDE_CODE_TIMEOUT_MS) || 60 * 60_000;
const STRIPPED_ENV = [
  'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL',
  'CLAUDE_CODE_USE_BEDROCK', 'CLAUDE_CODE_USE_MANTLE', 'CLAUDE_CODE_USE_VERTEX', 'CLAUDE_CODE_USE_FOUNDRY', 'CLAUDE_CODE_USE_ANTHROPIC_AWS',
  'AWS_BEARER_TOKEN_BEDROCK', 'BEDROCK_API_KEY', 'AWS_ENDPOINT_URL_BEDROCK_RUNTIME', 'AWS_ENDPOINT_URL_BEDROCK_MANTLE',
];
// Models offered in Settings; Claude Code also accepts any model ID it supports.
const MODELS = [
  { id: 'claude-opus-5-5', name: 'Claude Opus 5.5' },
  { id: 'claude-sonnet-5-5', name: 'Claude Sonnet 5.5' },
  { id: 'claude-haiku-5-5', name: 'Claude Haiku 5.5' },
  { id: 'claude-fable-5-1', name: 'Claude Fable 5.1' },
];

/** The `claude` executable: PATH first, then the installer's usual locations (apps started from Finder get a minimal PATH). */
function executable({ env = process.env, home = os.homedir() } = {}) {
  const name = process.platform === 'win32' ? 'claude.exe' : 'claude';
  const dirs = [...String(env.PATH || '').split(path.delimiter), path.join(home, '.local/bin'), path.join(home, '.claude/local'), '/opt/homebrew/bin', '/usr/local/bin'];
  return dirs.filter(Boolean).map(dir => path.join(dir, name)).find(file => { try { fs.accessSync(file, fs.constants.X_OK); return true; } catch { return false; } }) || null;
}

function childEnv(env = process.env) {
  const copy = { ...env };
  for (const name of STRIPPED_ENV) delete copy[name];
  // `auth status` also reads user settings. Prevent their env block from restoring provider/auth overrides.
  copy.CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST = '1';
  return copy;
}

/** { installed, loggedIn, authMethod, source } from `claude auth status`; never throws. */
function status({ env = process.env, execFileImpl = execFile } = {}) {
  const file = executable({ env });
  if (!file) return Promise.resolve({ installed: false, loggedIn: false, source: null });
  return new Promise(resolve => {
    execFileImpl(file, ['auth', 'status'], { env: childEnv(env), timeout: STATUS_TIMEOUT_MS }, (_error, stdout) => {
      let parsed = {};
      try { parsed = JSON.parse(String(stdout || '{}')); } catch { /* older CLI or unexpected output */ }
      const loggedIn = parsed.loggedIn === true;
      resolve({ installed: true, loggedIn, authMethod: parsed.authMethod || null, source: loggedIn ? `Claude Code login (${parsed.authMethod || 'signed in'})` : null });
    });
  });
}

/** argv for one locked-down headless run. */
function command(model, systemPromptFile, extraDirs = []) {
  return ['-p', '--output-format', 'stream-json', '--verbose', '--restricted', '--tools', READ_ONLY_TOOLS.join(','), '--strict-mcp-config',
    '--permission-mode', 'dontAsk', '--no-session-persistence', '--system-prompt-file', systemPromptFile, ...extraDirs.flatMap(dir => ['--add-dir', dir]), ...(model ? ['--model', model] : [])];
}

/** Earlier chat turns, folded into the prompt (each headless run is a fresh session). */
function withHistory(history, userMessage) {
  const turns = (history || []).map(turn => `${turn.role === 'assistant' ? 'Assistant' : 'User'}: ${typeof turn.content === 'string' ? turn.content : JSON.stringify(turn.content)}`);
  return turns.length ? `Conversation so far:\n\n${turns.join('\n\n')}\n\nUser: ${userMessage}` : userMessage;
}

/** Maps one stream-json event to Workbench progress events; returns the final result event when it arrives. */
function handleEvent(event, onEvent) {
  if (event.type === 'assistant') {
    for (const block of event.message?.content || []) {
      if (block.type === 'text' && block.text) onEvent({ type: 'text_chunk', text: block.text });
      if (block.type === 'tool_use') onEvent({ type: 'tool_executing', tool: block.name, input: block.input, id: block.id });
    }
  } else if (event.type === 'user') {
    for (const block of event.message?.content || []) if (block.type === 'tool_result') onEvent({ type: 'tool_result', id: block.tool_use_id, preview: 'Inspection completed' });
  } else if (event.type === 'result') return event;
  return null;
}

/** Runs one agent and resolves to its final report text. */
async function runClaudeCode({ systemPrompt, userMessage, images = [], history = [], model, repoPath, onEvent = () => {}, signal, env = process.env, spawnImpl = spawn, claudePath = executable({ env }) }) {
  const file = claudePath;
  if (!file) throw new Error('Claude Code is not installed. Install it (https://claude.com/claude-code), run `claude` once to sign in, then retry.');
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-claude-code-'));
  const promptFile = path.join(temp, 'system-prompt.md');
  fs.writeFileSync(promptFile, systemPrompt, { mode: 0o600 });
  // Images become files in their own directory, added with --add-dir so the restricted Read tool may open them.
  const imageDir = path.join(temp, 'images');
  const imagePaths = images.map((image, index) => {
    fs.mkdirSync(imageDir, { recursive: true, mode: 0o700 });
    const file = path.join(imageDir, `${index + 1}-${path.basename(image.name).replace(/[^\w.-]/g, '_')}`);
    fs.writeFileSync(file, Buffer.from(image.data, 'base64'), { mode: 0o600 });
    return file;
  });
  const prompt = imagePaths.length ? `${userMessage}\n\nImage files (open each with the Read tool):\n${imagePaths.map((file, index) => `${index + 1}. ${file}`).join('\n')}` : userMessage;
  try {
    return await new Promise((resolve, reject) => {
      const child = spawnImpl(file, command(model, promptFile, imagePaths.length ? [imageDir] : []), { cwd: repoPath, env: childEnv(env), stdio: ['pipe', 'pipe', 'pipe'] });
      let buffer = '', stderr = '', result = null, settled = false;
      const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener?.('abort', abort); error ? reject(error) : resolve(value); };
      const abort = () => { child.kill('SIGTERM'); finish(Object.assign(new Error('Run cancelled'), { name: 'AbortError' })); };
      const timer = setTimeout(() => { child.kill('SIGTERM'); finish(new Error(`Claude Code did not finish within ${Math.round(RUN_TIMEOUT_MS / 60000)} minutes`)); }, RUN_TIMEOUT_MS);
      if (signal?.aborted) return abort();
      signal?.addEventListener?.('abort', abort, { once: true });
      child.stdout.on('data', chunk => {
        buffer += chunk;
        const lines = buffer.split('\n');
        buffer = lines.pop();
        for (const line of lines) {
          if (!line.trim()) continue;
          let event;
          try { event = JSON.parse(line); } catch { continue; }
          result = handleEvent(event, onEvent) || result;
        }
      });
      child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-4000); });
      child.on('error', error => finish(new Error(`Claude Code could not start: ${error.message}`)));
      child.on('close', code => {
        if (result && !result.is_error && result.subtype === 'success') return finish(null, String(result.result || ''));
        const reason = result?.result || stderr.trim().split('\n').pop() || `exit code ${code}`;
        const login = /log ?in|auth|credential|unauthori[sz]ed/i.test(reason) ? ' Run `claude` in a terminal to sign in, then retry.' : '';
        finish(new Error(`Claude Code run failed: ${String(reason).slice(0, 300)}.${login}`));
      });
      child.stdin.end(withHistory(history, prompt));
    });
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

module.exports = { runClaudeCode, status, executable, command, handleEvent, withHistory, childEnv, MODELS, READ_ONLY_TOOLS };
