'use strict';

/** Run a Threatlint specialist through the user's signed-in Codex CLI.
 * Codex owns its login. Threatlint neither reads OAuth tokens nor converts them
 * into an API key. Each invocation is ephemeral and has a read-only sandbox.
 */
const { spawn, execFile } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { StringDecoder } = require('node:string_decoder');

const STATUS_TIMEOUT_MS = 15_000;
const RUN_TIMEOUT_MS = Number(process.env.THREATLINT_CODEX_TIMEOUT_MS) || 60 * 60_000;
const MAX_EVENT_LINE = 8 * 1024 * 1024;
const MAX_STDERR = 4096;
// A model-directed command can inspect its own environment. Keep only what
// Codex needs for its login, network connection, locale, and platform runtime.
const CHILD_ENV_NAMES = new Set([
  'PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'TMPDIR', 'TMP', 'TEMP',
  'LANG', 'LC_ALL', 'LC_CTYPE', 'CODEX_HOME', 'XDG_CONFIG_HOME',
  'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
  'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
  'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy',
  'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'USERPROFILE',
  'APPDATA', 'LOCALAPPDATA',
]);

function executable({ env = process.env, home = os.homedir(), platform = process.platform,
  appPath = '/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex' } = {}) {
  const name = platform === 'win32' ? 'codex.exe' : 'codex';
  const dirs = [...String(env.PATH || '').split(path.delimiter), path.join(home, '.local/bin'),
    '/opt/homebrew/bin', '/usr/local/bin'];
  const candidates = dirs.filter(Boolean).map(dir => path.join(dir, name));
  if (platform === 'darwin') {
    candidates.push(appPath);
  }
  return candidates.find(file => { try { fs.accessSync(file, fs.constants.X_OK); return true; } catch { return false; } }) || null;
}

function childEnv(env = process.env) {
  return Object.fromEntries(Object.entries(env).filter(([name, value]) =>
    CHILD_ENV_NAMES.has(name) && typeof value === 'string'));
}

function status({ env = process.env, execFileImpl = execFile, codexPath = executable({ env }) } = {}) {
  if (!codexPath) return Promise.resolve({ installed: false, loggedIn: false, source: null });
  return new Promise(resolve => {
    execFileImpl(codexPath, ['login', 'status'],
      { env: childEnv(env), timeout: STATUS_TIMEOUT_MS, windowsHide: true }, (error, stdout, stderr) => {
        const result = `${stdout || ''}\n${stderr || ''}`.trim();
        const loggedIn = !error && /^Logged in\b/i.test(result);
        const method = /ChatGPT/i.test(result) ? 'ChatGPT' : /API key/i.test(result) ? 'API key' : 'account';
        resolve({ installed: true, loggedIn, source: loggedIn ? `Codex login (${method})` : null });
      });
  });
}

function command({ repoPath, model = '', daybreakBlue = false, images = [] }) {
  return ['exec', '--json', '--ephemeral', '--sandbox', 'read-only', '--ignore-user-config',
    '--skip-git-repo-check', '-C', repoPath, '-c', `daybreak=${daybreakBlue ? 'true' : 'false'}`,
    ...(model ? ['--model', model] : []), ...images.flatMap(file => ['--image', file]), '-'];
}

function withHistory(history, userMessage) {
  const turns = (history || []).map(turn => `${turn.role === 'assistant' ? 'Assistant' : 'User'}: ${typeof turn.content === 'string' ? turn.content : JSON.stringify(turn.content)}`);
  return turns.length ? `Conversation so far:\n\n${turns.join('\n\n')}\n\nUser: ${userMessage}` : userMessage;
}

function promptText(systemPrompt, history, userMessage) {
  return `# Threatlint specialist instructions\n\n${systemPrompt}\n\n# Current request\n\n${withHistory(history, userMessage)}\n\nReturn the complete report as your final answer. Keep all repository inspection read-only.`;
}

function handleEvent(event, onEvent) {
  if (event.type === 'item.started' && event.item?.type === 'command_execution') {
    onEvent({ type: 'tool_executing', tool: 'Codex inspection', input: {}, id: event.item.id });
  } else if (event.type === 'item.completed') {
    if (event.item?.type === 'command_execution') {
      onEvent({ type: 'tool_result', tool: 'Codex inspection', id: event.item.id, preview: 'Inspection completed' });
    } else if (event.item?.type === 'agent_message' && typeof event.item.text === 'string') {
      onEvent({ type: 'text_chunk', text: event.item.text });
      return { text: event.item.text };
    }
  } else if (event.type === 'turn.completed') return event.turn?.status && event.turn.status !== 'completed' ? { failed: true } : { completed: true };
  else if (event.type === 'turn.failed' || event.type === 'turn.cancelled' || event.type === 'error') return { failed: true };
  return null;
}

async function runCodex({ systemPrompt, userMessage, images = [], history = [], model = '', repoPath,
  onEvent = () => {}, signal, daybreakBlue = false, env = process.env,
  spawnImpl = spawn, codexPath = executable({ env }) }) {
  if (!codexPath) throw new Error('Codex CLI is not installed. Install Codex, run `codex login`, then retry.');
  const imageDir = images.length ? fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-codex-images-')) : null;
  const imagePaths = images.map((image, index) => {
    const file = path.join(imageDir, `${index + 1}-${path.basename(image.name || 'image').replace(/[^\w.-]/g, '_')}`);
    fs.writeFileSync(file, Buffer.from(image.data, 'base64'), { mode: 0o600 });
    return file;
  });
  try {
    return await new Promise((resolve, reject) => {
      const child = spawnImpl(codexPath, command({ repoPath, model, daybreakBlue, images: imagePaths }),
        { cwd: repoPath, env: childEnv(env), stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
      let buffer = '', stderr = '', lastMessage = '', completed = false, failed = false, settled = false;
      const decoder = new StringDecoder('utf8');
      const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener?.('abort', abort); error ? reject(error) : resolve(value); };
      const abort = () => { child.kill('SIGTERM'); finish(Object.assign(new Error('Run cancelled'), { name: 'AbortError' })); };
      const invalidStream = message => { child.kill('SIGTERM'); finish(new Error(message)); };
      const consume = line => {
        if (!line.trim()) return;
        if (line.length > MAX_EVENT_LINE) return invalidStream('Codex returned an oversized event');
        let event;
        try { event = JSON.parse(line); } catch { return invalidStream('Codex returned an invalid event stream'); }
        try {
          const result = handleEvent(event, onEvent);
          if (result?.text) lastMessage = result.text;
          if (result?.completed) completed = true;
          if (result?.failed) failed = true;
        } catch { invalidStream('Codex returned an invalid event stream'); }
      };
      const timer = setTimeout(() => { child.kill('SIGTERM'); finish(new Error('Codex did not finish within the configured timeout')); }, RUN_TIMEOUT_MS);
      if (signal?.aborted) return abort();
      signal?.addEventListener?.('abort', abort, { once: true });
      child.stdout.on('data', chunk => {
        if (settled) return;
        buffer += decoder.write(chunk);
        const lines = buffer.split('\n'); buffer = lines.pop();
        if (buffer.length > MAX_EVENT_LINE) return invalidStream('Codex returned an oversized event');
        for (const line of lines) { if (settled) break; consume(line); }
      });
      child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-MAX_STDERR); });
      child.stdin.on('error', error => { if (error.code !== 'EPIPE') invalidStream('Codex could not receive the review request'); });
      child.on('error', () => finish(new Error('Codex could not start. Check the installed CLI.')));
      child.on('close', code => {
        if (settled) return;
        buffer += decoder.end();
        if (buffer.trim()) consume(buffer);
        if (settled) return;
        if (code === 0 && completed && !failed && lastMessage.trim()) return finish(null, lastMessage);
        const login = /login|auth/i.test(stderr) ? ' Run `codex login` and retry.' : '';
        finish(new Error(`Codex run did not complete.${login}`));
      });
      child.stdin.end(promptText(systemPrompt, history, userMessage));
    });
  } finally {
    if (imageDir) fs.rmSync(imageDir, { recursive: true, force: true });
  }
}

module.exports = { runCodex, status, executable, childEnv, command, handleEvent, withHistory, promptText };
