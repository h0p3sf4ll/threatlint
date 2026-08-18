'use strict';

const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const Anthropic = require('@anthropic-ai/sdk');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

// ── LM Studio helpers ──────────────────────────────────────────────────────

function httpGetJson(url, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? require('https') : http;
    const req = mod.get(url, { timeout: timeoutMs }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch (e) { reject(e); } });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

function streamLmStudio({ baseUrl, model, systemPrompt, messages, maxTokens, onChunk, onDone, onError, apiKey }) {
  const url = new URL(`${baseUrl}/chat/completions`);
  const payload = Buffer.from(JSON.stringify({
    model,
    messages: [{ role: 'system', content: systemPrompt }, ...messages],
    stream: true,
    max_tokens: maxTokens || 4096,
  }));

  const headers = { 'Content-Type': 'application/json', 'Content-Length': payload.length };
  if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;

  const options = {
    hostname: url.hostname,
    port: parseInt(url.port) || (url.protocol === 'https:' ? 443 : 80),
    path: url.pathname,
    method: 'POST',
    headers,
    timeout: 600_000,
  };

  const mod = url.protocol === 'https:' ? require('https') : http;
  const req = mod.request(options, res => {
    let buf = '';
    res.on('data', chunk => {
      buf += chunk.toString();
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const data = line.slice(6).trim();
        if (data === '[DONE]') { onDone(); return; }
        try {
          const parsed = JSON.parse(data);
          const text = parsed.choices?.[0]?.delta?.content;
          if (text) onChunk(text);
        } catch { /* skip malformed SSE line */ }
      }
    });
    res.on('end', () => {
      if (buf.startsWith('data: ') && buf.slice(6).trim() !== '[DONE]') {
        try { const t = JSON.parse(buf.slice(6)).choices?.[0]?.delta?.content; if (t) onChunk(t); } catch {}
      }
      onDone();
    });
    res.on('error', onError);
  });
  req.on('error', onError);
  req.on('timeout', () => { req.destroy(); onError(new Error('LM Studio request timed out')); });
  req.write(payload);
  req.end();
}

function callLmStudioChat({ baseUrl, model, messages, tools, signal, onTextChunk, apiKey }) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return resolve({ text: '', toolCalls: [], finishReason: 'stop' });
    const url = new URL(`${baseUrl}/chat/completions`);
    const payload = Buffer.from(JSON.stringify({ model, messages, tools, stream: true, max_tokens: 16000 }));
    const headers = { 'Content-Type': 'application/json', 'Content-Length': payload.length };
    if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
    const options = {
      hostname: url.hostname,
      port: parseInt(url.port) || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname, method: 'POST',
      headers,
      timeout: 600_000,
    };
    const mod = url.protocol === 'https:' ? require('https') : http;
    let text = '', buf = '', finishReason = 'stop';
    const tcMap = {};

    function buildToolCalls() {
      return Object.values(tcMap).map(tc => ({
        id: tc.id, name: tc.name,
        args: (() => { try { return JSON.parse(tc.args || '{}'); } catch { return {}; } })(),
      }));
    }

    const abortHandler = () => { req.destroy(); resolve({ text, toolCalls: buildToolCalls(), finishReason }); };
    signal?.addEventListener('abort', abortHandler);

    const req = mod.request(options, res => {
      res.on('data', chunk => {
        buf += chunk.toString();
        const lines = buf.split('\n'); buf = lines.pop();
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const raw = line.slice(6).trim();
          if (raw === '[DONE]') continue;
          try {
            const p = JSON.parse(raw);
            const c = p.choices?.[0]; if (!c) continue;
            if (c.finish_reason) finishReason = c.finish_reason;
            const d = c.delta; if (!d) continue;
            if (d.content) { text += d.content; onTextChunk(d.content); }
            if (d.tool_calls) {
              for (const tc of d.tool_calls) {
                if (!tcMap[tc.index]) tcMap[tc.index] = { id: tc.id || `call_${tc.index}`, name: '', args: '' };
                if (tc.id) tcMap[tc.index].id = tc.id;
                if (tc.function?.name) tcMap[tc.index].name += tc.function.name;
                if (tc.function?.arguments) tcMap[tc.index].args += tc.function.arguments;
              }
            }
          } catch { /* skip malformed */ }
        }
      });
      res.on('end', () => { signal?.removeEventListener('abort', abortHandler); resolve({ text, toolCalls: buildToolCalls(), finishReason }); });
      res.on('error', err => { signal?.removeEventListener('abort', abortHandler); reject(err); });
    });
    req.on('error', err => { signal?.removeEventListener('abort', abortHandler); reject(err); });
    req.on('timeout', () => { req.destroy(); reject(new Error('LM Studio request timed out')); });
    req.write(payload); req.end();
  });
}


const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const PORT = process.env.PORT || 3000;
const REPO_ROOT = path.resolve(__dirname, '..');
const AGENTS_DIR = path.join(REPO_ROOT, '.claude', 'agents');
const MD_TO_DOCX = path.join(os.homedir(), '.claude', 'scripts', 'md_to_docx.py');

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Session store ──────────────────────────────────────────────────────────

const sessions = new Map();

function createSession(repoPath, isTempRepo = false, tempDir = null) {
  const id = crypto.randomUUID();
  sessions.set(id, { id, repoPath, isTempRepo, tempDir, reports: [] });
  return id;
}

// ── Agent definitions ──────────────────────────────────────────────────────

function loadAgents() {
  const agents = {};
  if (!fs.existsSync(AGENTS_DIR)) {
    console.warn(`Agents dir not found: ${AGENTS_DIR}`);
    return agents;
  }
  for (const file of fs.readdirSync(AGENTS_DIR).filter(f => f.endsWith('.md'))) {
    const raw = fs.readFileSync(path.join(AGENTS_DIR, file), 'utf8');
    const fm = raw.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
    if (!fm) continue;
    const meta = {};
    fm[1].split('\n').forEach(line => {
      const c = line.indexOf(':');
      if (c > 0) meta[line.slice(0, c).trim()] = line.slice(c + 1).trim();
    });
    const id = path.basename(file, '.md');
    agents[id] = {
      id,
      name: meta.name || id,
      description: (meta.description || '').replace(/^"|"$/g, ''),
      systemPrompt: fm[2].trim(),
    };
  }
  return agents;
}

const AGENTS = loadAgents();

const AGENT_META = {
  'appsec-threat-modeler':        { label: 'Threat Model',       color: '#ff6b6b', emoji: '🎯', category: 'Analysis' },
  'appsec-code-reviewer':         { label: 'Code Review',        color: '#ffd93d', emoji: '🔍', category: 'Analysis' },
  'appsec-dependency-auditor':    { label: 'Dependencies',       color: '#6bcb77', emoji: '📦', category: 'Supply Chain' },
  'appsec-secrets-scanner':       { label: 'Secrets Scan',       color: '#4d96ff', emoji: '🔑', category: 'Exposure' },
  'appsec-iac-reviewer':          { label: 'IaC Review',         color: '#c77dff', emoji: '☁️', category: 'Infrastructure' },
  'appsec-cicd-auditor':          { label: 'CI/CD Audit',        color: '#ff9671', emoji: '⚙️', category: 'Supply Chain' },
  'appsec-api-security-reviewer': { label: 'API Security',       color: '#00c9a7', emoji: '🌐', category: 'Analysis' },
  'appsec-auth-reviewer':         { label: 'Auth Review',        color: '#f9c74f', emoji: '🛡️', category: 'Analysis' },
  'appsec-fp-reviewer':           { label: 'FP Triage',          color: '#90e0ef', emoji: '⚖️', category: 'Analysis' },
  'appsec-compliance-checker':    { label: 'Compliance Map',     color: '#a8dadc', emoji: '📋', category: 'Compliance' },
  'appsec-attack-tree':           { label: 'Attack Tree',        color: '#e63946', emoji: '🌳', category: 'Adversarial' },
  'appsec-red-team':              { label: 'Red Team',           color: '#d62828', emoji: '⚔️', category: 'Adversarial' },
  'appsec-threat-delta':          { label: 'Threat Delta',       color: '#b5838d', emoji: '📊', category: 'Analysis' },
  'appsec-verify-fix':            { label: 'Verify Fix',         color: '#52b788', emoji: '✅', category: 'Analysis' },
};

// ── Tool execution ─────────────────────────────────────────────────────────

const SAFE_CMD_PATTERNS = [
  /^git\s+(log|show|ls-files|status|diff|blame|remote|branch|tag|rev-parse|cat-file|describe|shortlog|stash\s+list|check-ignore|ls-tree|archive)\b/,
  /^find\s/,
  /^grep\s/,
  /^rg\s/,
  /^cat\s/,
  /^head\s/,
  /^tail\s/,
  /^wc\s/,
  /^ls(\s|$)/,
  /^echo\s/,
  /^which\s/,
  /^file\s/,
  /^stat\s/,
  /^basename\s/,
  /^dirname\s/,
  /^sort\b/,
  /^uniq\b/,
  /^awk\s/,
  /^sed\s+-[npe]/,
  /^cut\s/,
  /^tr\s/,
  /^jq\s/,
  /^python3\s+-c\s/,
  /^node\s+-e\s/,
  /^env\b/,
  /^printenv\b/,
];

function isCommandSafe(cmd) {
  const t = cmd.trim();
  // Block obvious dangerous patterns regardless of prefix
  if (/[;&|`]/.test(t) && !/^git\s/.test(t)) return false;
  if (/\brm\b|\bchmod\b|\bchown\b|\bmkdir\b|\btouch\b|\bcurl\b|\bwget\b/.test(t)) return false;
  return SAFE_CMD_PATTERNS.some(rx => rx.test(t));
}

function safeResolvePath(repoPath, filePath) {
  if (!filePath) return null;
  const resolved = filePath.startsWith('/')
    ? path.normalize(filePath)
    : path.resolve(repoPath, filePath);
  // Allow repo paths and /tmp for chain context files
  if (resolved.startsWith(repoPath) || resolved.startsWith('/tmp/')) return resolved;
  return null;
}

async function executeTool(name, input, repoPath) {
  try {
    switch (name) {
      case 'Read': {
        const fp = input.file_path || input.path || input.filePath;
        if (!fp) return 'Error: file_path required';
        const resolved = safeResolvePath(repoPath, fp);
        if (!resolved) return `Error: Access denied: ${fp}`;
        if (!fs.existsSync(resolved)) return `File not found: ${fp}`;
        const content = fs.readFileSync(resolved, 'utf8');
        const lines = content.split('\n');
        const offset = Math.max(0, input.offset || 0);
        const limit = Math.min(input.limit || 2000, 5000);
        return lines.slice(offset, offset + limit)
          .map((l, i) => `${offset + i + 1}\t${l}`)
          .join('\n');
      }

      case 'Bash': {
        const cmd = input.command || input.cmd;
        if (!cmd) return 'Error: command required';
        if (!isCommandSafe(cmd)) return `Error: Command not permitted — "${cmd.slice(0, 120)}"`;
        const { stdout, stderr } = await execAsync(cmd, {
          cwd: repoPath, timeout: 60000, maxBuffer: 5 * 1024 * 1024
        }).catch(err => ({ stdout: err.stdout || '', stderr: err.stderr || err.message }));
        return (stdout + stderr).slice(0, 50000);
      }

      case 'Grep': {
        const pattern = input.pattern;
        if (!pattern) return 'Error: pattern required';
        const searchIn = input.path
          ? path.resolve(repoPath, input.path.replace(/^\//, ''))
          : repoPath;
        if (!searchIn.startsWith(repoPath)) return 'Error: path outside repo';
        const flags = (input.flags || '-rn').replace(/[^-rnicElwsa]/g, '');
        const safePattern = pattern.replace(/'/g, "'\\''");
        const cmd = `grep ${flags} -e '${safePattern}' -- "${searchIn}" 2>/dev/null || true`;
        const { stdout } = await execAsync(cmd, { cwd: repoPath, timeout: 30000, maxBuffer: 5 * 1024 * 1024 });
        return stdout.slice(0, 50000) || '(no matches)';
      }

      case 'Glob': {
        const pattern = input.pattern;
        if (!pattern) return 'Error: pattern required';
        // Convert glob to find-compatible expression (simplified)
        const findCmd = `find "${repoPath}" -not -path '*/.git/*' -type f 2>/dev/null | head -500`;
        const { stdout } = await execAsync(findCmd, { cwd: repoPath, timeout: 30000, maxBuffer: 2 * 1024 * 1024 });
        const allFiles = stdout.split('\n').filter(Boolean).map(f => path.relative(repoPath, f));
        // Simple glob matching
        const regexStr = '^' + pattern
          .replace(/[.+^${}()|[\]\\]/g, '\\$&')
          .replace(/\*\*/g, '\x00')
          .replace(/\*/g, '[^/]*')
          .replace(/\x00/g, '.*')
          .replace(/\?/g, '.') + '$';
        try {
          const rx = new RegExp(regexStr);
          return allFiles.filter(f => rx.test(f)).join('\n') || '(no matches)';
        } catch {
          return allFiles.join('\n');
        }
      }

      default:
        return `Unknown tool: ${name}`;
    }
  } catch (err) {
    return `Tool error: ${err.message.slice(0, 500)}`;
  }
}

// ── Claude tool definitions ────────────────────────────────────────────────

const CLAUDE_TOOLS = [
  {
    name: 'Read',
    description: 'Read a file from the repository. Returns numbered lines. Use offset/limit for large files.',
    input_schema: {
      type: 'object',
      properties: {
        file_path: { type: 'string', description: 'Path relative to repo root or absolute' },
        offset: { type: 'integer', description: 'Starting line 0-based (optional)' },
        limit: { type: 'integer', description: 'Max lines to return (default 2000)' },
      },
      required: ['file_path'],
    },
  },
  {
    name: 'Bash',
    description: 'Run a read-only shell command in the repo directory. Permitted: git log/show/ls-files/status/diff/blame/branch/tag/rev-parse, find, grep, cat, head, tail, wc, ls, sort, uniq, awk, cut, jq.',
    input_schema: {
      type: 'object',
      properties: {
        command: { type: 'string', description: 'Shell command to execute' },
      },
      required: ['command'],
    },
  },
  {
    name: 'Grep',
    description: 'Search files for a regex pattern.',
    input_schema: {
      type: 'object',
      properties: {
        pattern: { type: 'string', description: 'Regex pattern' },
        path: { type: 'string', description: 'Path to search in (relative to repo root, default: whole repo)' },
        flags: { type: 'string', description: 'grep flags e.g. -rni (default: -rn)' },
      },
      required: ['pattern'],
    },
  },
  {
    name: 'Glob',
    description: 'Find files matching a glob pattern relative to repo root.',
    input_schema: {
      type: 'object',
      properties: {
        pattern: { type: 'string', description: 'Glob pattern e.g. **/*.tf or src/**/*.js' },
      },
      required: ['pattern'],
    },
  },
];

const OPENAI_TOOLS = CLAUDE_TOOLS.map(t => ({
  type: 'function',
  function: { name: t.name, description: t.description, parameters: t.input_schema },
}));

// ── Agent execution ────────────────────────────────────────────────────────

function buildUserMessage(repoPath, target, chainContexts) {
  let msg = `The repository to analyze is located at: ${repoPath}\n`;
  if (target) msg += `\nFocus area / target: ${target}\n`;
  if (chainContexts && chainContexts.length > 0) {
    msg += `\n${'─'.repeat(60)}\nCONTEXT FROM PREVIOUS AGENTS IN THIS PIPELINE\n${'─'.repeat(60)}\n\n`;
    for (const ctx of chainContexts) {
      const label = AGENT_META[ctx.agentId]?.label || ctx.agentId;
      msg += `### ${label} Output\n\n${ctx.summary}\n\n`;
    }
    msg += `${'─'.repeat(60)}\n\n`;
    msg += `Use the above context to inform your analysis. Build on the previous findings rather than repeating them.\n`;
  }
  msg += `\nBegin your full analysis now and produce the complete report as specified in your instructions.`;
  return msg;
}

async function runAgent({ agentId, repoPath, target, chainContexts, apiKey, model, onEvent, signal }) {
  const agent = AGENTS[agentId];
  if (!agent) throw new Error(`Unknown agent: ${agentId}`);

  const anthropic = new Anthropic({ apiKey });
  const messages = [{ role: 'user', content: buildUserMessage(repoPath, target, chainContexts) }];
  let fullText = '';

  for (let iter = 0; iter < 80; iter++) {
    if (signal?.aborted) throw new Error('Cancelled');

    onEvent({ type: 'iteration', n: iter + 1 });

    let stopReason = 'end_turn';
    const currentContent = [];
    let currentBlock = null;
    let inputBuf = '';

    const stream = anthropic.messages.stream({
      model: model || 'claude-sonnet-5',
      max_tokens: 16000,
      system: agent.systemPrompt,
      tools: CLAUDE_TOOLS,
      messages,
    });

    for await (const ev of stream) {
      if (signal?.aborted) { stream.abort?.(); break; }

      if (ev.type === 'content_block_start') {
        if (ev.content_block.type === 'tool_use') {
          currentBlock = { type: 'tool_use', id: ev.content_block.id, name: ev.content_block.name };
          inputBuf = '';
          onEvent({ type: 'tool_call_start', tool: ev.content_block.name, id: ev.content_block.id });
        } else {
          currentBlock = { type: 'text', text: '' };
        }
      } else if (ev.type === 'content_block_delta') {
        if (ev.delta.type === 'text_delta') {
          fullText += ev.delta.text;
          if (currentBlock?.type === 'text') currentBlock.text += ev.delta.text;
          onEvent({ type: 'text_chunk', text: ev.delta.text });
        } else if (ev.delta.type === 'input_json_delta') {
          inputBuf += ev.delta.partial_json;
        }
      } else if (ev.type === 'content_block_stop') {
        if (currentBlock?.type === 'tool_use') {
          try { currentBlock.input = JSON.parse(inputBuf || '{}'); } catch { currentBlock.input = {}; }
          currentContent.push({ ...currentBlock });
        } else if (currentBlock?.type === 'text') {
          currentContent.push({ ...currentBlock });
        }
        currentBlock = null;
      } else if (ev.type === 'message_delta') {
        stopReason = ev.delta.stop_reason || stopReason;
      }
    }

    const final = await stream.finalMessage();
    stopReason = final.stop_reason || stopReason;
    messages.push({ role: 'assistant', content: final.content });

    if (stopReason !== 'tool_use') break;

    const toolResults = [];
    for (const block of final.content) {
      if (block.type !== 'tool_use') continue;
      onEvent({ type: 'tool_executing', tool: block.name, input: block.input, id: block.id });
      const result = await executeTool(block.name, block.input, repoPath);
      onEvent({ type: 'tool_result', tool: block.name, id: block.id, preview: String(result).slice(0, 400) });
      toolResults.push({ type: 'tool_result', tool_use_id: block.id, content: String(result) });
    }
    messages.push({ role: 'user', content: toolResults });
  }

  return fullText;
}

async function runAgentLmStudio({ agentId, repoPath, target, chainContexts, model, baseUrl, apiKey, onEvent, signal }) {
  const agent = AGENTS[agentId];
  if (!agent) throw new Error(`Unknown agent: ${agentId}`);

  const messages = [
    { role: 'system', content: agent.systemPrompt },
    { role: 'user', content: buildUserMessage(repoPath, target, chainContexts) },
  ];
  let fullText = '';

  for (let iter = 0; iter < 80; iter++) {
    if (signal?.aborted) throw new Error('Cancelled');
    onEvent({ type: 'iteration', n: iter + 1 });

    const { text, toolCalls, finishReason } = await callLmStudioChat({
      baseUrl, model, messages, tools: OPENAI_TOOLS, signal, apiKey,
      onTextChunk: chunk => { fullText += chunk; onEvent({ type: 'text_chunk', text: chunk }); },
    });

    const assistantMsg = { role: 'assistant', content: text || null };
    if (toolCalls.length > 0) {
      assistantMsg.tool_calls = toolCalls.map(tc => ({
        id: tc.id, type: 'function', function: { name: tc.name, arguments: JSON.stringify(tc.args) },
      }));
    }
    messages.push(assistantMsg);

    if (finishReason !== 'tool_calls' || toolCalls.length === 0) break;

    for (const tc of toolCalls) {
      onEvent({ type: 'tool_call_start', tool: tc.name, id: tc.id });
      onEvent({ type: 'tool_executing', tool: tc.name, input: tc.args, id: tc.id });
      const result = await executeTool(tc.name, tc.args, repoPath);
      onEvent({ type: 'tool_result', tool: tc.name, id: tc.id, preview: String(result).slice(0, 400) });
      messages.push({ role: 'tool', tool_call_id: tc.id, content: String(result) });
    }
  }

  return fullText;
}

// ── Report generation ──────────────────────────────────────────────────────

async function generateReport(agentId, markdown, sessionId) {
  const session = sessions.get(sessionId);
  const dir = session?.tempDir
    ? path.join(session.tempDir, 'reports')
    : path.join(os.tmpdir(), `tl-reports-${sessionId}`);
  fs.mkdirSync(dir, { recursive: true });

  const ts = Date.now();
  const mdPath = path.join(dir, `${agentId}-${ts}.md`);
  const docxPath = path.join(dir, `${agentId}-${ts}.docx`);

  fs.writeFileSync(mdPath, markdown, 'utf8');

  let hasDocx = false;
  if (fs.existsSync(MD_TO_DOCX)) {
    try {
      await execAsync(`python3 "${MD_TO_DOCX}" "${mdPath}" "${docxPath}"`, { timeout: 60000 });
      hasDocx = fs.existsSync(docxPath);
    } catch (e) {
      console.error('docx conversion failed:', e.message);
    }
  }

  const report = {
    agentId,
    label: AGENT_META[agentId]?.label || agentId,
    timestamp: ts,
    mdPath,
    docxPath: hasDocx ? docxPath : null,
    sessionId,
  };
  if (session) session.reports.push(report);
  return report;
}

function extractSummary(markdown) {
  // Try to grab executive summary or first substantial section
  const match = markdown.match(/##\s*(?:TIER\s*1|Executive\s+Summary|Risk\s+Posture|Overview)([\s\S]{0,4000}?)(?=\n##|$)/i);
  if (match) return match[0].slice(0, 4000);
  return markdown.slice(0, 3000);
}

// ── HTTP API ───────────────────────────────────────────────────────────────

app.get('/api/lmstudio/models', async (req, res) => {
  const baseUrl = (req.query.baseUrl || 'http://localhost:1234/v1').replace(/\/$/, '');
  try {
    const data = await httpGetJson(`${baseUrl}/models`, 5000);
    const models = (data.data || []).map(m => m.id);
    res.json({ models });
  } catch (err) {
    res.status(503).json({ error: `Cannot reach LM Studio at ${baseUrl}: ${err.message}` });
  }
});

app.get('/api/fs/browse', (req, res) => {
  const raw = req.query.path || os.homedir();
  const requested = path.normalize(raw.replace(/^~(?=\/|$)/, os.homedir()));
  try {
    if (!fs.statSync(requested).isDirectory()) {
      return res.status(400).json({ error: 'Not a directory' });
    }
    const raw = fs.readdirSync(requested, { withFileTypes: true });
    const entries = raw
      .filter(e => e.isDirectory())
      .sort((a, b) => {
        // repos first, then alphabetical; hidden dirs last unless they're repos
        const aRepo = fs.existsSync(path.join(requested, a.name, '.git'));
        const bRepo = fs.existsSync(path.join(requested, b.name, '.git'));
        if (aRepo !== bRepo) return aRepo ? -1 : 1;
        const aHidden = a.name.startsWith('.');
        const bHidden = b.name.startsWith('.');
        if (aHidden !== bHidden) return aHidden ? 1 : -1;
        return a.name.localeCompare(b.name);
      })
      .map(e => ({
        name: e.name,
        isRepo: fs.existsSync(path.join(requested, e.name, '.git')),
      }));
    const parent = path.dirname(requested);
    res.json({ path: requested, parent: parent !== requested ? parent : null, entries });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/agents', (_req, res) => {
  const list = Object.values(AGENTS).map(a => ({
    id: a.id,
    name: a.name,
    description: a.description,
    ...AGENT_META[a.id],
  }));
  res.json(list);
});

app.post('/api/session/local', (req, res) => {
  const { repoPath } = req.body || {};
  if (!repoPath) return res.status(400).json({ error: 'repoPath required' });
  const expanded = repoPath.replace(/^~/, os.homedir());
  if (!fs.existsSync(expanded)) return res.status(400).json({ error: `Path not found: ${expanded}` });
  const id = createSession(expanded, false);
  res.json({ sessionId: id, repoPath: expanded });
});

app.post('/api/session/clone', async (req, res) => {
  const { url, username, token, branch } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url required' });

  const id = crypto.randomUUID();
  const tempDir = path.join(os.tmpdir(), `threatlint-${id}`);
  fs.mkdirSync(tempDir, { recursive: true });

  try {
    let cloneUrl = url;
    if (token) {
      const u = new URL(url.startsWith('http') ? url : `https://${url}`);
      u.username = encodeURIComponent(username || 'token');
      u.password = encodeURIComponent(token);
      cloneUrl = u.toString();
    }
    const branchFlag = branch ? `--branch "${branch}"` : '';
    await execAsync(
      `git clone --depth=20 ${branchFlag} "${cloneUrl}" "${path.join(tempDir, 'repo')}"`,
      { timeout: 300000 }
    );
    const repoPath = path.join(tempDir, 'repo');
    sessions.set(id, { id, repoPath, isTempRepo: true, tempDir, reports: [] });
    res.json({ sessionId: id, repoPath });
  } catch (err) {
    fs.rmSync(tempDir, { recursive: true, force: true });
    res.status(500).json({ error: err.message.replace(/https?:\/\/[^@]+@/, 'https://***@') });
  }
});

app.get('/api/session/:id', (req, res) => {
  const s = sessions.get(req.params.id);
  if (!s) return res.status(404).json({ error: 'Not found' });
  res.json({ id: s.id, repoPath: s.repoPath, reportCount: s.reports.length });
});

app.get('/api/session/:id/reports', (req, res) => {
  const s = sessions.get(req.params.id);
  if (!s) return res.status(404).json({ error: 'Not found' });
  res.json(s.reports.map(r => ({
    agentId: r.agentId,
    label: r.label,
    timestamp: r.timestamp,
    hasDocx: !!r.docxPath,
    mdUrl: `/api/report/${r.sessionId}/${r.agentId}/${r.timestamp}/md`,
    docxUrl: r.docxPath ? `/api/report/${r.sessionId}/${r.agentId}/${r.timestamp}/docx` : null,
  })));
});

app.get('/api/report/:sessionId/:agentId/:ts/:fmt', (req, res) => {
  const { sessionId, agentId, ts, fmt } = req.params;
  const s = sessions.get(sessionId);
  if (!s) return res.status(404).send('Session not found');
  const r = s.reports.find(x => x.agentId === agentId && String(x.timestamp) === ts);
  if (!r) return res.status(404).send('Report not found');
  if (fmt === 'md') {
    res.setHeader('Content-Disposition', `attachment; filename="${agentId}-${ts}.md"`);
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    return res.sendFile(r.mdPath);
  }
  if (fmt === 'docx' && r.docxPath) {
    res.setHeader('Content-Disposition', `attachment; filename="${agentId}-${ts}.docx"`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    return res.sendFile(r.docxPath);
  }
  res.status(404).send('Format not available');
});

// ── WebSocket handler ──────────────────────────────────────────────────────

const abortControllers = new Map();

wss.on('connection', ws => {
  const connId = crypto.randomUUID();
  console.log(`WS connected [${connId.slice(0, 8)}]`);

  function send(obj) {
    if (ws.readyState === 1) ws.send(JSON.stringify(obj));
  }

  ws.on('message', async raw => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return send({ type: 'error', message: 'Invalid JSON' }); }

    // ── Run pipeline ────────────────────────────────────────────────────────
    if (msg.action === 'run_pipeline') {
      const { sessionId, agentIds, target, apiKey, model, continueOnError,
              provider, lmstudioUrl, lmstudioModel, openaiApiKey } = msg;
      const isLocal = provider === 'lmstudio';
      const isOpenAI = provider === 'openai';
      const key = (isLocal || isOpenAI) ? null : (apiKey || process.env.ANTHROPIC_API_KEY);
      if (!isLocal && !isOpenAI && !key) return send({ type: 'error', message: 'Anthropic API key required' });
      if (isOpenAI && !(openaiApiKey || process.env.OPENAI_API_KEY)) return send({ type: 'error', message: 'OpenAI API key required' });
      const session = sessions.get(sessionId);
      if (!session) return send({ type: 'error', message: 'Session not found — configure a repo first' });

      const ac = new AbortController();
      abortControllers.set(connId, ac);

      send({ type: 'pipeline_start', agentIds });

      const chainContexts = [];
      for (const agentId of agentIds) {
        if (ac.signal.aborted) break;
        const meta = AGENT_META[agentId] || {};
        send({ type: 'agent_start', agentId, label: meta.label || agentId, color: meta.color });

        try {
          const output = (isLocal || isOpenAI)
            ? await runAgentLmStudio({
                agentId,
                repoPath: session.repoPath,
                target: target || '',
                chainContexts,
                model: isOpenAI ? (model || 'gpt-5.6') : (lmstudioModel || model || ''),
                baseUrl: isOpenAI
                  ? 'https://api.openai.com/v1'
                  : (lmstudioUrl || 'http://localhost:1234/v1').replace(/\/$/, ''),
                apiKey: isOpenAI ? (openaiApiKey || process.env.OPENAI_API_KEY) : undefined,
                signal: ac.signal,
                onEvent: ev => send({ ...ev, agentId }),
              })
            : await runAgent({
                agentId,
                repoPath: session.repoPath,
                target: target || '',
                chainContexts,
                apiKey: key,
                model: model || 'claude-sonnet-5',
                signal: ac.signal,
                onEvent: ev => send({ ...ev, agentId }),
              });

          const report = await generateReport(agentId, output, sessionId);
          chainContexts.push({ agentId, summary: extractSummary(output) });

          send({
            type: 'agent_complete',
            agentId,
            label: meta.label || agentId,
            hasDocx: !!report.docxPath,
            mdUrl: `/api/report/${sessionId}/${agentId}/${report.timestamp}/md`,
            docxUrl: report.docxPath ? `/api/report/${sessionId}/${agentId}/${report.timestamp}/docx` : null,
          });
        } catch (err) {
          send({ type: 'agent_error', agentId, message: err.message });
          if (!continueOnError) break;
        }
      }

      abortControllers.delete(connId);
      send({ type: 'pipeline_complete' });
    }

    // ── Cancel ──────────────────────────────────────────────────────────────
    else if (msg.action === 'cancel') {
      const ac = abortControllers.get(connId);
      if (ac) { ac.abort(); abortControllers.delete(connId); }
      send({ type: 'cancelled' });
    }

    // ── Chat ────────────────────────────────────────────────────────────────
    else if (msg.action === 'chat') {
      const { sessionId, message, history, apiKey, model, provider, lmstudioUrl, lmstudioModel, openaiApiKey } = msg;

      const session = sessions.get(sessionId);
      let system = `You are a senior application security expert assistant integrated with Threatlint, a multi-agent security analysis platform. Be concise, precise, and cite specific code locations when referencing findings.`;

      if (session?.reports?.length) {
        system += `\n\nReports from the current session:\n`;
        for (const r of session.reports.slice(-6)) {
          system += `\n### ${r.label}\n`;
          try { system += fs.readFileSync(r.mdPath, 'utf8').slice(0, 4000); } catch {}
        }
      }

      const msgs = [...(history || []).slice(-20), { role: 'user', content: message }];

      if (provider === 'lmstudio' || provider === 'openai') {
        const isOpenAI = provider === 'openai';
        const baseUrl = isOpenAI
          ? 'https://api.openai.com/v1'
          : (lmstudioUrl || 'http://localhost:1234/v1').replace(/\/$/, '');
        const chosenModel = isOpenAI ? (model || 'gpt-5.6') : (lmstudioModel || '');
        const key = isOpenAI ? (openaiApiKey || process.env.OPENAI_API_KEY) : undefined;
        if (!isOpenAI && !chosenModel) return send({ type: 'chat_error', message: 'No LM Studio model selected' });
        if (isOpenAI && !key) return send({ type: 'chat_error', message: 'OpenAI API key required' });

        send({ type: 'chat_start' });
        let fullText = '';
        streamLmStudio({
          baseUrl,
          model: chosenModel,
          systemPrompt: system,
          messages: msgs,
          maxTokens: 4096,
          apiKey: key,
          onChunk: text => { fullText += text; send({ type: 'chat_chunk', text }); },
          onDone: () => send({ type: 'chat_end', fullText }),
          onError: err => send({ type: 'chat_error', message: err.message }),
        });
        return;
      }

      // Claude (default)
      const key = apiKey || process.env.ANTHROPIC_API_KEY;
      if (!key) return send({ type: 'chat_error', message: 'API key required' });
      try {
        const anthropic = new Anthropic({ apiKey: key });
        const stream = anthropic.messages.stream({
          model: model || 'claude-sonnet-5',
          max_tokens: 4096,
          system,
          messages: msgs,
        });
        send({ type: 'chat_start' });
        for await (const ev of stream) {
          if (ev.type === 'content_block_delta' && ev.delta.type === 'text_delta') {
            send({ type: 'chat_chunk', text: ev.delta.text });
          }
        }
        const fin = await stream.finalMessage();
        send({ type: 'chat_end', fullText: fin.content[0]?.text || '' });
      } catch (err) {
        send({ type: 'chat_error', message: err.message });
      }
    }
  });

  ws.on('close', () => {
    console.log(`WS disconnected [${connId.slice(0, 8)}]`);
    abortControllers.get(connId)?.abort();
    abortControllers.delete(connId);
  });
});

// ── Serve index for any non-API routes ─────────────────────────────────────

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ──────────────────────────────────────────────────────────────────

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`\n┌─────────────────────────────────────────────┐`);
    console.log(`│  Threatlint Web UI                          │`);
    console.log(`│  http://localhost:${PORT}                       │`);
    console.log(`│  API key: ${process.env.ANTHROPIC_API_KEY ? 'loaded from env (ANTHROPIC_API_KEY)' : 'not set — enter in UI    '} │`);
    console.log(`└─────────────────────────────────────────────┘\n`);
  });
}

module.exports = { app, server };
