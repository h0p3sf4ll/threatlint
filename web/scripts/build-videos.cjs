'use strict';

/**
 * Builds the narrated video library and README screenshots from the real app.
 *
 *   npm --prefix web run videos            # all videos
 *   npm --prefix web run videos -- runtime # one video by id
 *
 * Requirements: Playwright Chromium (npx playwright install chromium), ffmpeg,
 * and a text-to-speech engine: macOS `say` (default) or `espeak-ng`/`espeak`.
 * Set THREATLINT_VOICE to pick a macOS voice and THREATLINT_BROWSER_EXECUTABLE
 * to use a specific Chromium.
 *
 * Every scene is a real screenshot of the workbench, driven against local
 * fixtures only: a deliberately weak loopback demo app, a fake source manager,
 * and the bundled synthetic report. No external service or model is contacted.
 * Outputs: web/public/media/<id>.mp4 + <id>.png (in-app library) and
 * docs/media/<id>.gif + <id>.png (README).
 */

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');
const { createWorkbench } = require('../server.js');
const { createDemoApp } = require('../examples/demo-app.cjs');
const { VIDEOS } = require('../lib/help.cjs');

const ROOT = path.resolve(__dirname, '../..');
const MEDIA = path.join(ROOT, 'web/public/media');
const DOCS_MEDIA = path.join(ROOT, 'docs/media');
const WIDTH = 1440, HEIGHT = 900;
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-videos-'));

// Friendly female narrator: the best installed US-English female voice, warmest first.
const FEMALE_VOICES = ['Ava (Premium)', 'Ava (Enhanced)', 'Zoe (Premium)', 'Zoe (Enhanced)', 'Samantha (Enhanced)', 'Allison (Enhanced)', 'Samantha'];
const SPEECH_RATE = '168';
let narrator;
function voice() {
  if (narrator) return narrator;
  if (process.env.THREATLINT_VOICE) return (narrator = process.env.THREATLINT_VOICE);
  const installed = execFileSync('say', ['-v', '?'], { encoding: 'utf8' }).split('\n').map(line => line.split(/\s{2,}/)[0].trim());
  narrator = FEMALE_VOICES.find(name => installed.includes(name)) || 'Samantha';
  console.log(`Narrator voice: ${narrator}`);
  return narrator;
}
function tts(text, file) {
  if (process.platform === 'darwin') {
    execFileSync('say', ['-v', voice(), '-r', SPEECH_RATE, '-o', file, '--data-format=LEI16@22050', text]);
    return;
  }
  for (const engine of ['espeak-ng', 'espeak']) {
    try { execFileSync(engine, ['-v', 'en-us+f3', '-s', '155', '-w', file, text]); return; } catch { /* try the next engine */ }
  }
  throw new Error('No text-to-speech engine found. Install espeak-ng or run on macOS.');
}
function duration(file) {
  return Number(execFileSync('ffprobe', ['-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', file]).toString().trim());
}
function ffmpeg(args) { execFileSync('ffmpeg', ['-hide_banner', '-loglevel', 'error', '-y', ...args]); }

// ── Fixtures ────────────────────────────────────────────────────────────────

function fakeSourceManagers(checkoutDir) {
  const repositories = [
    { id: '101', name: 'payments-api', fullName: 'acme-dev/payments-api', defaultBranch: 'main', webUrl: 'https://github.com/acme-dev/payments-api' },
    { id: '102', name: 'storefront', fullName: 'acme-dev/storefront', defaultBranch: 'main', webUrl: 'https://github.com/acme-dev/storefront' },
    { id: '103', name: 'infra', fullName: 'acme-dev/infra', defaultBranch: 'main', webUrl: 'https://github.com/acme-dev/infra' },
  ];
  let connected = [];
  return {
    list: () => connected,
    connect: async input => { const item = { id: '00000000-0000-4000-8000-000000000001', provider: input.provider, label: 'GitHub · acme-dev', account: 'acme-dev', host: 'github.com' }; connected = [item]; return item; },
    disconnect: () => { connected = []; return true; },
    repositories: async (_id, input) => ({ repositories: repositories.filter(repo => !input.search || repo.fullName.includes(input.search)), page: 1, hasMore: false }),
    branches: async () => ({ branches: [{ name: 'main' }, { name: 'feature/checkout-v2' }, { name: 'release/2026.10' }], page: 1, hasMore: false }),
    checkout: async () => ({ repoPath: checkoutDir, tempDir: null, provenance: { provider: 'github', repository: 'acme-dev/payments-api', branch: 'feature/checkout-v2', commit: 'c0ffee'.padEnd(40, '0'), webUrl: 'https://github.com/acme-dev/payments-api' } }),
  };
}

// Recorded answers stand in for a live model; they show the shape of a real reply.
async function chatAnswer(args) {
  const followUp = /where else/i.test(args.userMessage);
  for (const tool of followUp ? ['Grep SELECT .* \\{', 'Read api/orders.py'] : ['Read api/customers.py', 'Grep execute\\(']) {
    const [name, detail] = tool.split(' ');
    args.onEvent({ type: 'tool_executing', tool: name, input: { pattern: detail } }); await new Promise(resolve => setTimeout(resolve, 250));
  }
  return followUp
    ? 'Two more places build SQL from input:\n\n| Location | Input | Fix |\n| --- | --- | --- |\n| `api/orders.py:18` | `request.args["status"]` | bind as a parameter |\n| `api/reports.py:71` | `sort` column name | allowlist column names |\n\nThe second one cannot use a bound parameter, because it is an identifier. Use an allowlist instead.'
    : '**Why it matters:** `request.args["id"]` flows straight into the query at `api/customers.py:42`, so `\' OR \'1\'=\'1` returns every customer.\n\n**Fix:**\n\n```python\ncursor.execute(\n    "SELECT id, name FROM customers WHERE id = %s",\n    (customer_id,),\n)\n```\n\n**Regression test:**\n\n```python\ndef test_lookup_rejects_injection(client):\n    assert client.get("/customers?id=\' OR \'1\'=\'1").json == []\n```';
}

async function setup() {
  const repo = path.join(WORK, 'payments-api'); fs.mkdirSync(repo);
  fs.writeFileSync(path.join(repo, 'app.py'), 'print("synthetic")\n');
  const report = fs.readFileSync(path.join(ROOT, 'web/examples/fp-review.md'), 'utf8');
  const demo = createDemoApp(); await new Promise(resolve => demo.listen(0, '127.0.0.1', resolve));
  const workbench = createWorkbench({ storageDir: path.join(WORK, 'state'), sourceManagers: fakeSourceManagers(repo), runProvider: async args => {
    if (args.purpose === 'chat') return chatAnswer(args);
    for (const step of ['Reading the route table…\n', 'Tracing request.args into the query builder…\n', 'Checking the authorization decorator…\n']) {
      args.onEvent({ type: 'text_chunk', text: step }); await new Promise(resolve => setTimeout(resolve, 350));
    }
    return report;
  } });
  await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
  const launch = { headless: true };
  if (process.env.THREATLINT_BROWSER_EXECUTABLE) launch.executablePath = process.env.THREATLINT_BROWSER_EXECUTABLE;
  const browser = await chromium.launch(launch);
  return { repo, demo, demoUrl: `http://127.0.0.1:${demo.address().port}`, workbench, base: `http://127.0.0.1:${workbench.server.address().port}`, browser };
}

// A caption bar and a pointer highlight are drawn into the page for each frame.
async function caption(page, text, selector) {
  await page.evaluate(({ text, selector }) => {
    document.getElementById('video-caption')?.remove();
    document.getElementById('video-ring')?.remove();
    const bar = document.createElement('div');
    bar.id = 'video-caption'; bar.textContent = text;
    Object.assign(bar.style, { position: 'fixed', left: '50%', bottom: '26px', transform: 'translateX(-50%)', maxWidth: '980px', padding: '14px 22px', borderRadius: '12px',
      background: 'rgba(8,14,13,.92)', border: '1px solid #3d6b57', color: '#f2f7f4', font: '500 19px Inter, system-ui, sans-serif', lineHeight: '1.45', zIndex: 9999, boxShadow: '0 18px 50px rgba(0,0,0,.55)', textAlign: 'center' });
    document.body.append(bar);
    const target = selector && document.querySelector(selector);
    if (target) {
      const rect = target.getBoundingClientRect();
      const ring = document.createElement('div'); ring.id = 'video-ring';
      Object.assign(ring.style, { position: 'fixed', left: `${rect.left - 6}px`, top: `${rect.top - 6}px`, width: `${rect.width + 12}px`, height: `${rect.height + 12}px`,
        border: '2px solid #8ce5c7', borderRadius: '10px', boxShadow: '0 0 0 6px rgba(140,229,199,.18)', zIndex: 9998, pointerEvents: 'none' });
      document.body.append(ring);
    }
  }, { text, selector });
}

function terminalPage(title, lines) {
  const escape = value => value.replace(/[&<>]/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[char]));
  const body = lines.map(line => {
    const text = escape(line);
    if (line.startsWith('$ ')) return `<div class="cmd">${text}</div>`;
    if (/HIGH|CRITICAL|exit 2/.test(line)) return `<div class="bad">${text}</div>`;
    if (/secure alternative|added|installed|✓/.test(line)) return `<div class="good">${text}</div>`;
    return `<div>${text}</div>`;
  }).join('');
  return `<!doctype html><meta charset="utf-8"><style>body{margin:0;background:#0b1110;font:15px/1.65 "SF Mono",Menlo,monospace;color:#cfdcd6}
.win{margin:60px auto;width:1180px;border:1px solid #2b3a36;border-radius:12px;overflow:hidden;box-shadow:0 30px 80px #000a}
.bar{background:#141d1b;padding:11px 16px;color:#7f948d;font:13px system-ui}.bar b{display:inline-block;width:11px;height:11px;border-radius:50%;background:#3a4745;margin-right:6px}
pre{margin:0;padding:22px 26px;white-space:pre-wrap}.cmd{color:#8ce5c7}.bad{color:#f0a39b}.good{color:#a8d8a0}</style>
<div class="win"><div class="bar"><b></b><b></b><b></b> ${escape(title)}</div><pre>${body}</pre></div>`;
}

// ── Scenes ──────────────────────────────────────────────────────────────────
// Each scene: { say, caption?, highlight?, act(page, ctx) }. act runs before the frame.

const STORIES = {
  overview: ctx => [
    { say: 'Hi! This is Threatlint. Think of it as a security reviewer who sits right next to you. It reads your code, and tells you exactly what to fix: the file, the line, the fix, and the test.', act: async page => { await page.goto(ctx.base); await page.locator('#connection-status.online').waitFor(); } },
    { say: 'Start from a playbook. Each one is a curated set of agents for a common task, like reviewing a pull request or checking code your AI assistant just wrote.', highlight: '#workflow-presets' },
    { say: 'The agent library has twenty-two specialists: threat modeling, APIs, authentication, secrets, infrastructure, privacy, and secure code generation.', act: async page => { await page.click('[data-view="agents"]'); } },
    { say: 'Connect GitHub or Azure DevOps to check out any branch, then review it in one click.', act: async page => { await page.click('[data-view="sources"]'); } },
    { say: 'Runtime scanning tests a running app with real authentication, and draws the full attack chain from identity to impact.', act: async page => { await page.click('[data-view="runtime"]'); await page.click('#runtime-demo'); await page.waitForTimeout(500); await page.evaluate(() => document.getElementById('runtime-graph-board').scrollIntoView({ block: 'start' })); await page.evaluate(() => window.scrollBy(0, -60)); } },
    { say: 'Stuck on a finding? Just ask Threatlint, and it answers from your own code. Metrics show your progress, and the Learn tab has a guide for every workflow. Your code is never modified. Let’s find it, fix it, and prove it.', act: async page => { await page.click('[data-view="learn"]'); } },
  ],
  'first-review': ctx => [
    { say: 'Let’s run your very first review together. Open a repository from the top right. Threatlint only reads it.', highlight: '#choose-repo', act: async page => { await page.goto(ctx.base); await page.locator('#connection-status.online').waitFor(); } },
    { say: 'Type or browse to the folder, then press Open.', highlight: '#repository-dialog', act: async page => { await page.click('#choose-repo'); await page.fill('#repo-path', ctx.repo); } },
    { say: 'Next, choose a model. LM Studio keeps everything on your machine. Claude and OpenAI work too, and keys are held in memory only.', highlight: '#settings-dialog', act: async page => { await page.click('#open-repository'); await page.locator('#repository-dialog').waitFor({ state: 'hidden' }); await page.click('#settings-button'); await page.fill('#model-id', 'qwen2.5-coder-32b'); } },
    { say: 'Pick a playbook. Here, Pull request review loads the code, API, and authentication reviewers into your pipeline. Hover any question mark for an explanation.', highlight: '.pipeline-panel', act: async page => { await page.click('#settings-form button[type=submit]'); await page.getByRole('button', { name: /Pull request review/ }).click(); } },
    { say: 'Press Run. The activity panel streams what each agent inspects. For this walkthrough a recorded sample report stands in for a live model.', highlight: '.activity-panel', act: async page => { await page.click('#start-run'); await page.waitForTimeout(1600); } },
    { say: 'When it finishes, open Findings and read them. Each one cites a file and line, a severity, a proposed fix, and a regression test.', act: async page => { await page.waitForFunction(() => /complete|attention/i.test(document.getElementById('activity-badge').textContent), null, { timeout: 20000 }); await page.click('[data-view="reports"]'); await page.getByRole('button', { name: 'Read report ↗' }).first().click(); await page.click('#report-tab-findings'); } },
    { say: 'Fix critical and high findings first. Download the report as Markdown or Word to hand off to your team.', highlight: '#report-findings' },
  ],
  ask: ctx => [
    { say: 'Found a finding and not sure how to fix it? Let’s ask Threatlint. Open the report, switch to findings, and press Ask how to fix this.', highlight: '.finding-card-actions', act: async page => {
      await ctx.seedReport(); await page.goto(ctx.base); await page.locator('#connection-status.online').waitFor();
      await page.click('#choose-repo'); await page.fill('#repo-path', ctx.repo); await page.click('#open-repository'); await page.locator('#repository-dialog').waitFor({ state: 'hidden' });
      await page.click('#settings-button'); await page.fill('#model-id', 'qwen2.5-coder-32b'); await page.click('#settings-form button[type=submit]');
      await page.click('[data-view="reports"]'); await page.getByRole('button', { name: 'Read report ↗' }).first().click(); await page.click('#report-tab-findings'); } },
    { say: 'Threatlint opens a conversation about that exact finding, with a suggested question ready to go. You can edit it, or just press send.', highlight: '#chat-form', act: async page => { await page.getByRole('button', { name: /Ask how to fix this/ }).first().click(); } },
    { say: 'It reads your repository with read only tools, then answers with the change to make, where to make it, and a test that proves the fix.', highlight: '.chat-messages', act: async page => {
      await page.click('#chat-send'); await page.waitForFunction(() => document.querySelectorAll('.chat-message.assistant:not(.streaming)').length > 0, null, { timeout: 15000 }); } },
    { say: 'Follow up in plain language, like, where else do we build SQL like this? It remembers the conversation, and saves it for this workspace.', act: async page => {
      await page.fill('#chat-input', 'Where else do we build SQL like this?'); await page.keyboard.press('Enter');
      await page.waitForFunction(() => document.querySelectorAll('.chat-message.assistant:not(.streaming)').length > 1, null, { timeout: 15000 }); } },
    { say: 'And on a pull request, just comment slash threatlint with your question. The same assistant replies right in the thread, on GitHub or Azure DevOps.', act: async page => {
      await page.setContent(terminalPage('Pull request #482 · payments-api', ['@dev-sam commented:', '/threatlint why is CR-001 high, and what is the smallest safe fix?', '', 'threatlint (bot) replied:', '✓ CR-001 is HIGH because request.args["id"] reaches the SQL string at api/customers.py:42 without binding.', '  Anyone who can call /customers can read every row.', '  Smallest safe fix:', '    cursor.execute("SELECT * FROM customers WHERE id = %s", (customer_id,))', '  Regression test: test_lookup_rejects_injection (expects zero rows for \' OR \'1\'=\'1).'])); } },
  ],
  'connect-source': ctx => [
    { say: 'To review code that is not on your machine, open Connect source. You can connect GitHub or Azure DevOps.', act: async page => { await page.goto(`${ctx.base}/#sources`); await page.locator('#connection-status.online').waitFor(); await page.click('[data-view="sources"]'); } },
    { say: 'Create a read only token. For GitHub, a fine grained token with contents and metadata read. For Azure DevOps, code read. Paste it and press Connect. The token stays in runner memory and is never saved.', highlight: '#scm-connection-form', act: async page => { await page.fill('#scm-token', 'github_pat_demo_only_token'); } },
    { say: 'Your repositories appear on the right. This walkthrough uses a demonstration account. Search, then select a repository.', highlight: '.sources-repositories', act: async page => { await page.click('#scm-connect'); await page.locator('.scm-repository-select').first().waitFor(); } },
    { say: 'Choose the exact branch you want reviewed, such as a feature branch before you open a pull request.', highlight: '.scm-checkout', act: async page => { await page.locator('.scm-repository-select').first().click(); await page.locator('#scm-branch option', { hasText: 'feature/checkout-v2' }).waitFor({ state: 'attached' }); await page.selectOption('#scm-branch', 'feature/checkout-v2'); } },
    { say: 'Press Check out. Threatlint makes a shallow, hook free checkout and opens it as your workspace, ready for any playbook.', act: async page => { await page.click('#scm-checkout'); await page.waitForTimeout(800); } },
  ],
  'runtime-scan': ctx => [
    { say: 'Runtime scanning checks a running application. Only scan environments you own or are allowed to test. Here we use a deliberately weak demo app on this machine.', act: async page => { await page.goto(ctx.base); await page.locator('#connection-status.online').waitFor(); await page.click('[data-view="runtime"]'); } },
    { say: 'Enter the target and the exact paths to request. Threatlint only sends GET requests, with a request budget, and never crawls.', highlight: '#runtime-scope-title', act: async page => {
      await page.fill('#runtime-target', ctx.demoUrl); await page.fill('#runtime-paths', JSON.stringify(['/', '/api/profile', '/api/orders', '/api/admin/users', '/debug']));
      await page.check('#runtime-allow-private'); await page.check('#runtime-authorized'); } },
    { say: 'Choose an authentication workflow. Bearer tokens, basic, API keys, cookies, OAuth client credentials, refresh tokens, form login, mutual TLS, and manual browser sign in for single sign on and MFA are all supported.', highlight: '#runtime-auth-type', act: async page => {
      await page.selectOption('#runtime-auth-type', 'oauth-client-credentials');
      await page.fill('#runtime-auth-tokenUrl', `${ctx.demoUrl}/oauth/token`); await page.fill('#runtime-auth-clientId', 'ci-client'); await page.fill('#runtime-auth-clientSecret', 'ci-secret'); } },
    { say: 'To catch broken access control, compare against anonymous requests and add lower privilege roles. Assertions say which status a path must return.', highlight: '#runtime-roles-details', act: async page => {
      await page.check('#runtime-compare-anonymous'); await page.click('#runtime-roles-details summary'); await page.click('#runtime-add-role');
      await page.fill('#runtime-roles [data-role=label]', 'developer'); await page.fill('#runtime-roles [data-role=secret]', 'dev-token');
      await page.locator('summary', { hasText: 'Access-control assertions' }).click(); await page.fill('#runtime-assertions', '[{"path":"/api/orders","expectedAnonymousStatus":[401,403]}]');
      await page.locator('summary', { hasText: 'Request budget' }).click(); await page.fill('#runtime-delay', '0'); } },
    { say: 'Start the scan. The attack chain fills in live. Each column is a step: identity, request, response or access control, finding, and impact hypothesis.', act: async page => {
      await page.click('#runtime-start'); await page.waitForFunction(() => /COMPLETE/.test(document.getElementById('runtime-scan-status').textContent), null, { timeout: 20000 });
      await page.evaluate(() => document.getElementById('runtime-graph-board').scrollIntoView({ block: 'start' })); await page.evaluate(() => window.scrollBy(0, -60)); } },
    { say: 'Click a finding to light up its full chain. Here, anonymous users can read orders, which is flagged as a failed access control assertion, with the impact it could enable.', highlight: '#runtime-node-detail', act: async page => {
      await page.check('#runtime-chain-only'); await page.waitForTimeout(300);
      await page.locator('.runtime-node', { hasText: 'Access-control assertion' }).first().click(); await page.evaluate(() => document.getElementById('runtime-graph-board').scrollIntoView({ block: 'start' })); await page.evaluate(() => window.scrollBy(0, -60)); } },
    { say: 'Each finding includes a proposed fix. Export the evidence, or send it to the runtime review agent to trace each observation back to the source code that caused it.', highlight: '#runtime-findings', act: async page => { await page.locator('#runtime-findings').scrollIntoViewIfNeeded(); } },
  ],
  dashboards: ctx => [
    { say: 'Metrics turns every saved report and runtime scan into numbers you can track.', act: async page => { await ctx.seedMetrics(); await page.goto(ctx.base); await page.locator('#connection-status.online').waitFor(); await page.click('[data-view="metrics"]'); await page.waitForTimeout(900); } },
    { say: 'The built in security posture dashboard shows open risk, findings by severity, trends over time, risk by specialist, and a specialist by severity heatmap. Hover any mark for exact values, or switch a chart to a table.', highlight: '#dashboard-grid' },
    { say: 'To build your own, press Duplicate or New dashboard. Name it, then add widgets.', highlight: '#dashboard-editor', act: async page => { await page.click('#dashboard-new'); await page.fill('#dashboard-name', 'API team · sprint 42'); } },
    { say: 'Each widget is a metric, a dimension, and a chart. For example, findings grouped by workspace as a bar chart, filtered to high severity.', highlight: '#widget-editor', act: async page => {
      await page.click('#widget-add'); const row = page.locator('.widget-row').last();
      await row.locator('input').first().fill('High findings by workspace'); await row.locator('select').nth(0).selectOption('hbar'); await row.locator('select').nth(2).selectOption('workspace'); await row.locator('select').nth(5).selectOption('HIGH'); } },
    { say: 'Save it. Dashboards are stored locally, and Export CSV takes the raw findings into your own BI tool.', act: async page => { await page.click('#dashboard-save'); await page.waitForTimeout(900); } },
  ],
  ide: ctx => [
    { say: 'Threatlint also works inside your editor, so code generated by AI assistants is secure by default.', act: async page => { await page.setContent(terminalPage('terminal — your-repo', ['$ pip install threatlint', '$ threatlint ide install', ...ctx.ideInstall])); } },
    { say: 'One command installs secure coding rules for GitHub Copilot, Cursor, Windsurf, and Claude Code, plus a Claude Code hook, VS Code tasks, and a pre-commit check.' },
    { say: 'The guard is a fast, offline checker with rules for injection, unsafe deserialization, disabled TLS verification, weak crypto, and hardcoded secrets. Every finding comes with a secure alternative.', act: async page => { await page.setContent(terminalPage('terminal — your-repo', ['$ threatlint guard generated.py', ...ctx.guard])); } },
    { say: 'In Claude Code, the hook runs the guard after every edit. Findings are sent back to the model, which rewrites the code before you ever see it. The VS Code extension shows the same findings inline on save.' },
    { say: 'Before you push, run the secure code generation agent on your diff from the workbench. Then let the reusable CI template gate the pull request.', act: async page => { await page.goto(ctx.base); await page.locator('#connection-status.online').waitFor(); await page.getByRole('button', { name: /Check AI-generated code/ }).click(); } },
  ],
};

async function seedReport(ctx) {
  if (ctx.reportSeeded) return; ctx.reportSeeded = true;
  const response = await fetch(`${ctx.base}/api/session/local`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ repoPath: ctx.repo }) });
  const { sessionId } = await response.json();
  await ctx.workbench.generateReport('appsec-code-reviewer', fs.readFileSync(path.join(ROOT, 'web/examples/fp-review.md'), 'utf8'), sessionId);
}

async function seedMetrics(ctx) {
  const { workbench } = ctx;
  if (ctx.seeded) return; ctx.seeded = true;
  const report = fs.readFileSync(path.join(ROOT, 'web/examples/fp-review.md'), 'utf8');
  const day = 86_400_000;
  for (const [index, name] of ['payments-api', 'storefront', 'infra'].entries()) {
    const dir = path.join(WORK, `metrics-${name}`); fs.mkdirSync(dir, { recursive: true });
    const id = workbench.store.create(dir);
    for (const [offset, agentId] of [[9, 'appsec-code-reviewer'], [5 + index, 'appsec-api-security-reviewer'], [2, 'appsec-fp-reviewer']]) {
      const saved = await workbench.generateReport(agentId, report, id);
      saved.timestamp = Date.now() - offset * day; workbench.store.save();
    }
  }
  await fetch(`${ctx.base}/api/runtime/scans`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: ctx.demoUrl, paths: ['/', '/api/orders', '/debug'],
    authorization: { confirmed: true, allowPrivate: true, reason: 'demo fixture' }, auth: { type: 'bearer', token: 'admin-token' }, checks: { compareAnonymous: true },
    assertions: [{ path: '/api/orders', expectedAnonymousStatus: [401] }], limits: { delayMs: 0 } }) });
  await new Promise(resolve => setTimeout(resolve, 600));
}

function commandOutput(command, args, options = {}) {
  try { return execFileSync(command, args, { encoding: 'utf8', ...options }); } catch (error) { return `${error.stdout || ''}${error.stderr || ''}`; }
}

async function build(id, ctx) {
  const video = VIDEOS.find(item => item.id === id);
  const scenes = STORIES[id](ctx);
  const page = await ctx.browser.newPage({ viewport: { width: WIDTH, height: HEIGHT }, deviceScaleFactor: 1 });
  const clips = [];
  for (const [index, scene] of scenes.entries()) {
    if (scene.act) await scene.act(page, ctx);
    await page.waitForTimeout(250);
    await caption(page, scene.caption || scene.say, scene.highlight);
    const frame = path.join(WORK, `${id}-${index}.png`), audio = path.join(WORK, `${id}-${index}.wav`), clip = path.join(WORK, `${id}-${index}.mp4`);
    await page.screenshot({ path: frame });
    tts(scene.say, audio);
    const seconds = duration(audio) + 0.7;
    ffmpeg(['-loop', '1', '-i', frame, '-i', audio, '-filter_complex', `[0:v]scale=${WIDTH}:${HEIGHT},fade=t=in:st=0:d=0.25,format=yuv420p[v];[1:a]apad=pad_dur=0.7[a]`,
      '-map', '[v]', '-map', '[a]', '-t', seconds.toFixed(2), '-r', '24', '-c:v', 'libx264', '-preset', 'veryfast', '-crf', '26', '-tune', 'stillimage', '-c:a', 'aac', '-b:a', '96k', '-ar', '44100', clip]);
    clips.push({ clip, frame, seconds });
    if (index === 0 || (id === 'runtime-scan' && index === 5) || (id === 'dashboards' && index === 1) || (id === 'ask' && index === 2)) fs.copyFileSync(frame, path.join(WORK, `${id}-poster.png`));
  }
  await page.close();
  const list = path.join(WORK, `${id}.txt`);
  fs.writeFileSync(list, clips.map(item => `file '${item.clip}'`).join('\n'));
  ffmpeg(['-f', 'concat', '-safe', '0', '-i', list, '-c', 'copy', '-movflags', '+faststart', path.join(MEDIA, video.file)]);
  // Posters double as README screenshots; GIFs are silent, low-frame-rate previews.
  ffmpeg(['-i', path.join(WORK, `${id}-poster.png`), '-vf', 'scale=1280:-1', path.join(MEDIA, video.poster)]);
  fs.copyFileSync(path.join(MEDIA, video.poster), path.join(DOCS_MEDIA, video.poster));
  const gifList = path.join(WORK, `${id}-gif.txt`);
  fs.writeFileSync(gifList, clips.map(item => `file '${item.frame}'\nduration ${Math.min(3.2, item.seconds).toFixed(2)}`).join('\n') + `\nfile '${clips.at(-1).frame}'`);
  ffmpeg(['-f', 'concat', '-safe', '0', '-i', gifList, '-vf', 'scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96[p];[b][p]paletteuse=dither=bayer:bayer_scale=4', '-r', '1', path.join(DOCS_MEDIA, `${id}.gif`)]);
  const total = clips.reduce((sum, item) => sum + item.seconds, 0);
  console.log(`✓ ${video.file}  ${scenes.length} scenes · ${total.toFixed(0)}s narrated`);
}

(async () => {
  fs.mkdirSync(MEDIA, { recursive: true }); fs.mkdirSync(DOCS_MEDIA, { recursive: true });
  const ctx = await setup();
  ctx.seedMetrics = () => seedMetrics(ctx);
  ctx.seedReport = () => seedReport(ctx);
  const threatlint = process.env.THREATLINT_CLI || 'threatlint';
  const ideRepo = path.join(WORK, 'ide-repo'); fs.mkdirSync(ideRepo); execFileSync('git', ['init', '-q'], { cwd: ideRepo });
  ctx.ideInstall = commandOutput(threatlint, ['ide', 'install', '--target', ideRepo]).trim().split('\n');
  const sample = path.join(ideRepo, 'generated.py');
  fs.writeFileSync(sample, 'import pickle, subprocess, requests\n\ndef load(blob):\n    return pickle.loads(blob)\n\ndef thumbnail(name):\n    subprocess.run(f"convert {name} thumb.png", shell=True)\n\nAPI_KEY = "sk_live_51HxQ2fakeKey9876543210abcd"\nrequests.get("https://api.example.com", verify=False)\n');
  ctx.guard = commandOutput(threatlint, ['guard', 'generated.py'], { cwd: ideRepo }).trim().split('\n');
  const only = process.argv.slice(2);
  try {
    for (const video of VIDEOS) if (!only.length || only.includes(video.id)) await build(video.id, ctx);
  } finally {
    await ctx.browser.close(); await ctx.workbench.close(); ctx.demo.close();
    fs.rmSync(WORK, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exit(1); });
