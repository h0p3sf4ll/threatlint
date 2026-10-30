'use strict';

/**
 * Developer help content shared by the browser and desktop workbench.
 * TOOLTIPS: keyed by the data-tip attribute in index.html.
 * HELP_TOPICS: short, task-oriented guides shown in the Learn view.
 * VIDEOS: narrated walkthroughs rendered by docs/media/build-videos.cjs into
 *   web/public/media (MP4 with voiceover) and docs/media (GIF previews).
 */

const TOOLTIPS = {
  'open-repo': 'Pick a local folder or a checkout from Connect source. Agents only read it; nothing is modified.',
  pipeline: 'Agents run top to bottom. Each later agent receives the earlier agents’ findings as untrusted context to verify.',
  playbooks: 'Curated agent combinations for common developer tasks. Click one to load it into your pipeline.',
  scope: 'Optional. Narrow the review: a path (src/api), a diff range (main...HEAD), or a question (“is the upload route safe?”).',
  attach: 'Attach SARIF or Semgrep JSON so the triage agent can separate true positives from noise.',
  provider: 'Choose LM Studio for fully local analysis, or Claude / OpenAI. Keys stay in memory only.',
  'start-run': 'Starts the pipeline. You can stop at any time; completed reports are kept.',
  severity: 'CRITICAL/HIGH should block a merge. MEDIUM needs a ticket. LOW/INFO are hardening suggestions.',
  confidence: 'CONFIRMED = traced in source. PLAUSIBLE = likely but a link is unverified. THEORETICAL = needs runtime proof.',
  'scm-token': 'Use a fine-grained read-only token. GitHub: Contents + Metadata read. Azure DevOps: Code (Read).',
  'scm-checkout': 'Creates a shallow, hook-free temporary checkout and opens it as a workspace.',
  'runtime-target': 'Only scan environments you own or are explicitly allowed to test. Staging, not production.',
  'runtime-paths': 'Exact paths to request with GET. No crawling and no destructive payloads.',
  'runtime-auth': 'Every common workflow is supported: tokens, Basic, API keys, cookies, OAuth, form login, mTLS, and manual SSO/MFA sign-in.',
  'runtime-roles': 'Add lower-privilege roles to compare responses path-by-path and spot broken access control.',
  'runtime-chain': 'Each column is a step in the chain: who you are → what you asked → what came back → what it reveals → what it could enable.',
  'metrics-kpi': 'Open risk score = Σ severity weight for findings not marked false positive or remediated (CRITICAL 10, HIGH 6, MEDIUM 3, LOW 1).',
  'dashboard-builder': 'Add widgets, pick a metric, a dimension, and a chart. Dashboards are saved locally.',
  'chat-context': 'What the conversation is about. Threatlint can still read the whole repository to answer.',
  'fpreview-input': 'Paste AVIT and SCTASK numbers in any mix, separated by commas, spaces, semicolons, or new lines. Each SCTASK expands to the AVITs in its description; duplicates are reviewed once, up to 50 AVITs per run.',
  'evidence-coverage': 'Share of findings that cite a file:line location. Higher means easier to fix.',
};

const HELP_TOPICS = [
  { id: 'first-review', title: 'Run your first review in 60 seconds', minutes: 1, steps: [
    'Open a repository (top-right) or check one out from Connect source.',
    'Pick the “Pull request review” playbook, or add agents from the Agent library.',
    'Open Model & settings and choose LM Studio (local) or a cloud model.',
    'Press Start review and watch the activity stream.',
    'Open Findings → Read report. Fix CRITICAL/HIGH first; each finding includes a proposed patch and a regression test.',
    'Press “Ask how to fix this” on any finding to get a code change for your repository and a test.',
  ], video: 'first-review' },
  { id: 'ask', title: 'Ask Threatlint about your code', minutes: 1, steps: [
    'Open Ask Threatlint, or press “Ask about this report” / “Ask how to fix this” in a report.',
    'Ask in plain language: “Why is CR-002 high?”, “Where else do we build SQL from input?”, “Write the test.”',
    'Threatlint reads your repository with read-only tools and answers with file:line references, a fix, and a test.',
    'Follow up in the same conversation; it remembers the thread. Conversations are saved locally per workspace.',
    'On pull requests, comment `/threatlint <question>` to ask the same assistant from GitHub or Azure DevOps.',
  ], video: 'ask' },
  { id: 'connect-source', title: 'Connect GitHub or Azure DevOps', minutes: 2, steps: [
    'Create a read-only token: GitHub fine-grained PAT (Contents: read, Metadata: read) or Azure DevOps PAT (Code: Read).',
    'Go to Connect source, choose the provider, paste the token, and press Connect. Tokens live only in runner memory.',
    'Search for a repository, choose a branch, and press Check out & open workspace.',
    'The checkout opens as a normal workspace with its provider, branch, and commit recorded.',
  ], video: 'connect-source' },
  { id: 'runtime-scan', title: 'Scan a running app with authentication', minutes: 3, steps: [
    'Go to Scan running app. Enter your staging URL and the exact paths to check.',
    'Describe your authorization and tick the consent box. Loopback/private targets need the extra opt-in.',
    'Choose an authentication workflow. For SSO/MFA use Manual browser sign-in: a real browser opens, you sign in, then press Finish.',
    'Optionally add lower-privilege roles and anonymous comparison to detect broken access control.',
    'Start the scan. The attack chain fills in live: identity → request → response/control → finding → impact hypothesis.',
    'Press “Ask about this scan” to discuss results, or send the evidence to the Runtime review agent to correlate it with source code.',
  ], video: 'runtime-scan' },
  { id: 'ide', title: 'Secure-by-default AI coding in your IDE', minutes: 2, steps: [
    'Run `threatlint ide install` in your repository.',
    'Copilot, Cursor, Windsurf, and Claude Code now receive secure-coding rules for every generation.',
    'Claude Code runs `threatlint guard` after each edit and rewrites insecure code automatically.',
    'Install the VS Code extension from ide/vscode for inline diagnostics on save.',
    'Before you push, run the Secure codegen agent on your diff.',
  ], video: 'ide' },
  { id: 'dashboards', title: 'Build a metrics dashboard', minutes: 2, steps: [
    'Open Metrics. The built-in Security posture dashboard summarizes every saved report and runtime scan.',
    'Press Duplicate to customize, or New dashboard to start empty.',
    'Add widget → choose a metric (findings, risk score, evidence coverage…), a dimension (severity, agent, workspace, day…), and a chart.',
    'Use filters (e.g. severity = HIGH, since 2026-01-01) to focus a widget.',
    'Save. Export CSV to take the raw findings into your own BI tool.',
  ], video: 'dashboards' },
  { id: 'ci', title: 'Gate pull requests in CI', minutes: 2, steps: [
    'GitHub: call the reusable workflow `.github/workflows/threatlint-reusable.yml` from your repository.',
    'Azure DevOps: reference `azure-pipelines/templates/threatlint-job.yml` through a repository resource.',
    'Choose agents, a provider, and a severity threshold. By default findings warn (the build stays green); set gate-mode: fail to block merges.',
    'Findings are uploaded as SARIF and posted to the PR. Reply `/threatlint <question>` on the PR to converse with the configured model.',
  ], video: 'ci' },
  { id: 'fp-review', title: 'Review AVITs and SCTASKs for false positives', minutes: 2, steps: [
    'Open Test → False positive review and finish the required setup it lists (ServiceNow, Azure DevOps PAT, Semgrep token).',
    'Paste AVIT and SCTASK numbers in any mix, separated by commas, spaces, semicolons, or new lines.',
    'Each SCTASK is expanded into its AVITs; an AVIT named twice is reviewed once, and a task that cannot be read is reported without stopping the rest.',
    'The progress bar counts every AVIT that reached a final state (closed, noted, error, skipped); spinners mark what is still in progress.',
    'Every card keeps a timestamped history, and the activity log lists every event in the run. The history stays for this browser session after a reload.',
  ] },
];

const VIDEOS = [
  { id: 'overview', title: 'Threatlint in two minutes', file: 'overview.mp4', poster: 'overview.png', topic: null },
  { id: 'first-review', title: 'Your first review', file: 'first-review.mp4', poster: 'first-review.png', topic: 'first-review' },
  { id: 'ask', title: 'Ask Threatlint how to fix it', file: 'ask.mp4', poster: 'ask.png', topic: 'ask' },
  { id: 'connect-source', title: 'Connect a source code manager', file: 'connect-source.mp4', poster: 'connect-source.png', topic: 'connect-source' },
  { id: 'runtime-scan', title: 'Authenticated runtime scan and attack chain', file: 'runtime-scan.mp4', poster: 'runtime-scan.png', topic: 'runtime-scan' },
  { id: 'dashboards', title: 'Metrics and custom dashboards', file: 'dashboards.mp4', poster: 'dashboards.png', topic: 'dashboards' },
  { id: 'ide', title: 'Secure-by-default code in the IDE', file: 'ide.mp4', poster: 'ide.png', topic: 'ide' },
];

module.exports = { TOOLTIPS, HELP_TOPICS, VIDEOS };
