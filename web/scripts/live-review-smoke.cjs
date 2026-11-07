'use strict';

/** Explicit opt-in only: real Codex calls against a generated synthetic fixture, never a user repo. */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { AGENTS } = require('../lib/agents.cjs');
const { runCodex, status } = require('../lib/codex.cjs');
const { inventorySource, partitionFiles } = require('../lib/review-scopes.cjs');
const { orchestrateReview } = require('../lib/review-orchestration.cjs');

async function main(args) {
  if (!args.includes('--confirm-live')) throw new Error('Pass --confirm-live to authorize real Codex usage against the generated fixture. No other provider is called.');
  const option = (name, fallback) => args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
  const workers = Number(option('--workers', '1'));
  if (![1, 2].includes(workers)) throw new Error('--workers must be 1 or 2');
  const model = option('--model', 'gpt-6-astra');
  if (!model || model.startsWith('-')) throw new Error('Provide a model ID');
  const destination = option('--output-dir', null);
  if (!destination || destination.startsWith('-')) throw new Error('Provide --output-dir for local acceptance artifacts');
  const authenticated = await status();
  if (!authenticated.loggedIn) throw new Error('Codex is not signed in; no model calls were made');
  const repoPath = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-live-fixture-'));
  const output = path.resolve(destination, `codex-${workers}-workers-${Date.now()}`);
  fs.mkdirSync(output, { recursive: true, mode: 0o700 });
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5 * 60_000);
  const cancel = () => controller.abort();
  process.once('SIGINT', cancel); process.once('SIGTERM', cancel);
  const stages = [], calls = [];
  const started = performance.now();
  const summary = { schemaVersion: 1, requestedModel: model, reportedModel: null, reasoningEffort: 'native provider default',
    provider: 'codex', workers, plannedModelRuns: workers + 1, distinctProviders: false,
    limitations: 'Synthetic fixture only. One provider assessment/challenge tests serialization, not independent consensus, production detection quality, or a representative speedup.' };
  try {
    for (let index = 1; index <= 4; index++) fs.writeFileSync(path.join(repoPath, `handler-${index}.js`),
      `// Synthetic test fixture ${index}: an authenticated caller can supply another account's ID.\nmodule.exports = (req, res, store) => res.json(store.find(req.params.accountId));\n`, { mode: 0o600 });
    const inventory = inventorySource(repoPath), scopes = partitionFiles(inventory.files, workers);
    const participant = { id: 'codex-smoke', provider: 'codex', model };
    const result = await orchestrateReview({ agentId: 'appsec-auth-reviewer', repoPath,
      systemPrompt: AGENTS['appsec-auth-reviewer'].systemPrompt, inventory,
      scopePlan: { requested: workers, scopes, reason: null }, participants: [participant], ensemble: true,
      concurrency: workers, signal: controller.signal, send: event => stages.push({ ...event, elapsedMs: Math.round(performance.now() - started) }),
      userMessage: () => `Review only this synthetic repository: ${repoPath}. The caller is authenticated as one account. The store can return another account's private records and performs no authorization itself. Determine whether the supplied account ID is restricted to the caller. Keep reports concise, cite literal source, and report only the synthetic authorization issue if supported. Do not run tests or write files.`,
      invoke: async ({ participant: selected, stage, workerId, ...request }) => {
        const start = performance.now();
        const call = { stage, workerId, requestedModel: selected.model, startedMs: Math.round(start - started) }; calls.push(call);
        try { return await runCodex({ ...request, repoPath, model: selected.model }); }
        finally { call.durationMs = Math.round(performance.now() - start); }
      } });
    fs.writeFileSync(path.join(output, 'report.md'), result.output, { mode: 0o600 });
    fs.writeFileSync(path.join(output, 'provenance.json'), JSON.stringify(result.metadata, null, 2), { mode: 0o600 });
    Object.assign(summary, { status: 'complete', candidates: result.metadata.findings.length,
      verifiedCitations: result.metadata.findings.flatMap(item => item.evidence).filter(item => item.verified).length });
  } catch (error) {
    Object.assign(summary, { status: controller.signal.aborted ? 'cancelled' : 'error', error: String(error.message).slice(0, 500) });
    process.exitCode = 1;
  } finally {
    clearTimeout(timeout); process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel);
    Object.assign(summary, { elapsedMs: Math.round(performance.now() - started), calls, stages });
    fs.writeFileSync(path.join(output, 'acceptance.json'), JSON.stringify(summary, null, 2), { mode: 0o600 });
    fs.rmSync(repoPath, { recursive: true, force: true });
    console.log(JSON.stringify({ status: summary.status, elapsedMs: summary.elapsedMs, calls: calls.length, acceptance: path.join(output, 'acceptance.json'), ...(summary.error ? { error: summary.error } : {}) }));
  }
}

if (require.main === module) main(process.argv.slice(2)).catch(error => { console.error(error.message); process.exitCode = 1; });
