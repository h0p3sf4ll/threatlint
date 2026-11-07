'use strict';

const { AGENTS } = require('./agents.cjs');
const { positiveLimit, checkAbort } = require('./concurrency.cjs');
const { HttpError } = require('./http.cjs');

/** Build and validate the whole graph before any provider or integration call. */
function buildPlan(agentIds, execution = {}) {
  if (!execution || typeof execution !== 'object' || Array.isArray(execution)) throw new HttpError('Execution must be an object');
  const mode = execution.mode ?? 'auto';
  if (!['auto', 'sequential'].includes(mode)) throw new HttpError('Execution mode must be auto or sequential');
  let maxConcurrency;
  try { maxConcurrency = positiveLimit(execution.maxConcurrency, 3, 8); } catch (error) { throw new HttpError(error.message); }
  let roleWorkers, maxModelRuns;
  try {
    roleWorkers = positiveLimit(execution.roleWorkers, 1, 4);
    maxModelRuns = positiveLimit(execution.maxModelRuns, 24, 64);
  } catch (error) { throw new HttpError(error.message); }
  const roleWorkerCounts = execution.roleWorkerCounts ?? {};
  if (!roleWorkerCounts || typeof roleWorkerCounts !== 'object' || Array.isArray(roleWorkerCounts) || Object.keys(roleWorkerCounts).some(id => !agentIds.includes(id))) throw new HttpError('Role worker counts must map selected agent IDs to counts');
  for (const count of Object.values(roleWorkerCounts)) {
    try { positiveLimit(count, 1, 4); } catch { throw new HttpError('Role worker counts must be integers from 1 to 4'); }
  }
  if (mode === 'sequential') maxConcurrency = 1;
  const dependencies = execution.dependencies ?? {};
  if (!dependencies || typeof dependencies !== 'object' || Array.isArray(dependencies)) throw new HttpError('Dependencies must map selected agent IDs to prerequisite arrays');
  if (Object.keys(dependencies).some(id => !agentIds.includes(id))) throw new HttpError('Dependencies must name selected agents');
  const nodes = agentIds.map((id, index) => {
    const extra = Object.hasOwn(dependencies, id) ? dependencies[id] : [];
    if (!Array.isArray(extra) || extra.length > agentIds.length || extra.some(dep => typeof dep !== 'string' || !agentIds.includes(dep) || dep === id)) throw new HttpError(`Invalid dependencies for ${id}`);
    const previous = mode === 'sequential' || AGENTS[id].contract.evidenceMode === 'upstream' ? agentIds.slice(0, index) : [];
    return { id, dependsOn: agentIds.filter(dep => previous.includes(dep) || extra.includes(dep)) };
  });
  const visited = new Set(), visiting = new Set(), byId = new Map(nodes.map(node => [node.id, node]));
  function visit(id) {
    if (visiting.has(id)) throw new HttpError('Agent dependencies contain a cycle');
    if (visited.has(id)) return;
    visiting.add(id);
    for (const dependency of byId.get(id).dependsOn) visit(dependency);
    visiting.delete(id); visited.add(id);
  }
  for (const node of nodes) visit(node.id);
  return { mode, maxConcurrency, roleWorkers, roleWorkerCounts: { ...roleWorkerCounts }, maxModelRuns, nodes };
}

/** Each task receives a deterministic snapshot of its successful ancestors, never shared mutable context. */
async function executePlan(plan, run, { signal, continueOnError = false, onSkipped = () => {} } = {}) {
  const states = new Map(plan.nodes.map(node => [node.id, 'pending']));
  const results = new Map(), running = new Map();
  const nodes = new Map(plan.nodes.map(node => [node.id, node]));
  let failed = false;
  const skip = (node, reason) => { states.set(node.id, 'skipped'); onSkipped(node.id, reason); };
  function contexts(node) {
    const ancestors = new Set();
    function collect(id) { if (ancestors.has(id)) return; ancestors.add(id); nodes.get(id).dependsOn.forEach(collect); }
    node.dependsOn.forEach(collect);
    return plan.nodes.filter(item => ancestors.has(item.id)).map(item => results.get(item.id));
  }
  while ([...states.values()].includes('pending') || running.size) {
    const pendingBefore = [...states.values()].filter(state => state === 'pending').length;
    for (const node of plan.nodes) {
      if (states.get(node.id) !== 'pending') continue;
      if (signal?.aborted) { skip(node, 'Cancelled before starting'); continue; }
      if (node.dependsOn.some(id => ['failed', 'skipped'].includes(states.get(id)))) { skip(node, 'A required upstream review did not complete'); continue; }
      if (failed && !continueOnError) { skip(node, 'Stopped after a failed review'); continue; }
      if (running.size >= plan.maxConcurrency || !node.dependsOn.every(id => states.get(id) === 'complete')) continue;
      states.set(node.id, 'running');
      const promise = Promise.resolve().then(() => { checkAbort(signal); return run(node.id, contexts(node)); })
        .then(result => { results.set(node.id, result); states.set(node.id, 'complete'); }, () => { states.set(node.id, 'failed'); failed = true; })
        .finally(() => running.delete(node.id));
      running.set(node.id, promise);
    }
    if (running.size) await Promise.race(running.values());
    else {
      const pendingAfter = [...states.values()].filter(state => state === 'pending').length;
      // Backward edges may need another pass to propagate a failed prerequisite through skipped nodes.
      if (pendingAfter && pendingAfter === pendingBefore) throw new Error('No executable agent remains in the workflow');
    }
  }
  return { status: signal?.aborted ? 'cancelled' : failed ? 'error' : 'complete', states, results };
}

module.exports = { buildPlan, executePlan };
