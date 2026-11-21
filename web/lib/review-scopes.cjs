'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { AGENTS } = require('./agents.cjs');
const { HttpError } = require('./http.cjs');

const SKIP = new Set(['.git', 'node_modules', '.venv', '__pycache__', 'release']);
const MAX_FILES = 2000, MAX_PATH_CHARACTERS = 64_000, MAX_ENTRIES = 20_000;

/** Stable, bounded working-tree inventory. Symlinks and generated dependency directories are excluded. */
function inventorySource(repoPath) {
  const files = [], limitations = [];
  let entries = 0, characters = 0, stopped = false;
  function walk(relative) {
    let children;
    try { children = fs.readdirSync(path.join(repoPath, relative), { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : Number(a.name > b.name)); }
    catch { limitations.push(`Unreadable directory: ${relative || '.'}`); return; }
    for (const entry of children) {
      if (stopped) break;
      if (++entries > MAX_ENTRIES) { stopped = true; break; }
      if (entry.isSymbolicLink()) continue;
      const file = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory() && !SKIP.has(entry.name)) walk(file);
      else if (entry.isFile()) {
        if (files.length >= MAX_FILES || characters + file.length > MAX_PATH_CHARACTERS) { stopped = true; break; }
        files.push(file); characters += file.length;
      }
    }
  }
  walk('');
  if (stopped) limitations.push(`Inventory limit reached (${MAX_FILES} files, ${MAX_PATH_CHARACTERS} path characters, ${MAX_ENTRIES} directory entries); omitted files were not assigned or reviewed.`);
  limitations.push('Inventory excludes symlinks, .git, node_modules, .venv, __pycache__, and release. File assignment is not proof of inspection; source may change during the run.');
  return { files, truncated: stopped, limitations, digest: crypto.createHash('sha256').update(JSON.stringify(files)).digest('hex') };
}

/** Partition primary ownership exactly once; any worker may read other files only as supporting context. */
function partitionFiles(files, requested) {
  const count = Math.min(requested, Math.max(1, Math.floor(files.length / 2)));
  return Array.from({ length: count }, (_, index) => ({
    id: `scope-${index + 1}`,
    files: files.slice(Math.floor(index * files.length / count), Math.floor((index + 1) * files.length / count)),
  }));
}

function prepareScopes(plan, repoPath, participantCount = 1, ensemble = false) {
  const advanced = ensemble || plan.roleWorkers > 1 || Object.values(plan.roleWorkerCounts).some(count => count > 1);
  const inventory = advanced ? inventorySource(repoPath) : null;
  const byAgent = new Map();
  let plannedModelRuns = 0;
  for (const node of plan.nodes) {
    const requested = plan.roleWorkerCounts[node.id] ?? plan.roleWorkers;
    // Capture-oriented and upstream reviews cannot safely be split by source-file ownership.
    const partitionable = AGENTS[node.id].contract.evidenceMode === 'source' && node.id !== 'appsec-runtime-reviewer';
    const scopes = inventory && partitionable ? partitionFiles(inventory.files, requested) : [{ id: 'scope-1', files: null }];
    const structured = ensemble || scopes.length > 1;
    const reason = requested > 1 && !partitionable ? 'This role consumes shared evidence; source-file partitioning would duplicate or fragment its review.'
      : requested > scopes.length ? 'Worker count reduced: each source partition needs at least two primary files.' : null;
    byAgent.set(node.id, { scopes, requested, structured, reason });
    plannedModelRuns += structured ? scopes.length * participantCount + (ensemble ? participantCount : 0) : 1;
  }
  if (plannedModelRuns > plan.maxModelRuns) throw new HttpError(`This plan needs ${plannedModelRuns} model runs; the limit is ${plan.maxModelRuns}. Reduce agents/workers/providers or explicitly raise maxModelRuns (maximum 64).`);
  return { inventory, byAgent, plannedModelRuns };
}

module.exports = { inventorySource, partitionFiles, prepareScopes };
