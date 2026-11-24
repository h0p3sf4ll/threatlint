'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

/** Only app-created AVIT temp roots can enter this durable retry queue. Never follow arbitrary stored paths. */
function createTempCleanup({ directory, remove = fs.promises.rm, tempRoot = os.tmpdir() } = {}) {
  const file = directory && path.join(directory, 'pending-avit-cleanup.json');
  const allowed = value => typeof value === 'string' && path.dirname(path.resolve(value)) === path.resolve(tempRoot)
    && /^threatlint-avit-[A-Za-z0-9]+$/.test(path.basename(value));
  const pending = new Set();
  try {
    if (file && fs.statSync(file).size <= 16 * 1024 * 1024) {
      const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (Array.isArray(saved)) for (const value of saved) if (allowed(value)) pending.add(value);
    }
  } catch { /* A new profile has no retry queue. */ }
  function persist() {
    if (!file) return false;
    try {
      fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
      const temporary = `${file}.${process.pid}.tmp`;
      fs.writeFileSync(temporary, JSON.stringify([...pending]), { mode: 0o600 }); fs.renameSync(temporary, file);
      return true;
    } catch { return false; }
  }
  async function cleanup(value) {
    if (!allowed(value)) return { removed: false, scheduled: false };
    try {
      // Node handles read-only Git objects on Windows; retry transient antivirus/indexer locks too.
      await remove(value, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
      if (pending.delete(value)) persist();
      return { removed: true, scheduled: false };
    } catch {
      if (!pending.has(value) && pending.size >= 10000) return { removed: false, scheduled: false };
      pending.add(value);
      return { removed: false, scheduled: persist() };
    }
  }
  let retrying = null;
  function retry() {
    if (retrying) return retrying;
    retrying = (async () => { for (const value of [...pending].slice(0, 5)) await cleanup(value); })().finally(() => { retrying = null; });
    return retrying;
  }
  return { cleanup, retry };
}
module.exports = { createTempCleanup };
