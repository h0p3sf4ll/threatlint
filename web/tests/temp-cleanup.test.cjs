'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createTempCleanup } = require('../lib/temp-cleanup.cjs');
const { createAvitBatch } = require('../lib/avit-batch.cjs');

test('locked AVIT roots are durably retried without deleting unrelated paths', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cleanup-queue-'));
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-avit-'));
  t.after(() => { fs.rmSync(directory, { recursive: true, force: true }); fs.rmSync(work, { recursive: true, force: true }); });
  const locked = createTempCleanup({ directory, remove: async (_value, options) => { assert.equal(options.maxRetries, 5); throw Object.assign(new Error('locked'), { code: 'EPERM' }); } });
  assert.deepEqual(await locked.cleanup(work), { removed: false, scheduled: true });
  const manifest = path.join(directory, 'pending-avit-cleanup.json');
  assert.deepEqual(JSON.parse(fs.readFileSync(manifest)), [work]);
  fs.writeFileSync(manifest, JSON.stringify([work, directory, path.join(os.tmpdir(), 'threatlint-avit-../../unsafe')]));
  await createTempCleanup({ directory }).retry();
  assert.equal(fs.existsSync(work), false); assert.equal(fs.existsSync(directory), true);
  assert.deepEqual(JSON.parse(fs.readFileSync(manifest)), []);
});

test('EPERM during failed clone cleanup does not stop the next two AVITs', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'avit-batch-cleanup-test-'));
  let lockedRoot;
  const ids = ['AVIT000000000000011', 'AVIT000000000000012', 'AVIT000000000000013'];
  const fetched = [], events = [];
  t.after(() => { fs.rmSync(directory, { recursive: true, force: true }); if (lockedRoot) fs.rmSync(lockedRoot, { recursive: true, force: true }); });
  const batch = createAvitBatch({ store: { directory, sessions: new Map() }, reports: {}, integrations: {
    semgrepVersion: async () => 'synthetic',
    removeAvitTemporaryDirectory: async (value, options) => { if (value === lockedRoot) throw Object.assign(new Error('Windows lock'), { code: 'EPERM' }); await fs.promises.rm(value, options); },
    threatlintCli: async args => {
      if (args[0] === 'setup') return { code: 0, stdout: '[]', stderr: '' };
      if (args[1] === 'fetch') {
        fetched.push(args[2]);
        const output = args[args.indexOf('-o') + 1];
        if (args[2] === ids[0]) { lockedRoot = path.dirname(output); fs.writeFileSync(output, 'Synthetic AVIT evidence'); return { code: 0 }; }
        return { code: 1, stderr: 'ERROR: Synthetic AVIT fixture unavailable' };
      }
      if (args[1] === 'checkout') return { code: 1, stderr: 'ERROR: Git could not materialize the working tree' };
      throw new Error('Unexpected fixture command');
    },
  } });
  await batch.run({ avits: ids.join(' '), provider: 'lmstudio', model: 'fixture', servicenow: { instance: 'https://example.service-now.com' } }, event => events.push(event), new AbortController());
  assert.deepEqual(fetched, ids);
  assert.equal(events.filter(e => e.type === 'avit_item' && e.done).length, 3);
  assert.equal(events.at(-1).type, 'avit_batch_complete');
  assert.ok(events.some(e => e.action === 'cleanup-warning' && e.avit === ids[0]));
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(directory, 'pending-avit-cleanup.json'))), [lockedRoot]);
  await createTempCleanup({ directory }).retry(); assert.equal(fs.existsSync(lockedRoot), false);
});
