'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.THREATLINT_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-home-'));
const { createWorkbench } = require('../server.js');

describe('Sidekick routes', () => {
  let wb, base;
  const calls = [];
  before(async () => {
    const sidekickCli = async (args, input, onLine) => {
      calls.push({ args, input });
      if (onLine) { onLine({ type: 'progress', current: 1, total: 2 }); onLine({ type: 'log', message: 'api: 3 branches' }); }
      if (args[0] === 'loadouts') return { code: 0, json: { loadouts: { 'Team A': [] }, powered: {} } };
      if (args[0] === 'loadout-save') return { code: 0, json: { name: args[1], entries: 1, warnings: [], added: 1, removed: 0 } };
      if (args[0] === 'report') return { code: 0, json: { runId: 'a'.repeat(32), rows: 2, failed: 0 } };
      if (args[0] === 'avit-close') return { code: 1, error: 'A closure reason is required' };
      return { code: 0, json: {} };
    };
    wb = createWorkbench({ storageDir: fs.mkdtempSync(path.join(os.tmpdir(), 'tl-')), integrations: { sidekickCli } });
    await new Promise(resolve => wb.server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${wb.server.address().port}`;
  });
  after(() => wb.close());
  const post = (url, body) => fetch(base + url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

  it('saves a loadout from text on stdin and rejects bad names', async () => {
    const ok = await post('/api/sidekick/loadouts', { name: 'Team A', text: 'api, Platform' });
    assert.equal(ok.status, 200);
    assert.deepEqual(calls.at(-1), { args: ['loadout-save', 'Team A'], input: 'api, Platform' });
    assert.equal((await post('/api/sidekick/loadouts', { name: 'x;rm', text: '' })).status, 400);
  });

  it('runs a vReport as a job and reports progress and the result', async () => {
    const { jobId } = await (await post('/api/sidekick/jobs', { kind: 'report', loadout: 'Team A', staleDays: 30 })).json();
    let job;
    for (let i = 0; i < 20; i++) { job = await (await fetch(`${base}/api/sidekick/jobs/${jobId}`)).json(); if (job.state !== 'running') break; await new Promise(r => setTimeout(r, 20)); }
    assert.equal(job.state, 'done'); assert.equal(job.result.rows, 2); assert.deepEqual(job.progress, { type: 'progress', current: 1, total: 2 });
    const args = calls.find(c => c.args[0] === 'report').args;
    assert.deepEqual(args.slice(0, 6), ['report', 'Team A', '--stale-days', '30', '--workers', '10']);
    assert.equal(args[6], '--cancel-file', 'jobs pass a portable cancel file');
  });

  it('validates closure requests before the CLI sees them', async () => {
    assert.equal((await post('/api/sidekick/jobs', { kind: 'avit-close', reason: '', conditions: [] })).status, 400);
    assert.equal((await post('/api/sidekick/jobs', { kind: 'avit-close', reason: 'cleanup', records: [{ sysId: 'not-an-id' }] })).status, 400);
    assert.equal((await post('/api/sidekick/jobs', { kind: 'nope' })).status, 400);
  });
});
