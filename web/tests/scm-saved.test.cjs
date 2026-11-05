'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.THREATLINT_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-home-'));
const { createWorkbench } = require('../server.js');

describe('Saved Azure DevOps PATs', () => {
  let wb, base;
  let shared = false;
  let nextId = 0;
  const connected = [];
  const disconnected = [];
  const repositoryTokens = [];
  before(async () => {
    const threatlintCli = async args => {
      if (args.join(' ') === 'ado status --json') return { code: 0, stdout: shared ? JSON.stringify({ hasPat: true, source: 'AWS Parameter Store (service account)',
        organizations: [{ name: 'Contoso', source: 'AWS Parameter Store (service account)' }, { name: 'broken', source: 'AWS Parameter Store (service account)' }],
        serviceAccount: { configured: true, parameter: '/team/ado/pat', profile: 'appsec', region: 'us-west-2', organizations: ['Contoso', 'broken'] } })
        : 'Azure DevOps PAT: OS credential store · Contoso\nAzure DevOps PAT: OS credential store · broken\n', stderr: '' };
      if (args[1] === 'token') return args[3] === 'Contoso' ? { code: 0, stdout: (shared ? 's' : 'p').repeat(52), stderr: '' } : { code: 1, stdout: '', stderr: 'ERROR: none' };
      throw new Error(`unexpected ${args.join(' ')}`);
    };
    const scm = { list: () => connected.map(c => ({ id: c.id, provider: 'azure-devops', account: c.organization.toLowerCase(), label: `Azure DevOps · ${c.organization.toLowerCase()}`, host: 'dev.azure.com' })),
      connect: async input => { connected.push({ ...input, id: `id-${nextId++}` }); return {}; },
      disconnect: id => { const index = connected.findIndex(item => item.id === id); if (index >= 0) disconnected.push(...connected.splice(index, 1)); },
      repositories: async id => { repositoryTokens.push(connected.find(item => item.id === id)?.token); return []; } };
    wb = createWorkbench({ storageDir: fs.mkdtempSync(path.join(os.tmpdir(), 'tl-')), integrations: { threatlintCli }, sourceManagers: scm });
    await new Promise(resolve => wb.server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${wb.server.address().port}`;
  });
  after(() => wb.close());

  it('connects each organization with a saved PAT once, and never returns the PAT', async () => {
    const first = await (await fetch(`${base}/api/scm/connections`)).text();
    const second = await (await fetch(`${base}/api/scm/connections`)).json();
    assert.deepEqual(connected.map(c => [c.provider, c.organization]), [['azure-devops', 'Contoso']], 'connected once; a failing PAT is not retried on this pass');
    assert.ok(!first.includes('p'.repeat(20)), 'the PAT is never in a response');
    // The working org is live; the org whose PAT failed stays visible as not-connected rather than disappearing.
    const contoso = second.find(c => c.account === 'contoso');
    const broken = second.find(c => c.account === 'broken');
    assert.ok(contoso && contoso.connected === true, 'the connected org is live');
    assert.ok(broken && broken.connected === false, 'a saved org whose PAT fails is still listed, marked not connected');
    assert.equal(broken.source, 'Saved PAT');
    assert.equal(broken.reason, 'saved PAT could not be read', 'the failure reason is a fixed phrase, never CLI or provider text');
    assert.equal(second.length, 2);
  });

  it('replaces cached personal sessions when the Parameter Store service account becomes authoritative', async () => {
    const previousId = connected[0].id;
    shared = true;
    assert.equal((await fetch(`${base}/api/scm/connections/${previousId}/repositories`)).status, 409);
    assert.deepEqual(repositoryTokens, [], 'a stale selection never accesses a repository with the personal PAT');
    const response = await (await fetch(`${base}/api/scm/connections`)).json();
    const currentId = response.find(item => item.account === 'contoso').id;
    assert.equal((await fetch(`${base}/api/scm/connections/${currentId}/repositories`)).status, 200);
    assert.deepEqual(repositoryTokens, ['s'.repeat(52)]);
    assert.equal(disconnected.length, 1);
    assert.equal(disconnected[0].token, 'p'.repeat(52));
    assert.equal(connected.length, 1);
    assert.equal(connected[0].token, 's'.repeat(52));
    assert.equal(response.find(item => item.account === 'contoso').source, 'AWS Parameter Store (service account)');
    assert.equal(response.find(item => item.account === 'broken').reason, 'service-account PAT could not be read');
    assert.ok(!JSON.stringify(response).includes('s'.repeat(20)));
    await fetch(`${base}/api/scm/connections`);
    assert.equal(disconnected.length, 1, 'a current service-account connection is reused');
    const manual = await fetch(`${base}/api/scm/connections`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'azure-devops', organization: 'Contoso', token: 'q'.repeat(52) }) });
    assert.equal(manual.status, 400);
    assert.equal(connected.length, 1, 'a personal PAT cannot replace the shared source');
  });
});
