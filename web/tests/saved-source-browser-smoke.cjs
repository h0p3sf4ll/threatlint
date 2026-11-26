'use strict';

// Real Settings/Workbench UI and encrypted registry, synthetic provider accounts only.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-saved-sources-'));
process.env.THREATLINT_HOME = path.join(directory, 'config');
process.env.THREATLINT_STATE_DIR = path.join(directory, 'default-state');
for (const key of Object.keys(process.env)) if (/^THREATLINT_GITHUB_APP_/.test(key)) delete process.env[key];
const { createWorkbench } = require('../server.js');

(async () => {
  const live = [{ id: 'legacy', provider: 'azure-devops', account: 'acmeit2', host: 'dev.azure.com' }];
  const savedAzureOrgs = [{ name: 'acmeit', source: 'file' }];
  let attempts = 0, rejectSaved = false;
  const wb = createWorkbench({ storageDir: path.join(directory, 'state'),
    integrations: { threatlintCli: async args => args[1] === 'status'
      ? { code: 0, stdout: JSON.stringify({ organizations: savedAzureOrgs }) }
      : { code: 1, stdout: '' } },
    sourceManagers: {
      list: () => live.slice(),
      connect: async input => {
        if (input.organization === 'acmeit2') {
          assert.deepEqual(input, { provider: 'azure-devops', organization: 'acmeit2', token: 'synthetic-session-pat' });
          const value = { id: 'legacy', provider: input.provider, account: input.organization, host: 'dev.azure.com' };
          live.push(value); return value;
        }
        attempts++;
        if (rejectSaved) throw new Error('Synthetic rejected credential');
        assert.equal(input.organization, 'AcmeIT');
        assert.equal(input.token, 'synthetic-saved-pat');
        const value = { id: `named-${attempts}`, provider: input.provider, account: input.organization.toLowerCase(), host: 'dev.azure.com' };
        live.push(value); return value;
      },
      disconnect: id => { const index = live.findIndex(item => item.id === id); if (index >= 0) live.splice(index, 1); return index >= 0; },
      repositories: async id => ({ repositories: [{ id: 'fixture-repository', name: id === 'legacy' ? 'other-account' : 'saved-account', fullName: `${live.find(item => item.id === id)?.account}/project/repository`, defaultBranch: 'main' }], page: 1, hasMore: false }),
    },
  });
  let browser;
  try {
    await new Promise(resolve => wb.server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${wb.server.address().port}`;
    browser = await chromium.launch({ headless: true, ...(process.env.THREATLINT_BROWSER_EXECUTABLE ? { executablePath: process.env.THREATLINT_BROWSER_EXECUTABLE } : {}) });
    const page = await browser.newPage(); const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', route => new URL(route.request().url()).origin === base ? route.continue() : route.abort());
    const openSources = async () => {
      await page.goto(base); await page.locator('#connection-status.online').waitFor();
      await page.evaluate(() => document.dispatchEvent(new CustomEvent('threatlint:navigate', { detail: { view: 'sources' } })));
    };
    const form = page.locator('#scm-connection-form'), add = page.locator('#scm-add-connection');
    const provider = page.locator('#scm-provider'), org = page.locator('#scm-organization'), token = page.locator('#scm-token');
    const expectCollapsed = async () => {
      await token.waitFor({ state: 'hidden' });
      assert.equal(await org.isVisible(), false);
      assert.equal(await token.isDisabled(), true);
      assert.equal(await token.inputValue(), '');
    };

    const response = await fetch(`${base}/api/management/connections`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'azure-devops', kind: 'scm', name: 'ADO-AcmeIT', organization: 'AcmeIT', token: 'synthetic-saved-pat', isDefault: true }) });
    assert.equal(response.status, 200);
    const record = await response.json();
    assert.equal(JSON.stringify(record).includes('synthetic-saved-pat'), false);
    await openSources();
    await page.locator('#scm-repositories', { hasText: 'saved-account' }).waitFor();
    assert.match(await page.locator('#scm-connections .selected').innerText(), /ADO-AcmeIT/);
    assert.equal(await page.locator('#scm-connections .saved').count(), 0, 'working named source replaces the stale CLI placeholder');
    await expectCollapsed();
    await page.locator('#scm-refresh-connections').click();
    await page.waitForFunction(() => !document.querySelector('#scm-refresh-connections').disabled);
    assert.equal(attempts, 1, 'refresh reuses the saved account');

    await add.click();
    await provider.selectOption('azure-devops');
    await org.fill('another-org');
    await token.fill('synthetic-discarded-pat');
    await add.click();
    await expectCollapsed();
    await add.click();
    await token.fill('synthetic-unsubmitted-pat');
    await page.locator('#scm-connections .scm-connection-select', { hasText: 'acmeit2' }).click();
    await page.locator('#scm-repositories', { hasText: 'other-account' }).waitFor();
    await expectCollapsed();
    await page.locator('[data-view="settings"]').click();
    await page.locator('.settings-nav [data-settings-category="integrations"]').click();
    await page.locator('.management-connection', { hasText: 'ADO-AcmeIT' }).getByRole('button', { name: 'Use in Connect source' }).click();
    await page.locator('#scm-repositories', { hasText: 'saved-account' }).waitFor();
    assert.match(await page.locator('#scm-connections .selected').innerText(), /ADO-AcmeIT/);

    // Provider rejection stays visible and retries the saved record, without asking for a browser token.
    live.splice(1); rejectSaved = true;
    await page.locator('#scm-refresh-connections').click();
    await page.locator('#scm-connections .saved', { hasText: 'ADO-AcmeIT' }).waitFor();
    assert.match(await page.locator('#scm-connections .saved').innerText(), /Settings/);
    rejectSaved = false;
    await page.locator('#scm-connections .saved').getByRole('button', { name: /Reconnect/ }).click();
    await page.waitForFunction(() => !document.querySelector('#scm-connections .saved'));
    assert.equal(await page.locator('#scm-token').inputValue(), '');

    // GitHub App configuration is available directly under Integrations, and adding an App needs no PAT.
    await page.locator('#scm-github-app-settings').click();
    await page.locator('#github-form').waitFor({ state: 'visible' });
    await page.locator('#management-add-connection').click();
    await page.locator('#management-connection-provider').selectOption('github-app');
    assert.equal(await page.locator('#management-connection-token').isVisible(), false);
    assert.equal(await page.locator('#management-connection-name').evaluate(input => input.required), false);
    await page.locator('#management-save-connection').click();
    await page.locator('#management-connection-dialog').waitFor({ state: 'hidden' });
    await page.locator('#github-form').waitFor({ state: 'visible' });
    // Issue Management uses the full Metrics filter vocabulary and preserves loaded records after failure.
    const requests = []; let failAvits = false;
    await page.route('**/api/trackers/servicenow-avit/items', route => {
      const body = route.request().postDataJSON(); requests.push(body);
      return route.fulfill({ status: failAvits ? 504 : 200, contentType: 'application/json', body: JSON.stringify(failAvits
        ? { error: 'Synthetic ServiceNow timeout' }
        : { items: [{ id: body.offset ? 'avit-b' : 'avit-a', number: body.offset ? 'AVIT0000002' : 'AVIT0000001',
          title: 'Synthetic AVIT', organization: 'acme', repository: 'application', state: 'Open', riskRating: 'Critical', url: 'https://fixture.service-now.com/avit' }],
          filters: body.filters, nextOffset: body.offset ? null : 100 }) });
    });
    await page.evaluate(() => document.dispatchEvent(new CustomEvent('threatlint:navigate', { detail: { view: 'management' } })));
    const filterForm = page.locator('#management-avit-form');
    const names = form => form.evaluate(element => [...element.querySelectorAll('[name]')].map(input => input.name).sort());
    assert.deepEqual(await names(filterForm), await names(page.locator('#avit-aggregate-form')));
    await filterForm.locator('[name=scm]').selectOption('ado');
    await filterForm.locator('[name=organization]').fill('acme');
    await filterForm.locator('[name=project]').fill('project');
    await filterForm.locator('[name=findingType]').selectOption('secrets');
    await filterForm.locator('[name=riskRating]').selectOption('1');
    await filterForm.locator('[name=state]').selectOption('1');
    await filterForm.getByRole('button', { name: 'Load AVITs', exact: true }).click();
    await page.locator('#management-avits', { hasText: 'AVIT0000001' }).waitFor();
    assert.deepEqual(requests[0], { filters: { scm: 'ado', organization: 'acme', project: 'project', findingType: 'secrets', riskRating: '1', state: '1' }, offset: 0 });
    await page.locator('#management-avits-more').click();
    await page.locator('#management-avits', { hasText: 'AVIT0000002' }).waitFor();
    assert.equal(requests[1].offset, 100);
    assert.equal(await page.locator('#management-avits .management-finding').count(), 2);
    failAvits = true;
    await filterForm.getByRole('button', { name: 'Load AVITs', exact: true }).click();
    await page.locator('#management-avit-error', { hasText: 'Previously loaded AVITs remain visible' }).waitFor();
    assert.equal(await page.locator('#management-avits .management-finding').count(), 2);
    await filterForm.locator('[name=scm]').selectOption('github');
    assert.equal(await filterForm.locator('[name=project]').inputValue(), '');
    // A fresh Workbench visit with no saved or live sources opens the manual form.
    const removed = await fetch(`${base}/api/management/connections/${record.connection.id}`, { method: 'DELETE' });
    assert.equal(removed.status, 200);
    savedAzureOrgs.length = 0;
    live.length = 0;
    await openSources();
    await token.waitFor({ state: 'visible' });
    assert.equal(await form.evaluate(node => Boolean(document.querySelector('#scm-connections').compareDocumentPosition(node) & Node.DOCUMENT_POSITION_FOLLOWING)), true);
    assert.equal(await org.isVisible(), false, 'GitHub only needs the token');
    await provider.selectOption('azure-devops');
    await org.fill('acmeit2');
    await token.fill('synthetic-session-pat');
    await page.locator('#scm-connect').click();
    await page.locator('#scm-repositories', { hasText: 'other-account' }).waitFor();
    await expectCollapsed();

    assert.deepEqual(errors, []);
    console.log('PASS: manual source entry and cancellation, connected-source selection, saved Azure auto-connect and retry, GitHub App settings, and paginated AVIT filters.');
  } finally {
    await browser?.close(); await wb.close(); fs.rmSync(directory, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
