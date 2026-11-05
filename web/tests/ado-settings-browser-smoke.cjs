'use strict';

/** ADO settings with synthetic CLI responses; no AWS or Azure DevOps calls. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-ado-ui-'));
process.env.THREATLINT_HOME = path.join(temporary, 'home');
for (const name of ['THREATLINT_GITHUB_APP_ID', 'THREATLINT_GITHUB_APP_INSTALLATION_ID', 'THREATLINT_GITHUB_APP_PRIVATE_KEY_FILE']) delete process.env[name];
const { createWorkbench } = require('../server.js');

(async () => {
  let configured = false;
  const calls = [];
  const shared = { configured: true, parameter: '/team/ado/pat', profile: 'appsec', region: 'us-west-2', organizations: ['Contoso', 'Fabrikam'] };
  const wb = createWorkbench({ storageDir: path.join(temporary, 'history'), integrations: {
    credentialSources: async () => ({}), semgrepVersion: async () => 'synthetic',
    threatlintCli: async args => {
      calls.push(args);
      if (args[0] === 'ado' && args[1] === 'service-account') { configured = true; return { code: 0, stdout: 'Configured', stderr: '' }; }
      if (args[0] === 'ado' && args[1] === 'status') return { code: 0, stdout: JSON.stringify({ hasPat: true,
        source: configured ? 'AWS Parameter Store (service account)' : 'OS credential store',
        organizations: [{ name: 'Contoso', source: configured ? 'AWS Parameter Store (service account)' : 'OS credential store' }],
        serviceAccount: configured ? shared : {} }), stderr: '' };
      return { code: 0, stdout: '[]', stderr: '' };
    },
  } });
  let browser;
  try {
    await new Promise(resolve => wb.server.listen(0, '127.0.0.1', resolve));
    browser = await chromium.launch({ headless: true, ...(process.env.THREATLINT_BROWSER_EXECUTABLE ? { executablePath: process.env.THREATLINT_BROWSER_EXECUTABLE } : {}) });
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(`http://127.0.0.1:${wb.server.address().port}/#settings`);
    await page.locator('#ado-auth-mode').selectOption('service-account');
    await page.locator('#ado-pat-parameter').fill(shared.parameter);
    await page.locator('#ado-service-organizations').fill('Contoso, Fabrikam');
    await page.locator('#ado-aws-profile').fill(shared.profile);
    await page.locator('#ado-aws-region').fill(shared.region);
    assert.equal(await page.locator('#ado-pat').isVisible(), false);
    await page.locator('#ado-save').click();
    await page.locator('#ado-status', { hasText: 'personal PATs are not used' }).waitFor();
    assert.equal(await page.locator('#ado-error').innerText(), '');
    assert.equal(await page.locator('#ado-pat').inputValue(), '');
    assert.equal(await page.locator('#ado-auth-mode option[value=personal]').isDisabled(), true);
    assert.equal(await page.locator('#ado-organizations button').count(), 0, 'shared organizations have no local-PAT Remove button');
    assert.deepEqual(calls.find(args => args[1] === 'service-account'), ['ado', 'service-account', '--parameter', shared.parameter,
      '--organization', 'Contoso', '--organization', 'Fabrikam', '--aws-profile', shared.profile, '--region', shared.region]);
    await page.reload();
    await page.locator('#ado-status', { hasText: 'personal PATs are not used' }).waitFor();
    assert.equal(await page.locator('#ado-pat-parameter').inputValue(), shared.parameter);
    assert.equal(await page.locator('#ado-pat').isVisible(), false);
    assert.deepEqual(errors, []);
    console.log('PASS: ADO service-account settings save metadata, hide personal PATs, and restore the configured source.');
  } finally {
    if (browser) await browser.close();
    await wb.close();
    fs.rmSync(temporary, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
