'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { createAwsSso, openPrivate, validateStart, signedSsmRequest } = require('../lib/aws-sso.cjs');

const json = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
const START = { startUrl: 'https://pep.awsapps.com/start/', region: 'eu-central-1' };

function fakeAws(calls, { pending = 1, readable = ['111122223333'] } = {}) {
  let polls = 0;
  return async (url, options = {}) => {
    calls.push({ url, options });
    if (url.endsWith('/client/register')) return json({ clientId: 'cid', clientSecret: 'csecret' });
    if (url.endsWith('/device_authorization')) return json({ deviceCode: 'dev', userCode: 'ABCD-EFGH', verificationUriComplete: 'https://pep.awsapps.com/start/#/device?user_code=ABCD-EFGH', interval: 1, expiresIn: 600 });
    if (url.endsWith('/token')) return polls++ < pending ? json({ error: 'authorization_pending' }, 400) : json({ accessToken: 'sso-token' });
    if (url.includes('/assignment/accounts')) return json({ accountList: [{ accountId: '999988887777', accountName: 'Other' }, { accountId: '111122223333', accountName: 'AppSec' }] });
    if (url.includes('/assignment/roles')) return json({ roleList: [{ roleName: 'ReadOnly' }] });
    if (url.includes('/federation/credentials')) {
      const account = new URL(url).searchParams.get('account_id');
      return json({ roleCredentials: { accessKeyId: `AKIA${account}`, secretAccessKey: 'secret', sessionToken: 'session' } });
    }
    if (url.startsWith('https://ssm.us-west-2.amazonaws.com/')) {
      const account = /Credential=AKIA(\d+)\//.exec(options.headers.Authorization)[1];
      if (!readable.includes(account)) return json({ __type: 'com.amazon.coral.service#AccessDeniedException' }, 400);
      const names = JSON.parse(options.body).Names;
      return json({ Parameters: names.map(Name => ({ Name, Value: `value:${Name}` })) });
    }
    throw new Error(`unexpected ${url}`);
  };
}

describe('AWS SSO sign-in without the AWS CLI', () => {
  it('opens the device verification page privately, then finds a role that can read the keys', async () => {
    const calls = [], opened = [];
    const sso = createAwsSso({ fetchImpl: fakeAws(calls), openBrowser: async url => { opened.push(url); return { browser: 'Google Chrome', usedDefault: true }; } });
    const login = await sso.start(START);
    assert.equal(login.userCode, 'ABCD-EFGH');
    assert.deepEqual(opened, ['https://pep.awsapps.com/start/#/device?user_code=ABCD-EFGH']);
    assert.match(calls[1].options.body, /"startUrl":"https:\/\/pep\.awsapps\.com\/start"/);
    assert.ok(calls.every(call => call.url.startsWith('https://oidc.eu-central-1.amazonaws.com/') && call.options.redirect === 'error'));
    assert.deepEqual(await sso.poll(login.loginId), { status: 'pending', interval: 1 });
    const signedIn = await sso.poll(login.loginId);
    assert.equal(signedIn.roles.length, 2);
    const values = await sso.values(login.loginId);
    assert.equal(values.account, 'AppSec / ReadOnly');
    assert.equal(values.clientSecret, 'value:/cfc-appsec-snow-vulnerabilities-prod/client-secret');
    assert.equal(values.semgrepToken, 'value:/cfc-appsec-semgrep-scan/semgrep-token');
    await assert.rejects(sso.values(login.loginId), /expired/, 'a sign-in is single use');
  });
  it('explains when no role can read the ServiceNow keys', async () => {
    const sso = createAwsSso({ fetchImpl: fakeAws([], { pending: 0, readable: [] }), openBrowser: async () => ({ browser: 'Chrome', usedDefault: true }) });
    const login = await sso.start(START);
    await sso.poll(login.loginId);
    await assert.rejects(sso.values(login.loginId), error => error.status === 403 && /AccessDeniedException/.test(error.message));
  });
  it('still returns the code and link when no private window can be opened', async () => {
    const sso = createAwsSso({ fetchImpl: fakeAws([]), openBrowser: async () => { throw new Error('No browser'); } });
    const login = await sso.start(START);
    assert.equal(login.openError, 'No browser'); assert.match(login.verificationUrl, /user_code=ABCD-EFGH/);
  });
  it('accepts only AWS access portal URLs and real regions', () => {
    assert.deepEqual(validateStart(START), { startUrl: 'https://pep.awsapps.com/start', region: 'eu-central-1' });
    assert.throws(() => validateStart({ startUrl: 'https://attacker.example/start', region: 'us-east-1' }), /awsapps/);
    assert.throws(() => validateStart({ startUrl: 'http://pep.awsapps.com/start', region: 'us-east-1' }), /awsapps/);
    assert.throws(() => validateStart({ startUrl: START.startUrl, region: 'us-east-1/../x' }), /region/);
  });
});

describe('Private browser window', () => {
  const available = async () => true;
  it('uses the default browser private mode when it has one', async () => {
    const launched = [];
    const result = await openPrivate('https://x.awsapps.com/start', { detect: async () => (process.platform === 'win32' ? 'MSEdgeHTM' : process.platform === 'darwin' ? 'com.microsoft.edgemac' : 'microsoft-edge.desktop'),
      available, launcher: async (browser, url) => launched.push([browser.name, browser.flag, url]) });
    assert.deepEqual(result, { browser: 'Microsoft Edge', usedDefault: true });
    assert.deepEqual(launched, [['Microsoft Edge', '--inprivate', 'https://x.awsapps.com/start']]);
  });
  it('falls back to an installed browser with private mode when the default has none', async () => {
    const launched = [];
    const result = await openPrivate('https://x', { detect: async () => 'company.thebrowser.dia', available: async browser => browser.name !== 'Google Chrome',
      launcher: async browser => launched.push(browser.flag) });
    assert.deepEqual(result, { browser: 'Microsoft Edge', usedDefault: false });
    assert.deepEqual(launched, ['--inprivate']);
  });
});

describe('Parameter Store request signing', () => {
  it('signs GetParameters with SigV4 for us-west-2 SSM', () => {
    const request = signedSsmRequest({ accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', sessionToken: 'token' },
      'GetParameters', '{"Names":["a"],"WithDecryption":true}', new Date('2026-10-21T12:00:00Z'));
    assert.equal(request.url, 'https://ssm.us-west-2.amazonaws.com/');
    assert.equal(request.headers['x-amz-target'], 'AmazonSSM.GetParameters');
    assert.equal(request.headers['x-amz-date'], '20261021T120000Z');
    assert.match(request.headers.Authorization, /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20261021\/us-west-2\/ssm\/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=[0-9a-f]{64}$/);
  });
});
