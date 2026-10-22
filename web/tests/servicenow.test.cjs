'use strict';
// Never read the developer's saved ~/.threatlint config.
process.env.THREATLINT_HOME = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'threatlint-home-'));
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { parseAvitNumbers, validateInstanceUrl, validateCredentials, fetchAvits, avitsMarkdown, loadAvitAttachment } = require('../lib/servicenow.cjs');

const INSTANCE = 'https://example.service-now.com';
const json = body => ({ ok: true, status: 200, json: async () => body });

describe('AVIT numbers and instance URLs', () => {
  it('normalizes, de-duplicates, and bounds AVIT lists', () => {
    assert.deepEqual(parseAvitNumbers('avit000000000001234, AVIT000000000001235\nAVIT000000000001234'), ['AVIT000000000001234', 'AVIT000000000001235']);
    assert.throws(() => parseAvitNumbers('AVIT12'), /Not an AVIT/);
    assert.throws(() => parseAvitNumbers('AVIT0012345'), /15 digits/, 'short forms are not the AVIT format');
    assert.deepEqual(parseAvitNumbers('AVIT000000095938462'), ['AVIT000000095938462'], 'production AVITs have 15 digits');
    assert.throws(() => parseAvitNumbers('AVIT0000000959384621'), /Not an AVIT/);
    assert.throws(() => parseAvitNumbers(''), /at least one/);
    assert.throws(() => parseAvitNumbers(Array.from({ length: 51 }, (_, i) => `AVIT${String(i).padStart(15, '0')}`)), /at most 50/);
  });
  it('accepts only HTTPS ServiceNow origins because the client secret is sent there', () => {
    assert.equal(validateInstanceUrl('https://Example.service-now.com/'), INSTANCE);
    for (const bad of ['http://example.service-now.com', 'https://user:pw@example.service-now.com', 'https://example.service-now.com/login', 'https://service-now.com.attacker.example', 'https://attacker.example']) {
      assert.throws(() => validateInstanceUrl(bad), /ServiceNow/);
    }
  });
  it('requires both client credentials and explains where to find them', () => {
    assert.throws(() => validateCredentials({ instance: INSTANCE, clientId: 'id' }), /Parameter Store/);
  });
});

describe('AVIT retrieval', () => {
  it('uses client credentials, follows same-instance references only, and keeps request order', async () => {
    const calls = [];
    const fetchImpl = async (url, options) => {
      calls.push({ url, options });
      if (url.endsWith('/oauth_token.do')) return json({ access_token: 'token' });
      if (url.includes('/sysrule_view')) return json({ result: [{ condition: 'u_scm_toolISNOTEMPTY' }] });
      if (url.includes('u_scm_toolISNOTEMPTY')) return json({ result: ['AVIT000000000000001', 'AVIT000000000000002', 'AVIT000000000000003'].map(number => ({ number })) });
      if (url.includes('/api/now/table/sn_vul_app_vulnerable_item')) return json({ result: [
        { number: { display_value: 'AVIT000000000000002' }, u_security_finding_source: { display_value: 'SCA' }, sys_mod_count: { value: '4' }, description: { display_value: 'line one\nline two' } },
        { number: { display_value: 'AVIT000000000000005' }, u_security_finding_source: { display_value: 'SAST' } },
        { number: { display_value: 'AVIT000000000000001' }, vulnerability: { display_value: 'SSRF rule', link: `${INSTANCE}/api/now/table/sn_vul_app_vulnerability_entry/abc` } },
        { number: { display_value: 'AVIT000000000000003' }, scanner: { display_value: 'Semgrep' }, vulnerability: { display_value: 'x', link: 'https://attacker.example/api/now/table/x/1' } },
      ] });
      if (url.includes('sn_vul_app_vulnerability_entry/abc')) return json({ result: { id: 'semgrep:tainted-ssrf', cwe: 'CWE-918', category: 'SAST' } });
      throw new Error(`unexpected ${url}`);
    };
    const { items, missing, excluded } = await fetchAvits({ instance: INSTANCE, clientId: 'id', clientSecret: 's' }, ['AVIT000000000000001', 'AVIT000000000000002', 'AVIT000000000000003', 'AVIT000000000000004', 'AVIT000000000000005'], { fetchImpl });
    assert.deepEqual(items.map(item => item.fields.number), ['AVIT000000000000001', 'AVIT000000000000002', 'AVIT000000000000003']);
    assert.deepEqual(missing, ['AVIT000000000000004']);
    assert.deepEqual(excluded, ['AVIT000000000000005']);
    assert.equal(items[0].references.vulnerability.cwe, 'CWE-918');
    assert.deepEqual(items[2].references, {});
    assert.equal(items[1].fields.sys_mod_count, undefined);
    assert.equal(calls.length, 5, 'token, AVITs, reference, view rule, view membership');
    assert.match(calls[0].options.body, /grant_type=client_credentials/);
    assert.equal(calls[1].options.headers.Authorization, 'Bearer token');
    assert.ok(calls.every(call => call.options.redirect === 'error'));
    const markdown = avitsMarkdown(INSTANCE, items, ['AVIT000000000000001', 'AVIT000000000000002', 'AVIT000000000000003', 'AVIT000000000000004'], missing, new Date('2026-10-20T12:00:00Z'));
    assert.match(markdown, /## AVIT000000000000001/); assert.match(markdown, /### Referenced vulnerability/);
    assert.match(markdown, /Not found or not readable: AVIT000000000000004/); assert.match(markdown, /~~~text\nline one\nline two\n~~~/);
    assert.match(markdown, /untrusted evidence/);
  });
  it('reports authentication failures and empty results without leaking credentials', async () => {
    const denied = async () => ({ ok: false, status: 401, json: async () => ({}) });
    await assert.rejects(fetchAvits({ instance: INSTANCE, clientId: 'id', clientSecret: 'very-secret' }, ['AVIT000000000000001'], { fetchImpl: denied }), error => /HTTP 401/.test(error.message) && !/very-secret/.test(error.message));
    const empty = async url => json(url.endsWith('/oauth_token.do') ? { access_token: 't' } : { result: [] });
    await assert.rejects(loadAvitAttachment({ instance: INSTANCE, clientId: 'id', clientSecret: 's' }, ['AVIT000000000000001'], { fetchImpl: empty }), /No AVITs were returned/);
  });
  it('skips AVITs outside the CodeSecurity view, whatever their finding source (no view rule: SCM fields decide)', async () => {
    const other = async url => json(url.endsWith('/oauth_token.do') ? { access_token: 't' } : url.includes('/sysrule_view') ? { result: [] } : { result: [{ number: { display_value: 'AVIT000000000000009' }, u_security_finding_source: { display_value: 'Secrets' } }] });
    await assert.rejects(loadAvitAttachment({ instance: INSTANCE, clientId: 'id', clientSecret: 's' }, ['AVIT000000000000009'], { fetchImpl: other }), error => error.status === 422 && /CodeSecurity/.test(error.message));
  });
});
