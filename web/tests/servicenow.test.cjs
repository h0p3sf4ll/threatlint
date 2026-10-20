'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { parseAvitNumbers, validateInstanceUrl, validateCredentials, fetchAvits, avitsMarkdown, loadAvitAttachment } = require('../lib/servicenow.cjs');

const INSTANCE = 'https://example.service-now.com';
const json = body => ({ ok: true, status: 200, json: async () => body });

describe('AVIT numbers and instance URLs', () => {
  it('normalizes, de-duplicates, and bounds AVIT lists', () => {
    assert.deepEqual(parseAvitNumbers('avit0001234, AVIT0001235\nAVIT0001234'), ['AVIT0001234', 'AVIT0001235']);
    assert.throws(() => parseAvitNumbers('AVIT12'), /Not an AVIT/);
    assert.throws(() => parseAvitNumbers(''), /at least one/);
    assert.throws(() => parseAvitNumbers(Array.from({ length: 51 }, (_, i) => `AVIT${String(i).padStart(7, '0')}`)), /at most 50/);
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
      if (url.includes('/api/now/table/sn_vul_app_vulnerable_item')) return json({ result: [
        { number: { display_value: 'AVIT0000002' }, sys_mod_count: { value: '4' }, description: { display_value: 'line one\nline two' } },
        { number: { display_value: 'AVIT0000001' }, vulnerability: { display_value: 'SSRF rule', link: `${INSTANCE}/api/now/table/sn_vul_app_vulnerability_entry/abc` } },
        { number: { display_value: 'AVIT0000003' }, vulnerability: { display_value: 'x', link: 'https://attacker.example/api/now/table/x/1' } },
      ] });
      if (url.includes('sn_vul_app_vulnerability_entry/abc')) return json({ result: { id: 'semgrep:tainted-ssrf', cwe: 'CWE-918' } });
      throw new Error(`unexpected ${url}`);
    };
    const { items, missing } = await fetchAvits({ instance: INSTANCE, clientId: 'id', clientSecret: 's' }, ['AVIT0000001', 'AVIT0000002', 'AVIT0000003', 'AVIT0000004'], { fetchImpl });
    assert.deepEqual(items.map(item => item.fields.number), ['AVIT0000001', 'AVIT0000002', 'AVIT0000003']);
    assert.deepEqual(missing, ['AVIT0000004']);
    assert.equal(items[0].references.vulnerability.cwe, 'CWE-918');
    assert.deepEqual(items[2].references, {});
    assert.equal(items[1].fields.sys_mod_count, undefined);
    assert.equal(calls.length, 3);
    assert.match(calls[0].options.body, /grant_type=client_credentials/);
    assert.equal(calls[1].options.headers.Authorization, 'Bearer token');
    assert.ok(calls.every(call => call.options.redirect === 'error'));
    const markdown = avitsMarkdown(INSTANCE, items, ['AVIT0000001', 'AVIT0000002', 'AVIT0000003', 'AVIT0000004'], missing, new Date('2026-10-20T12:00:00Z'));
    assert.match(markdown, /## AVIT0000001/); assert.match(markdown, /### Referenced vulnerability/);
    assert.match(markdown, /Not found or not readable: AVIT0000004/); assert.match(markdown, /~~~text\nline one\nline two\n~~~/);
    assert.match(markdown, /untrusted evidence/);
  });
  it('reports authentication failures and empty results without leaking credentials', async () => {
    const denied = async () => ({ ok: false, status: 401, json: async () => ({}) });
    await assert.rejects(fetchAvits({ instance: INSTANCE, clientId: 'id', clientSecret: 'very-secret' }, ['AVIT0000001'], { fetchImpl: denied }), error => /HTTP 401/.test(error.message) && !/very-secret/.test(error.message));
    const empty = async url => json(url.endsWith('/oauth_token.do') ? { access_token: 't' } : { result: [] });
    await assert.rejects(loadAvitAttachment({ instance: INSTANCE, clientId: 'id', clientSecret: 's' }, ['AVIT0000001'], { fetchImpl: empty }), /No AVITs were returned/);
  });
});
