'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const script = new vm.Script(fs.readFileSync(path.join(__dirname, '../public/login.js'), 'utf8'));
const plain = value => JSON.parse(JSON.stringify(value));
const tick = () => new Promise(resolve => setImmediate(resolve));
class Node {
  constructor() { this.hidden = false; this.disabled = false; this.value = ''; this.children = []; this.events = {}; this.textContent = ''; }
  setAttribute() {}
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  addEventListener(type, fn) { this.events[type] = fn; }
  focus() {}
  async trigger(type) { await this.events[type]?.({ preventDefault() {} }); await tick(); }
}
function setup({ organizations = [], canCreate = true, callback = true, company, managementAvailable = true, failure = false, search = '', create, redirectFails = 0, storedDraft } = {}) {
  const ids = ['identity-options','login-status','login-error','identity-sso-divider','company-context','company-name','personal-login-link','login-title','login-description','workspace-options','organization-create','organizations-retry','organization-list','workspace-description','personal-workspace','use-another-account','organization-name'];
  const nodes = Object.fromEntries(ids.map(id => [id, new Node()]));
  const buttons = ['google','github','sso'].map(identity => Object.assign(new Node(), { dataset: { identity } }));
  const navigations = [], openings = [], requests = [], values = new Map();
  if (storedDraft) values.set('threatlint.organization-create.v1', JSON.stringify(storedDraft));
  const user = { id: 'personal-profile', email: 'member@example.test', ...(company ? { company } : {}) };
  let creationCalls = 0;
  const auth = { initialize: async () => ({ config: { enabledProviders: ['google','github','sso'] } }), callbackPresent: () => callback,
    completeRedirect: async () => ({ user }), loginOrganization: async value => { openings.push(plain(value)); if (openings.length <= redirectFails) throw new Error('Sign-in interrupted'); }, login: async () => {}, logout: async () => {} };
  script.runInContext(vm.createContext({
    window: { ThreatlintAuth: auth, sessionStorage: { getItem: key => values.get(key) || null, setItem: (key,value) => values.set(key,value), removeItem: key => values.delete(key) } },
    document: { getElementById: id => nodes[id], querySelectorAll: selector => selector === '[data-identity]' ? buttons : ['personal-workspace','use-another-account','organizations-retry'].map(id => nodes[id]), createElement: () => new Node() },
    location: { search, replace: value => navigations.push(value), assign: value => navigations.push(value) }, URLSearchParams, crypto,
    fetch: async (url, options = {}) => {
      requests.push({ url, options: plain(options) });
      if (url === '/auth/session') return { ok: true, status: 200, json: async () => ({ user }) };
      if (options.method === 'POST') {
        creationCalls++; if (create) return create(creationCalls, options);
        return { ok: true, json: async () => ({ organization: { slug: 'created-org', name: 'Created', organizationId: 'org_created' } }) };
      }
      return { ok: !failure, status: failure ? 503 : 200, json: async () => failure ? { error: 'Organization service unavailable' } : { organizations, canCreate, managementAvailable } };
    },
  }));
  return { nodes, navigations, openings, requests, values };
}
const acme = { slug: 'acme', name: 'Acme', organizationId: 'org_acme' };
const beta = { slug: 'beta', name: 'Beta', organizationId: 'org_beta' };

test('verified single membership opens the organization without a slug field or domain inference', async () => {
  const ui = setup({ organizations: [acme] }); await tick(); await tick();
  assert.deepEqual(ui.openings, [acme]);
  assert.equal(ui.requests.find(request => request.url === '/auth/organizations').options.headers['X-Threatlint-Profile'], 'personal-profile');
  assert.equal(ui.nodes['organization-create'].hidden, true);
  assert.deepEqual(ui.navigations, []);
});
test('multiple memberships require a deliberate choice; switching workspaces does not auto-pick one', async () => {
  const ui = setup({ organizations: [acme,beta] }); await tick(); await tick();
  assert.equal(ui.nodes['organization-list'].children.length, 2); assert.deepEqual(ui.openings, []);
  await ui.nodes['organization-list'].children[1].trigger('click');
  assert.deepEqual(ui.openings, [beta]);
  const single = setup({ organizations: [acme], callback: false, search: '?choose=1' }); await tick(); await tick();
  assert.deepEqual(single.openings, []);
});
test('no memberships offers organization creation or a personal workspace', async () => {
  const ui = setup(); await tick(); await tick();
  assert.equal(ui.nodes['organization-create'].hidden, false); assert.deepEqual(ui.openings, []);
  await ui.nodes['personal-workspace'].trigger('click'); assert.deepEqual(ui.navigations, ['/']);
});
test('failed or unavailable membership discovery never masquerades as no membership or enables creation', async () => {
  for (const options of [{ failure: true },{ managementAvailable: false }]) {
    const ui = setup(options); await tick(); await tick();
    assert.equal(ui.nodes['organization-create'].hidden, true); assert.equal(ui.nodes['organizations-retry'].hidden, false);
    assert.deepEqual(ui.openings, []); assert.deepEqual(ui.navigations, []);
    await ui.nodes['personal-workspace'].trigger('click'); assert.deepEqual(ui.navigations, ['/']);
  }
});
test('a lost creation response is retried with the same idempotency key, then opens the verified org', async () => {
  const ui = setup({ create: async count => ({ ok: count > 1, json: async () => count === 1 ? { error: 'Try again' } : { organization: acme } }) });
  await tick(); await tick(); ui.nodes['organization-name'].value = 'Acme';
  await ui.nodes['organization-create'].trigger('submit');
  await ui.nodes['organization-create'].trigger('submit');
  const bodies = ui.requests.filter(r => r.options.method === 'POST').map(r => JSON.parse(r.options.body));
  assert.equal(bodies.length, 2); assert.equal(bodies[0].idempotencyKey, bodies[1].idempotencyKey); assert.equal(bodies[0].name, 'Acme');
  assert.ok(ui.requests.filter(request => request.options.method === 'POST').every(request => request.options.headers['X-Threatlint-Profile'] === 'personal-profile'));
  assert.deepEqual(ui.openings, [acme]); assert.equal(ui.values.size, 0);
});

test('a successful creation followed by an interrupted sign-in exposes a workspace retry without creating again', async () => {
  const ui = setup({ redirectFails: 1 }); await tick(); await tick();
  ui.nodes['organization-name'].value = 'Acme'; await ui.nodes['organization-create'].trigger('submit');
  assert.equal(ui.nodes['organization-create'].hidden, true);
  assert.match(ui.nodes['login-error'].textContent, /interrupted/);
  assert.equal(ui.nodes['organization-list'].children.length, 1);
  await ui.nodes['organization-list'].children[0].trigger('click');
  assert.equal(ui.openings.length, 2);
  assert.equal(ui.requests.filter(request => request.options.method === 'POST').length, 1);
});

test('an unfinished creation survives reload for the same profile without reusing another profile’s draft', async () => {
  const draft = { userId: 'personal-profile', name: 'Earlier Team', idempotencyKey: crypto.randomUUID() };
  const ui = setup({ storedDraft: draft }); await tick(); await tick();
  assert.equal(ui.nodes['organization-name'].value, draft.name);
  await ui.nodes['organization-create'].trigger('submit');
  assert.equal(JSON.parse(ui.requests.find(request => request.options.method === 'POST').options.body).idempotencyKey, draft.idempotencyKey);
  const other = setup({ storedDraft: { ...draft, userId: 'different-profile' } }); await tick(); await tick();
  assert.equal(other.nodes['organization-name'].value, '');
});
