'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { inspect } = require('node:util');
const { createSourceManagers, SOURCE_MANAGER_CAPABILITIES: CAPABILITIES } = require('../lib/scm.cjs');

// All credentials, responses, DNS answers, and Git executions are synthetic.
// Filesystem fixtures live exclusively in the checkout's OS temporary directory.
const TOKEN = 'synthetic-fixture-token-never-real';
const COMMIT = 'a'.repeat(40);
const OTHER_COMMIT = 'b'.repeat(40);
const PUBLIC_ADDRESS = '140.82.112.4';
const basic = provider => `Basic ${Buffer.from(provider === 'github' ? `x-access-token:${TOKEN}` : `:${TOKEN}`).toString('base64')}`;
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const json = (data, headers = {}, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...headers } });
const githubRepository = (id = 1, fields = {}) => ({
  id, name: `repo-${id}`, full_name: `octocat/repo-${id}`, owner: { login: 'octocat' }, default_branch: 'main',
  clone_url: `https://github.com/octocat/repo-${id}.git`, html_url: `https://github.com/octocat/repo-${id}`,
  ...fields,
});
const azureRepository = (id = 'repo-id', fields = {}) => ({
  id, name: `Repository ${id}`, project: { id: 'project-id', name: 'Project One' }, defaultBranch: 'refs/heads/main',
  remoteUrl: `https://dev.azure.com/contoso/project-id/_git/${id}`, ...fields,
});
function config(env) {
  const entries = [];
  for (let index = 0; index < Number(env.GIT_CONFIG_COUNT); index++) entries.push([env[`GIT_CONFIG_KEY_${index}`], env[`GIT_CONFIG_VALUE_${index}`]]);
  return new Map(entries);
}
function noSecret(value) {
  const serialized = typeof value === 'string' ? value : inspect(value, { depth: 10, showHidden: true });
  for (const secret of [TOKEN, encodeURIComponent(TOKEN), basic('github'), basic('azure-devops')]) assert.equal(serialized.includes(secret), false, 'secret must not be exposed');
}
async function rejectsCode(action, code) {
  await assert.rejects(action, error => {
    assert.equal(error.code, code);
    assert.equal(error.status, error.statusCode);
    assert.equal(error.name, 'SourceManagerError');
    assert.equal(Object.hasOwn(error, 'cause'), false);
    assert.equal(Object.hasOwn(error, 'stderr'), false);
    assert.equal(Object.hasOwn(error, 'stdout'), false);
    noSecret(error);
    return true;
  });
}
function fixture(t, settings = {}) {
  const requests = [], executions = [], retainedEnvironments = [], directories = new Set(), lookups = [];
  const github = settings.github || [githubRepository()];
  const azure = settings.azure || [azureRepository()];
  const branch = settings.branch || 'main';
  let handler = settings.handle;
  const fetch = async (url, init) => {
    requests.push({ url, init: { ...init, headers: { ...init.headers } } });
    const parsed = new URL(url);
    if (handler) {
      const response = await handler(parsed, init, requests.length);
      if (response !== undefined) return response;
    }
    if (parsed.hostname === 'api.github.com') {
      if (parsed.pathname === '/user') return settings.installation ? json({ message: 'Resource not accessible by integration' }, {}, 403) : json({ login: 'octocat', token: TOKEN });
      if (['/user/repos', '/installation/repositories'].includes(parsed.pathname)) {
        const page = Number(parsed.searchParams.get('page'));
        const items = github.slice((page - 1) * 100, page * 100);
        return parsed.pathname.startsWith('/installation/') ? json({ repositories: items, total_count: github.length }) : json(items);
      }
      if (parsed.pathname.endsWith('/branches')) return json([{ name: branch, commit: { sha: COMMIT }, token: TOKEN }]);
      if (parsed.pathname.includes('/branches/')) return json({ name: decodeURIComponent(parsed.pathname.split('/branches/')[1]), commit: { sha: COMMIT } });
    }
    if (parsed.hostname === 'dev.azure.com') {
      if (parsed.pathname.endsWith('/_apis/git/repositories')) return json({ value: azure, count: azure.length });
      if (parsed.pathname.endsWith('/refs')) return json({ value: [{ name: `refs/heads/${branch}`, objectId: COMMIT }, { name: 'refs/tags/main', objectId: OTHER_COMMIT }] });
    }
    throw new Error(`Unexpected fake API request ${url}`);
  };
  const execFile = async (file, args, options) => {
    executions.push({ file, args: [...args], options: { ...options, env: { ...options.env } } });
    retainedEnvironments.push(options.env);
    if (args.includes('clone')) {
      const repoPath = args.at(-1);
      directories.add(path.dirname(repoPath));
      if (settings.execute) return settings.execute(file, args, options);
      await fs.mkdir(path.join(repoPath, '.git'), { recursive: true });
      // Emulate Git's normal storage of the credential-free URL argument only.
      await fs.writeFile(path.join(repoPath, '.git', 'config'), `[remote "origin"]\n\turl = ${args.at(-2)}\n`);
      return { stdout: '', stderr: `ignored provider chatter ${TOKEN}` };
    }
    if (settings.execute) {
      const result = await settings.execute(file, args, options);
      if (result !== undefined) return result;
    }
    if (args.includes('rev-parse')) return { stdout: `${settings.commit || COMMIT}\n`, stderr: '' };
    if (args.includes('symbolic-ref')) return { stdout: `${settings.actualBranch || branch}\n`, stderr: '' };
    throw new Error('Unexpected fake Git command');
  };
  const lookup = async (host, options) => {
    lookups.push({ host, options });
    if (settings.lookup) return settings.lookup(host, options);
    return [{ address: PUBLIC_ADDRESS, family: 4 }];
  };
  const managers = createSourceManagers({ fetch, execFile, lookup });
  t.after(async () => {
    for (const connection of managers.list()) managers.disconnect(connection.id);
    for (const directory of directories) await fs.rm(directory, { recursive: true, force: true });
  });
  return { managers, requests, executions, retainedEnvironments, directories, lookups,
    setHandler(value) { handler = value; },
    async connect(provider = 'github', extras = {}) { return managers.connect({ provider, token: TOKEN, ...(provider === 'azure-devops' ? { organization: 'contoso' } : {}), ...extras }); },
    async discovered(provider = 'github', extras = {}) {
      const connection = await this.connect(provider, extras);
      const result = await managers.repositories(connection.id);
      return { connection, ...result };
    },
  };
}

describe('Source manager public contract and session-only credentials', () => {
  it('documents fixed cloud origins, permissions, bounds, and lifecycle without dependencies', () => {
    assert.deepEqual(Object.keys(createSourceManagers()).sort(), ['branches', 'checkout', 'connect', 'disconnect', 'list', 'repositories']);
    assert.equal(CAPABILITIES.pageSize, 100);
    assert.equal(CAPABILITIES.maxPage, 100);
    assert.equal(CAPABILITIES.providers.github.apiOrigin, 'https://api.github.com');
    assert.equal(CAPABILITIES.providers.github.gitOrigin, 'https://github.com');
    assert.equal(CAPABILITIES.providers['azure-devops'].apiOrigin, 'https://dev.azure.com');
    assert.equal(CAPABILITIES.credentials, 'session-memory-only');
    assert.equal(CAPABILITIES.successfulCheckoutCleanup, 'caller');
    assert.equal(CAPABILITIES.customHosts, false);
    assert.ok(Object.isFrozen(CAPABILITIES.providers.github));
    assert.throws(() => createSourceManagers({ fetch: 'not a function' }), /Invalid source/);
    assert.throws(() => createSourceManagers({ host: 'https://example.test' }), /Invalid source/);
  });

  for (const provider of ['github', 'azure-devops']) {
    it(`connects ${provider} with safe detached summaries and no persistence`, async t => {
      const f = fixture(t), connection = await f.connect(provider);
      assert.deepEqual(Object.keys(connection).sort(), ['account', 'host', 'id', 'label', 'provider']);
      assert.match(connection.id, /^[a-f\d-]{36}$/);
      assert.equal(connection.provider, provider);
      assert.equal(connection.account, provider === 'github' ? 'octocat' : 'contoso');
      noSecret(connection);
      noSecret(f.managers.list());
      connection.label = TOKEN;
      f.managers.list()[0].account = TOKEN;
      noSecret(f.managers.list());
      assert.equal(f.executions.length, 0);
      assert.equal(f.directories.size, 0);
      assert.equal(createSourceManagers().list().length, 0);
      const request = f.requests[0];
      assert.equal(request.init.headers.Authorization, provider === 'github' ? `Bearer ${TOKEN}` : basic(provider));
      assert.equal(request.init.method, 'GET');
      assert.equal(request.init.redirect, 'manual');
      assert.equal(request.init.credentials, 'omit');
      assert.ok(request.init.signal instanceof AbortSignal);
      noSecret(request.url);
      assert.equal(f.managers.disconnect(connection.id), true);
      assert.deepEqual(f.managers.list(), []);
      assert.equal(f.managers.disconnect(connection.id), false);
      await rejectsCode(() => f.managers.repositories(connection.id), 'SCM_CONNECTION_NOT_FOUND');
    });
  }

  it('validates provider, token, organization, objects, and URL overrides before any API use', async t => {
    const f = fixture(t);
    const invalid = [
      [{ provider: 'gitlab', token: TOKEN }, 'SCM_INVALID_PROVIDER'],
      [{ provider: { toString: () => 'github' }, token: TOKEN }, 'SCM_INVALID_PROVIDER'],
      [{ provider: 'github', token: '' }, 'SCM_INVALID_TOKEN'],
      [{ provider: 'github', token: ' token-with-spaces ' }, 'SCM_INVALID_TOKEN'],
      [{ provider: 'github', token: `${TOKEN}\r\nHeader: injected` }, 'SCM_INVALID_TOKEN'],
      [{ provider: 'github', token: 'x'.repeat(4097) }, 'SCM_INVALID_TOKEN'],
      [{ provider: 'github', token: TOKEN, organization: 'https://github.com/org' }, 'SCM_INVALID_ORGANIZATION'],
      [{ provider: 'azure-devops', token: TOKEN }, 'SCM_INVALID_ORGANIZATION'],
      [{ provider: 'azure-devops', token: TOKEN, organization: '../other' }, 'SCM_INVALID_ORGANIZATION'],
      [{ provider: 'azure-devops', token: TOKEN, organization: 'https://dev.azure.com/org' }, 'SCM_INVALID_ORGANIZATION'],
      [{ provider: 'azure-devops', token: TOKEN, organization: 'org@evil.test' }, 'SCM_INVALID_ORGANIZATION'],
      [{ provider: 'github', token: TOKEN, baseUrl: 'https://evil.test' }, 'SCM_INVALID_INPUT'],
      [null, 'SCM_INVALID_INPUT'], [[], 'SCM_INVALID_INPUT'],
    ];
    for (const [input, code] of invalid) await rejectsCode(() => f.managers.connect(input), code);
    assert.equal(f.requests.length, 0);
    assert.deepEqual(f.managers.list(), []);
  });

  it('bounds connection allocation and reuses a slot after disconnect', async t => {
    const f = fixture(t);
    for (let index = 0; index < 16; index++) await f.connect();
    await rejectsCode(() => f.connect(), 'SCM_LIMIT');
    assert.equal(f.requests.length, 16);
    f.managers.disconnect(f.managers.list()[0].id);
    await f.connect();
    assert.equal(f.managers.list().length, 16);
  });
});

describe('Provider discovery, search, and bounded pagination', () => {
  it('maps GitHub metadata into safe repository DTOs and never trusts response URLs', async t => {
    const f = fixture(t, { github: [githubRepository(7, { clone_url: `https://user:${TOKEN}@evil.test/repo.git`, html_url: `javascript:${TOKEN}`, full_name: TOKEN, token: TOKEN })] });
    const { repositories } = await f.discovered();
    assert.deepEqual(repositories, [{ id: '7', name: 'repo-7', fullName: 'octocat/repo-7', defaultBranch: 'main', webUrl: 'https://github.com/octocat/repo-7' }]);
    noSecret(repositories);
    assert.equal(new URL(f.requests[1].url).pathname, '/user/repos');
  });

  it('supports fine-grained PAT discovery, 100-item pages, cache isolation, and one-item lookahead', async t => {
    const github = Array.from({ length: 101 }, (_, index) => githubRepository(index + 1));
    const f = fixture(t, { github });
    const { connection, repositories, page, hasMore } = await f.discovered();
    assert.equal(repositories.length, 100);
    assert.equal(page, 1);
    assert.equal(hasMore, true);
    assert.equal(f.requests.length, 3);
    repositories[0].fullName = TOKEN;
    repositories[0].id = 'attacker-id';
    const second = await f.managers.repositories(connection.id, { page: '2' });
    assert.equal(second.repositories.length, 1);
    assert.equal(second.repositories[0].id, '101');
    assert.equal(second.hasMore, false);
    assert.equal(f.requests.length, 3);
    noSecret(await f.managers.repositories(connection.id));
    for (const request of f.requests.slice(1)) {
      assert.equal(new URL(request.url).searchParams.get('per_page'), '100');
      assert.equal(new URL(request.url).searchParams.get('sort'), 'full_name');
    }
  });

  it('detects GitHub installation tokens without requiring user privileges', async t => {
    const f = fixture(t, { installation: true });
    const connection = await f.connect();
    assert.equal(connection.account, 'octocat');
    assert.equal(new URL(f.requests[1].url).pathname, '/installation/repositories');
    const result = await f.managers.repositories(connection.id);
    assert.equal(result.repositories[0].id, '1');
    assert.equal(f.requests.length, 2);
  });

  it('connects an empty GitHub installation without exposing credentials or inventing repositories', async t => {
    const f = fixture(t, { installation: true, github: [] });
    const { connection, repositories, hasMore } = await f.discovered();
    assert.equal(connection.account, 'GitHub App installation');
    assert.deepEqual(repositories, []);
    assert.equal(hasMore, false);
    noSecret(connection);
  });

  it('performs literal global search across accessible pages and optional GitHub owner scope', async t => {
    const github = Array.from({ length: 105 }, (_, index) => githubRepository(index + 1, { name: `project-${index + 1}`, owner: { login: index === 100 ? 'OtherOrg' : 'Octocat' } }));
    const f = fixture(t, { github });
    const connection = await f.connect('github', { organization: 'OCTOCAT' });
    const result = await f.managers.repositories(connection.id, { search: ' PROJECT-10 ' });
    assert.deepEqual(result.repositories.map(repo => repo.name), ['project-10', 'project-100', 'project-102', 'project-103', 'project-104', 'project-105']);
    assert.equal(result.hasMore, false);
    assert.ok(f.requests.every(request => !new URL(request.url).searchParams.has('q')));
    assert.deepEqual((await f.managers.repositories(connection.id, { search: 'repo:evil OR fork:true' })).repositories, []);
  });

  it('honors GitHub hasMore relations without following untrusted Link URLs', async t => {
    const f = fixture(t, { handle: url => {
      if (url.pathname === '/user/repos') return json([githubRepository(Number(url.searchParams.get('page')))],
        url.searchParams.get('page') === '1' ? { Link: `<https://evil.test/?token=${TOKEN}>; rel="next"` } : {});
    } });
    const { repositories, hasMore } = await f.discovered();
    assert.equal(repositories.length, 2);
    assert.equal(hasMore, false);
    assert.deepEqual(f.requests.slice(1).map(request => new URL(request.url).hostname), ['api.github.com', 'api.github.com']);
    assert.deepEqual(f.requests.slice(1).map(request => new URL(request.url).searchParams.get('page')), ['1', '2']);
  });

  it('paginates a capped Azure DevOps snapshot locally (API has no repository paging)', async t => {
    const azure = Array.from({ length: 151 }, (_, index) => azureRepository(`id-${index + 1}`));
    const f = fixture(t, { azure });
    const { connection, repositories, hasMore } = await f.discovered('azure-devops', { organization: 'CONTOSO' });
    assert.equal(connection.account, 'contoso');
    assert.equal(repositories.length, 100);
    assert.equal(hasMore, true);
    const second = await f.managers.repositories(connection.id, { page: 2 });
    assert.equal(second.repositories.length, 51);
    assert.equal(second.hasMore, false);
    assert.equal((await f.managers.repositories(connection.id, { search: 'id-151' })).repositories[0].id, 'id-151');
    assert.equal(f.requests.length, 1);
    assert.equal(new URL(f.requests[0].url).pathname, '/contoso/_apis/git/repositories');
    assert.equal(new URL(f.requests[0].url).searchParams.get('api-version'), '7.1');
    noSecret(second);
  });

  it('rejects malformed metadata rather than cloning a forged path', async t => {
    for (const fields of [{ name: '..' }, { name: '../evil' }, { owner: { login: 'github.com@evil.test' } }, { default_branch: '--upload-pack=evil' }]) {
      const f = fixture(t, { github: [githubRepository(1, fields)] });
      const connection = await f.connect();
      await rejectsCode(() => f.managers.repositories(connection.id), 'SCM_INVALID_RESPONSE');
      assert.equal(f.executions.length, 0);
    }
    const f = fixture(t, { azure: [azureRepository('../evil')] });
    await rejectsCode(() => f.connect('azure-devops'), 'SCM_INVALID_RESPONSE');
    assert.deepEqual(f.managers.list(), []);
  });

  it('rejects token echoes in metadata, including encoded credential representations', async t => {
    const f = fixture(t, { azure: [azureRepository('id', { name: `echo ${TOKEN}` })] });
    await rejectsCode(() => f.connect('azure-devops'), 'SCM_INVALID_RESPONSE');
    const g = fixture(t, { github: [githubRepository(1, { default_branch: Buffer.from(`x-access-token:${TOKEN}`).toString('base64') })] });
    const connection = await g.connect();
    await rejectsCode(() => g.managers.repositories(connection.id), 'SCM_INVALID_RESPONSE');
  });

  it('validates bounded page and search parameters without issuing requests', async t => {
    const f = fixture(t), { connection } = await f.discovered();
    const count = f.requests.length;
    for (const page of [0, -1, 101, '0', '01', '', '2.0', '1e2', 1.5, Infinity, null, {}, []]) {
      await rejectsCode(() => f.managers.repositories(connection.id, { page }), 'SCM_INVALID_PAGE');
      await rejectsCode(() => f.managers.branches(connection.id, '1', { page }), 'SCM_INVALID_PAGE');
    }
    for (const search of [[], {}, 'x'.repeat(201), 'x\r\n', '\ud800']) await rejectsCode(() => f.managers.repositories(connection.id, { search }), 'SCM_INVALID_INPUT');
    assert.equal(f.requests.length, count);
    assert.deepEqual(await f.managers.repositories(connection.id, { page: '100' }), { repositories: [], page: 100, hasMore: false });
  });

  it('stops bounded inventory discovery rather than silently truncating an unfinished search', async t => {
    const items = Array.from({ length: 100 }, (_, index) => githubRepository(index + 1));
    const f = fixture(t, { handle: url => url.pathname === '/user/repos' ? json(items) : undefined });
    const connection = await f.connect();
    await rejectsCode(() => f.managers.repositories(connection.id, { search: 'does-not-match' }), 'SCM_LIMIT');
    assert.equal(f.requests.length, 101);
  });

  it('requires per-connection discovered identities, not caller-provided URLs or names', async t => {
    const f = fixture(t), a = await f.connect(), b = await f.connect();
    for (const id of ['1', 'octocat/repo-1', 'https://github.com/octocat/repo-1.git', 'file:///etc', '--upload-pack=evil']) {
      await rejectsCode(() => f.managers.checkout(a.id, { repositoryId: id }), 'SCM_REPOSITORY_NOT_FOUND');
      await rejectsCode(() => f.managers.branches(a.id, id), 'SCM_REPOSITORY_NOT_FOUND');
    }
    await f.managers.repositories(a.id);
    await rejectsCode(() => f.managers.checkout(b.id, { repositoryId: '1' }), 'SCM_REPOSITORY_NOT_FOUND');
    assert.equal(f.executions.length, 0);
  });
});

describe('Branch enumeration and encoded provider refs', () => {
  it('paginates and caches GitHub branches with sanitized { name } DTOs', async t => {
    const f = fixture(t, { handle: url => {
      if (!url.pathname.endsWith('/branches')) return undefined;
      return url.searchParams.get('page') === '1'
        ? json(Array.from({ length: 100 }, (_, index) => ({ name: `feature/${index}`, secret: TOKEN })), { Link: '<https://evil.test/>; rel="next"' })
        : json([{ name: 'feature/final', token: TOKEN }]);
    } });
    const { connection } = await f.discovered();
    const first = await f.managers.branches(connection.id, '1');
    assert.equal(first.branches.length, 100);
    assert.equal(first.hasMore, true);
    assert.deepEqual(first.branches[0], { name: 'feature/0' });
    first.branches[0].name = TOKEN;
    noSecret(await f.managers.branches(connection.id, '1'));
    const second = await f.managers.branches(connection.id, '1', { page: 2 });
    assert.deepEqual(second, { branches: [{ name: 'feature/final' }], page: 2, hasMore: false });
    assert.equal(f.requests.length, 4);
    assert.equal(new URL(f.requests.at(-1).url).hostname, 'api.github.com');
  });

  it('walks Azure DevOps continuation tokens, encodes IDs, and excludes tags', async t => {
    const repoId = "repo ?#&'()", projectId = "project ?#&'()", cursor = 'opaque+/&?=#';
    const f = fixture(t, { azure: [azureRepository(repoId, { project: { id: projectId, name: 'Project' } })], handle: url => {
      if (!url.pathname.endsWith('/refs')) return undefined;
      assert.equal(url.searchParams.get('$top'), '100');
      assert.equal(url.searchParams.get('filter'), 'heads/');
      if (!url.searchParams.has('continuationToken')) return json({ value: [{ name: 'refs/heads/main' }, { name: 'refs/tags/main' }] }, { 'x-ms-continuationtoken': cursor });
      assert.equal(url.searchParams.get('continuationToken'), cursor);
      return json({ value: [{ name: 'refs/heads/feature/a&b' }] });
    } });
    const { connection, repositories } = await f.discovered('azure-devops');
    const second = await f.managers.branches(connection.id, repoId, { page: 2 });
    assert.deepEqual(second, { branches: [{ name: 'feature/a&b' }], page: 2, hasMore: false });
    assert.deepEqual((await f.managers.branches(connection.id, repoId)).branches, [{ name: 'main' }]);
    assert.equal(f.requests.length, 3);
    const requestUrl = f.requests.at(-1).url;
    assert.match(requestUrl, /project%20%3F%23%26%27%28%29/);
    assert.match(requestUrl, /repo%20%3F%23%26%27%28%29/);
    assert.equal(new URL(repositories[0].webUrl).hostname, 'dev.azure.com');
    assert.equal((await f.managers.branches(connection.id, repoId, { page: 3 })).hasMore, false);
    assert.equal(f.requests.length, 3);
  });

  it('rejects repeated Azure continuation tokens instead of looping or repeating pages', async t => {
    const f = fixture(t, { handle: url => url.pathname.endsWith('/refs') ? json({ value: [{ name: 'refs/heads/main' }] }, { 'x-ms-continuationtoken': 'repeat' }) : undefined });
    const { connection } = await f.discovered('azure-devops');
    await rejectsCode(() => f.managers.branches(connection.id, 'repo-id', { page: 2 }), 'SCM_INVALID_RESPONSE');
    assert.equal(f.requests.length, 3);
  });

  it('URL-encodes GitHub branch path segments and ADO ref filters without URL injection', async t => {
    const branch = "feature/a&b+#%'()";
    for (const provider of ['github', 'azure-devops']) {
      const f = fixture(t, { branch }), { connection, repositories } = await f.discovered(provider);
      const result = await f.managers.checkout(connection.id, { repositoryId: repositories[0].id, branch });
      assert.equal(result.provenance.branch, branch);
      const url = new URL(f.requests.at(-1).url);
      assert.equal(url.hash, '');
      if (provider === 'github') {
        assert.match(url.pathname, /feature%2Fa%26b%2B%23%25%27%28%29$/);
        assert.equal(url.search, '');
      } else assert.equal(url.searchParams.get('filter'), `heads/${branch}`);
    }
  });
});

describe('Credential-isolated, bounded shallow checkout', () => {
  for (const provider of ['github', 'azure-devops']) {
    it(`clones ${provider} without secret argv/config/URL exposure and preserves completed sessions`, async t => {
      const f = fixture(t), { connection, repositories } = await f.discovered(provider);
      const repo = repositories[0];
      const result = await f.managers.checkout(connection.id, { repositoryId: repo.id });
      assert.equal(result.repoPath, path.join(result.tempDir, 'repository'));
      assert.deepEqual(result.provenance, { provider, repository: repo.fullName, branch: 'main', commit: COMMIT, webUrl: repo.webUrl });
      noSecret(result);
      assert.equal(f.executions.length, 3);
      const [clone, revParse, symbolic] = f.executions;
      assert.equal(clone.file, 'git');
      assert.equal(clone.options.shell, false);
      assert.equal(clone.options.timeout, CAPABILITIES.gitTimeoutMs);
      assert.equal(clone.options.maxBuffer, CAPABILITIES.gitMaxBuffer);
      for (const arg of ['--depth=1', '--single-branch', '--no-tags', '--no-recurse-submodules', '--template=', '--quiet', '--no-progress']) assert.ok(clone.args.includes(arg));
      assert.equal(clone.args[clone.args.indexOf('--branch') + 1], 'main');
      assert.equal(clone.args.at(-3), '--');
      const remote = new URL(clone.args.at(-2));
      assert.equal(remote.hostname, connection.host);
      assert.equal(remote.protocol, 'https:');
      assert.equal(remote.username, '');
      assert.equal(remote.password, '');
      noSecret(clone.args);
      const entries = config(clone.options.env);
      assert.equal(entries.get(`http.${remote}.extraHeader`), `Authorization: ${basic(provider)}`);
      assert.deepEqual([...entries].filter(([key, value]) => /extraheader/i.test(key) && value), [[`http.${remote}.extraHeader`, `Authorization: ${basic(provider)}`]]);
      for (const [key, value] of [['http.followRedirects', 'false'], ['http.sslVerify', 'true'], ['credential.helper', ''], ['credential.interactive', 'false'],
        ['protocol.file.allow', 'never'], ['protocol.ext.allow', 'never'], ['protocol.allow', 'never'], ['protocol.https.allow', 'always'], ['submodule.recurse', 'false'],
        ['filter.lfs.process', ''], ['filter.lfs.smudge', ''], ['filter.lfs.required', 'false'], ['transfer.bundleURI', 'false']]) assert.equal(entries.get(key), value);
      assert.equal(clone.options.env.GIT_TERMINAL_PROMPT, '0');
      assert.equal(clone.options.env.GIT_LFS_SKIP_SMUDGE, '1');
      assert.equal(clone.options.env.GIT_CONFIG_NOSYSTEM, '1');
      assert.equal(clone.options.env.HOME, result.tempDir);
      assert.equal(entries.get('http.curloptResolve'), `${connection.host}:443:${PUBLIC_ADDRESS}`);
      assert.equal(f.lookups[0].host, connection.host);
      assert.deepEqual(f.lookups[0].options, { all: true, verbatim: true });
      assert.ok(revParse.args.includes('rev-parse'));
      assert.ok(revParse.args.includes('HEAD^{commit}'));
      assert.ok(symbolic.args.includes('symbolic-ref'));
      noSecret(revParse.options);
      noSecret(symbolic.options);
      for (const env of f.retainedEnvironments) noSecret(env);
      const stored = await fs.readFile(path.join(result.repoPath, '.git', 'config'), 'utf8');
      noSecret(stored);
      assert.doesNotMatch(stored, /extraheader|credential/i);
      assert.ok(stored.includes(remote.toString()));
      assert.equal(f.managers.disconnect(connection.id), true);
      assert.ok((await fs.stat(result.repoPath)).isDirectory());
      await rejectsCode(() => f.managers.checkout(connection.id, { repositoryId: repo.id }), 'SCM_CONNECTION_NOT_FOUND');
    });
  }

  it('does not inherit unsafe Git, trace, proxy, helper, loader, or PATH environment', async t => {
    const poisoned = { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'credential.helper', GIT_CONFIG_VALUE_0: '!malicious', GIT_CONFIG_PARAMETERS: '-c x=y',
      GIT_DIR: '/untrusted', GIT_WORK_TREE: '/untrusted', GIT_EXEC_PATH: '/untrusted', GIT_TEMPLATE_DIR: '/untrusted', GIT_SSH_COMMAND: 'malicious',
      GIT_TRACE: '/tmp/scm-must-not-create-trace', GIT_TRACE_CURL: '1', GIT_TRACE2_EVENT: '/tmp/scm-must-not-create-trace', GIT_SSL_NO_VERIFY: '1',
      HTTPS_PROXY: 'https://evil.test', HTTP_PROXY: 'http://evil.test', ALL_PROXY: 'socks://evil.test', LD_PRELOAD: '/untrusted', DYLD_INSERT_LIBRARIES: '/untrusted',
      NODE_OPTIONS: '--require=/untrusted', NODE_DEBUG: 'child_process', PATH: '/untrusted' };
    const saved = Object.fromEntries(Object.keys(poisoned).map(key => [key, process.env[key]]));
    Object.assign(process.env, poisoned);
    try {
      const f = fixture(t), { connection } = await f.discovered();
      await f.managers.checkout(connection.id, { repositoryId: '1' });
      for (const execution of f.executions) {
        for (const [key, value] of Object.entries(poisoned)) assert.notEqual(execution.options.env[key], value, key);
        assert.equal(execution.options.env.GIT_ASKPASS, '');
        assert.equal(execution.options.env.SSH_ASKPASS, '');
      }
    } finally {
      for (const [key, value] of Object.entries(saved)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
  });

  it('refuses unsafe branches and revision expressions before API or process execution', async t => {
    const f = fixture(t), { connection } = await f.discovered();
    const count = f.requests.length;
    const invalid = ['', '--upload-pack=evil', '-x', 'HEAD', 'refs/heads/main', '@', '@{-1}', 'x..y', 'x//y', '.x', 'x/.y', 'x.lock', 'x.LOCK/y', 'main^', 'main~1',
      'x?y', 'x*y', 'x:y', 'x\\y', 'x[y', 'x y', 'x\n', 'x\0', '/x', 'x/', 'x.', '\ud800', 'x'.repeat(256), {}, null];
    for (const branch of invalid) await rejectsCode(() => f.managers.checkout(connection.id, { repositoryId: '1', branch }), 'SCM_INVALID_BRANCH');
    assert.equal(f.requests.length, count);
    assert.equal(f.executions.length, 0);
  });

  it('verifies branch metadata rather than accepting tags or a mismatched provider branch', async t => {
    for (const provider of ['github', 'azure-devops']) {
      const f = fixture(t, { handle: url => {
        if (url.pathname.includes('/branches/')) return json({ name: 'different', commit: { sha: COMMIT } });
        if (url.pathname.endsWith('/refs')) return json({ value: [{ name: 'refs/tags/main', objectId: COMMIT }, { name: 'refs/heads/main-longer', objectId: COMMIT }] });
      } });
      const { connection, repositories } = await f.discovered(provider);
      await rejectsCode(() => f.managers.checkout(connection.id, { repositoryId: repositories[0].id }), 'SCM_BRANCH_NOT_FOUND');
      assert.equal(f.executions.length, 0);
    }
  });

  it('redacts arbitrary process failures, stderr/stdout/env and cleans failed clone directories', async t => {
    const f = fixture(t, { execute: async (file, args, options) => {
      await fs.mkdir(args.at(-1), { recursive: true });
      const error = new Error(`Git failed ${TOKEN} ${JSON.stringify(options.env)}`);
      Object.assign(error, { stdout: TOKEN, stderr: basic('github'), cmd: TOKEN, env: options.env, cause: new Error(TOKEN) });
      throw error;
    } });
    const { connection } = await f.discovered();
    await rejectsCode(() => f.managers.checkout(connection.id, { repositoryId: '1' }), 'SCM_CHECKOUT_FAILED');
    for (const directory of f.directories) await assert.rejects(() => fs.stat(directory), { code: 'ENOENT' });
    for (const env of f.retainedEnvironments) noSecret(env);
    noSecret(f.managers.list());
  });

  it('rejects malformed commit output or a tag checkout and removes the checkout', async t => {
    for (const settings of [{ commit: `${TOKEN}\n` }, { commit: '--not-a-commit' }, { actualBranch: 'different' }]) {
      const f = fixture(t, settings), { connection } = await f.discovered();
      await rejectsCode(() => f.managers.checkout(connection.id, { repositoryId: '1' }), 'SCM_CHECKOUT_FAILED');
      for (const directory of f.directories) await assert.rejects(() => fs.stat(directory), { code: 'ENOENT' });
    }
  });

  it('refuses private, loopback, reserved, mapped, or mixed DNS answers before clone', async t => {
    for (const address of ['127.0.0.1', '10.1.2.3', '169.254.169.254', '192.168.1.1', '100.64.0.1', '::1', '::ffff:127.0.0.1', 'fc00::1', '2001:db8::1', 'not-an-ip']) {
      const family = address.includes(':') ? 6 : 4;
      const f = fixture(t, { lookup: async () => [{ address: PUBLIC_ADDRESS, family: 4 }, { address, family }] });
      const { connection } = await f.discovered();
      await rejectsCode(() => f.managers.checkout(connection.id, { repositoryId: '1' }), 'SCM_PROVIDER_FAILED');
      assert.equal(f.executions.length, 0);
    }
  });

  it('pins public IPv6 answers with libcurl IPv6 syntax', async t => {
    const f = fixture(t, { lookup: async () => [{ address: '2606:50c0:8000::154', family: 6 }] });
    const { connection } = await f.discovered();
    await f.managers.checkout(connection.id, { repositoryId: '1' });
    assert.equal(config(f.executions[0].options.env).get('http.curloptResolve'), 'github.com:443:[2606:50c0:8000::154]');
  });

  it('supports ordinary Node callback execFile and lookup injections', async t => {
    const f = fixture(t), { connection } = await f.discovered();
    f.managers.disconnect(connection.id);
    const manager = createSourceManagers({
      fetch: async url => new URL(url).pathname === '/user' ? json({ login: 'octocat' })
        : new URL(url).pathname.includes('/branches/') ? json({ name: 'main', commit: { sha: COMMIT } }) : json([githubRepository()]),
      lookup(host, options, callback) { callback(null, [{ address: PUBLIC_ADDRESS, family: 4 }]); },
      execFile(file, args, options, callback) {
        if (args.includes('clone')) { f.directories.add(path.dirname(args.at(-1))); callback(null, '', ''); }
        else callback(null, args.includes('rev-parse') ? `${COMMIT}\n` : 'main\n', '');
      },
    });
    const connected = await manager.connect({ provider: 'github', token: TOKEN });
    t.after(() => manager.disconnect(connected.id));
    await manager.repositories(connected.id);
    const checkout = await manager.checkout(connected.id, { repositoryId: '1' });
    assert.equal(checkout.provenance.commit, COMMIT);
  });

  it('aborts an in-flight clone on disconnect, forgets credentials, and cleans only that failed checkout', async t => {
    const started = deferred();
    const f = fixture(t, { execute: (file, args, options) => new Promise((resolve, reject) => {
      started.resolve();
      options.signal.addEventListener('abort', () => reject(new Error(`${TOKEN}: cancelled`)), { once: true });
    }) });
    const { connection } = await f.discovered();
    const pending = f.managers.checkout(connection.id, { repositoryId: '1' });
    await started.promise;
    assert.equal(f.managers.disconnect(connection.id), true);
    await rejectsCode(() => pending, 'SCM_CONNECTION_NOT_FOUND');
    for (const directory of f.directories) await assert.rejects(() => fs.stat(directory), { code: 'ENOENT' });
    assert.deepEqual(f.managers.list(), []);
    for (const env of f.retainedEnvironments) noSecret(env);
  });
});

describe('Provider failures, size limits, and cancellation never expose credentials', () => {
  for (const status of [301, 302, 307, 308, 401, 403, 404, 429, 500]) {
    it(`sanitizes HTTP ${status} without returning or following provider error text`, async t => {
      const f = fixture(t, { handle: () => json({ message: `${TOKEN} ${basic('github')}` }, { Location: `https://evil.test/?token=${TOKEN}` }, status) });
      const code = [401, 403].includes(status) ? 'SCM_AUTHORIZATION_FAILED' : 'SCM_PROVIDER_FAILED';
      await rejectsCode(() => f.connect(), code);
      assert.ok(f.requests.every(request => new URL(request.url).hostname === 'api.github.com'));
      assert.ok(f.requests.every(request => request.init.redirect === 'manual'));
      assert.deepEqual(f.managers.list(), []);
    });
  }

  it('rejects a transport that reports a followed redirect even when it ends with HTTP 200', async t => {
    const f = fixture(t, { handle: () => ({ ...json({ login: 'octocat' }), status: 200, redirected: true, url: 'https://evil.test' }) });
    await rejectsCode(() => f.connect(), 'SCM_INVALID_RESPONSE');
    assert.equal(f.requests.length, 1);
  });

  it('never propagates network/DNS errors or malformed provider JSON', async t => {
    const f = fixture(t, { handle: () => { throw new Error(`network error ${TOKEN}`); } });
    await rejectsCode(() => f.connect(), 'SCM_PROVIDER_FAILED');
    const g = fixture(t, { handle: () => new Response(`{ invalid ${TOKEN}`, { headers: { 'Content-Type': 'application/json' } }) });
    await rejectsCode(() => g.connect(), 'SCM_PROVIDER_FAILED');
    const h = fixture(t, { lookup: () => { throw new Error(`DNS error ${TOKEN}`); } });
    const { connection } = await h.discovered();
    await rejectsCode(() => h.managers.checkout(connection.id, { repositoryId: '1' }), 'SCM_CHECKOUT_FAILED');
  });

  it('rejects oversized Content-Length and streamed bodies before parsing', async t => {
    const f = fixture(t, { handle: () => json({ login: 'octocat' }, { 'Content-Length': String(CAPABILITIES.apiMaxBytes + 1) }) });
    await rejectsCode(() => f.connect(), 'SCM_RESPONSE_TOO_LARGE');
    const g = fixture(t, { handle: () => new Response('x'.repeat(CAPABILITIES.apiMaxBytes + 1), { headers: { 'Content-Type': 'application/json' } }) });
    await rejectsCode(() => g.connect(), 'SCM_RESPONSE_TOO_LARGE');
    assert.deepEqual(f.managers.list(), []);
    assert.deepEqual(g.managers.list(), []);
  });

  it('rejects HTML sign-in pages and compressed bodies rather than returning provider content', async t => {
    for (const headers of [{ 'Content-Type': 'text/html' }, { 'Content-Encoding': 'gzip' }]) {
      const f = fixture(t, { handle: () => json({ login: TOKEN }, headers) });
      await rejectsCode(() => f.connect(), 'SCM_INVALID_RESPONSE');
    }
  });

  it('times out a stalled request with an aborted transport signal', async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const started = deferred();
    const f = fixture(t, { handle: (url, init) => { started.resolve(init.signal); return new Promise(() => {}); } });
    const pending = f.connect();
    const signal = await started.promise;
    t.mock.timers.tick(CAPABILITIES.apiTimeoutMs + 1);
    await rejectsCode(() => pending, 'SCM_TIMEOUT');
    assert.equal(signal.aborted, true);
    assert.deepEqual(f.managers.list(), []);
  });

  it('times out and cancels a stalled response body, not only response headers', async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const reading = deferred();
    let cancelled = false;
    const f = fixture(t, { handle: () => new Response(new ReadableStream({
      pull() { reading.resolve(); return new Promise(() => {}); },
      cancel() { cancelled = true; },
    }), { headers: { 'Content-Type': 'application/json' } }) });
    const pending = f.connect();
    await reading.promise;
    t.mock.timers.tick(CAPABILITIES.apiTimeoutMs + 1);
    await rejectsCode(() => pending, 'SCM_TIMEOUT');
    assert.equal(cancelled, true);
  });

  it('cancels discovery on disconnect without committing late metadata', async t => {
    const started = deferred();
    const f = fixture(t), connection = await f.connect();
    f.setHandler((url, init) => {
      if (url.pathname !== '/user/repos') return undefined;
      started.resolve(init.signal);
      return new Promise(() => {});
    });
    const pending = f.managers.repositories(connection.id);
    const signal = await started.promise;
    f.managers.disconnect(connection.id);
    await rejectsCode(() => pending, 'SCM_CONNECTION_NOT_FOUND');
    assert.equal(signal.aborted, true);
    assert.deepEqual(f.managers.list(), []);
  });
});
