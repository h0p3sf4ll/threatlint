'use strict';

/** In-memory Auth0 HTTP responses only. Gateway JWT/userinfo checks still use the official SDK. */
function createManagementFixture() {
  const users = new Map(), organizations = new Map(), memberships = new Map(), calls = [];
  let failure;
  const options = { clientId: 'fixture-management-client', clientSecret: 'fixture-management-secret', connectionIds: ['con_Google'] };
  function user(subject, email = 'member@example.test', name = subject) { users.set(subject, { user_id: subject, email, name }); }
  function organization(id, name, subjects = []) {
    organizations.set(id, { id, name, display_name: name, enabled_connections: [{ connection_id: 'con_Google', assign_membership_on_login: false, is_signup_enabled: false }] });
    memberships.set(id, new Set(subjects));
  }
  async function fetch(input, init = {}) {
    const url = new URL(input), method = init.method || 'GET';
    if (url.origin !== 'https://tenant.auth0.test') throw new Error('Unexpected fixture tenant');
    if (url.pathname === '/oauth/token') return Response.json({ access_token: 'fixture-management-token', expires_in: 3600 });
    if (new Headers(init.headers).get('authorization') !== 'Bearer fixture-management-token') return Response.json({}, { status: 401 });
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method, path: url.pathname, query: url.searchParams.toString(), body });
    if (failure?.(method, url, body)) { failure = undefined; return Response.json({ message: 'fixture failure' }, { status: 503 }); }
    const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent).slice(2);
    if (parts[0] === 'users-by-email') return Response.json([...users.values()].filter(value => value.email === url.searchParams.get('email')));
    if (parts[0] === 'users' && parts.length === 2) return users.has(parts[1]) ? Response.json(users.get(parts[1])) : Response.json({}, { status: 404 });
    function paginated(values, key) {
      if (url.searchParams.has('take')) {
        const from = Number(url.searchParams.get('from') || 0), take = Number(url.searchParams.get('take'));
        return Response.json({ [key]: values.slice(from, from + take), ...(from + take < values.length ? { next: String(from + take) } : {}) });
      }
      const page = Number(url.searchParams.get('page') || 0), perPage = Number(url.searchParams.get('per_page') || 100); return Response.json({ [key]: values.slice(page * perPage, (page + 1) * perPage), total: values.length });
    }
    if (parts[0] === 'users' && parts[2] === 'organizations') return paginated([...organizations.values()].filter(value => memberships.get(value.id)?.has(parts[1])), 'organizations');
    if (parts[0] === 'organizations' && parts[1] === 'name') {
      const value = [...organizations.values()].find(org => org.name === parts[2]);
      return value ? Response.json(value) : Response.json({}, { status: 404 });
    }
    if (parts[0] === 'organizations' && parts.length === 1 && method === 'POST') {
      if (body.enabled_connections?.some(value => Object.hasOwn(value, 'is_signup_enabled') || Object.hasOwn(value, 'show_as_button'))) return Response.json({ errorCode: 'invalid_body', message: 'Only database connections support is_signup_enabled' }, { status: 400 });
      const value = { id: `org_Created${organizations.size + 1}`, ...body }; organizations.set(value.id, value); memberships.set(value.id, new Set());
      return Response.json(value, { status: 201 });
    }
    if (parts[0] === 'organizations' && parts[2] === 'enabled_connections') return paginated(organizations.get(parts[1]).enabled_connections, 'enabled_connections');
    if (parts[0] === 'organizations' && parts[2] === 'members') {
      const members = memberships.get(parts[1]);
      if (!members) return Response.json({}, { status: 404 });
      if (method === 'GET') return paginated([...members].map(subject => users.get(subject) || { user_id: subject }), 'members');
      for (const subject of body.members) {
        if (method === 'POST') { if (!users.has(subject)) return Response.json({}, { status: 400 }); members.add(subject); }
        if (method === 'DELETE') members.delete(subject);
      }
      return new Response(null, { status: 204 });
    }
    throw new Error(`Unexpected fixture endpoint ${method} ${url.pathname}`);
  }
  return { options, fetch, users, organizations, memberships, calls, user, organization, failOnce(predicate) { failure = predicate; } };
}
module.exports = { createManagementFixture };
