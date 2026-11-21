'use strict';

// Transport fixtures only: production Auth0 SDK code performs discovery, JWKS signature/claim checks,
// and userinfo subject verification against these responses. No authentication method is mocked.
const crypto = require('node:crypto');

function createAuth0Fixture() {
  const configuration = { domain: 'tenant.auth0.test', clientId: 'fixture-client', audience: 'https://threatlint.dev/api' };
  const issuer = `https://${configuration.domain}/`;
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = crypto.randomUUID(), jwk = { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' };
  const identities = new Map(), requests = [];
  function issue({ subject = 'google-oauth2|alice', email = 'alice@example.test', displayName = 'Alice', claims = {}, userInfo } = {}) {
    const at = Math.floor(Date.now() / 1000);
    const payload = { iss: issuer, sub: subject, aud: [configuration.audience, `${issuer}userinfo`],
      azp: configuration.clientId, iat: at, exp: at + 3600, scope: 'openid profile email', ...claims };
    const data = [Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid })).toString('base64url'),
      Buffer.from(JSON.stringify(payload)).toString('base64url')].join('.');
    const token = `${data}.${crypto.sign('RSA-SHA256', Buffer.from(data), privateKey).toString('base64url')}`;
    identities.set(token, userInfo || { sub: payload.sub, name: displayName, email });
    return token;
  }
  async function fetch(input, init = {}) {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    requests.push(url.href);
    if (url.origin !== new URL(issuer).origin) throw new Error(`Unexpected Auth0 fixture origin: ${url.origin}`);
    if (url.pathname === '/.well-known/openid-configuration') return Response.json({ issuer,
      authorization_endpoint: `${issuer}authorize`, token_endpoint: `${issuer}oauth/token`, userinfo_endpoint: `${issuer}userinfo`,
      jwks_uri: `${issuer}.well-known/jwks.json`, response_types_supported: ['code'], subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'], token_endpoint_auth_methods_supported: ['none', 'client_secret_post'] });
    if (url.pathname === '/.well-known/jwks.json') return Response.json({ keys: [jwk] });
    if (url.pathname === '/userinfo') {
      const headers = new Headers(init.headers || (typeof input === 'object' ? input.headers : undefined));
      const token = headers.get('authorization')?.replace(/^Bearer /i, ''), user = identities.get(token);
      return user ? Response.json(user) : Response.json({ error: 'invalid_token' }, { status: 401 });
    }
    throw new Error(`Unexpected Auth0 fixture path: ${url.pathname}`);
  }
  return { configuration, issuer, issue, fetch, requests };
}

module.exports = { createAuth0Fixture };
