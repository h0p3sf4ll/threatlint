'use strict';

const DEFAULTS = Object.freeze({ domain: 'threatlint.us.auth0.com', clientId: 'eysUAb8yPNapU4TXqRHpIfhSX4xC4Qqy', audience: 'https://threatlint.dev/api' });
const PROVIDERS = new Set(['google', 'apple', 'github', 'sso']);
function auth0Configuration(origin, options = {}, env = process.env) {
  const domain = options.domain || env.AUTH0_DOMAIN || DEFAULTS.domain;
  const clientId = options.clientId || env.AUTH0_CLIENT_ID || DEFAULTS.clientId;
  const audience = options.audience || env.AUTH0_AUDIENCE || DEFAULTS.audience;
  if (typeof domain !== 'string' || domain.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/i.test(domain)) throw new Error('AUTH0_DOMAIN must be a hostname without a scheme or path');
  if (typeof clientId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(clientId)) throw new Error('Invalid AUTH0_CLIENT_ID');
  if (typeof audience !== 'string' || !audience || audience.length > 2048 || /[\x00-\x20\x7f]/.test(audience)) throw new Error('Invalid AUTH0_AUDIENCE');
  const connections = { google: env.AUTH0_GOOGLE_CONNECTION || 'google-oauth2', apple: env.AUTH0_APPLE_CONNECTION || 'apple', github: env.AUTH0_GITHUB_CONNECTION || 'github' };
  for (const value of Object.values(connections)) if (!/^[A-Za-z0-9._-]{1,128}$/.test(value)) throw new Error('Invalid Auth0 social connection name');
  const requestedProviders = options.enabledProviders ?? env.AUTH0_ENABLED_PROVIDERS ?? 'google';
  const enabledProviders = Array.isArray(requestedProviders) ? [...requestedProviders]
    : typeof requestedProviders === 'string' && requestedProviders.length <= 128 ? requestedProviders.split(',').map(value => value.trim()) : [];
  if (!enabledProviders.length || enabledProviders.some(value => !PROVIDERS.has(value)) || new Set(enabledProviders).size !== enabledProviders.length) {
    throw new Error('AUTH0_ENABLED_PROVIDERS must list configured providers: google, apple, github, sso');
  }
  return { provider: 'auth0', domain: domain.toLowerCase(), clientId, audience, redirectUri: `${origin.origin}/`, connections, enabledProviders };
}

// Explicitly reject database/passwordless/anonymous and machine identities, even when enabled in the tenant.
const STRATEGIES = new Set(['google-oauth2', 'apple', 'github', 'waad', 'ad', 'adfs', 'samlp', 'oidc', 'oauth2']);
function permittedSubject(subject) {
  if (typeof subject !== 'string' || subject.length > 1024 || /[\x00-\x20\x7f]/.test(subject)) return false;
  const split = subject.indexOf('|');
  return split > 0 && split < subject.length - 1 && STRATEGIES.has(subject.slice(0, split));
}
module.exports = { auth0Configuration, permittedSubject, DEFAULTS };
