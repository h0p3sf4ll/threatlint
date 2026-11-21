'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { auth0Configuration } = require('../lib/auth0-config.cjs');
const origin = new URL('https://app.threatlint.dev');

test('public Auth0 configuration defaults to advertising Google only', () => {
  const config = auth0Configuration(origin, {}, {});
  assert.deepEqual(config.enabledProviders, ['google']);
  assert.equal(config.connections.google, 'google-oauth2');
  assert.equal(config.redirectUri, 'https://app.threatlint.dev/');
});

test('operators explicitly advertise configured social and enterprise providers without management credentials', () => {
  const config = auth0Configuration(origin, {}, { AUTH0_ENABLED_PROVIDERS: 'google, apple,github,sso', AUTH0_GITHUB_CONNECTION: 'github-production' });
  assert.deepEqual(config.enabledProviders, ['google', 'apple', 'github', 'sso']);
  assert.equal(config.connections.github, 'github-production');
  assert.deepEqual(auth0Configuration(origin, { enabledProviders: ['sso'] }, {}).enabledProviders, ['sso']);
});

test('unknown, empty and duplicate provider lists fail startup instead of advertising broken choices', () => {
  for (const value of ['', ' ', 'google,', ',google', 'google,google', 'google,password', 'Google', 'x'.repeat(129)]) {
    assert.throws(() => auth0Configuration(origin, {}, { AUTH0_ENABLED_PROVIDERS: value }), /AUTH0_ENABLED_PROVIDERS/);
  }
  for (const enabledProviders of [[], ['google', 'google'], ['invalid'], 7, false]) {
    assert.throws(() => auth0Configuration(origin, { enabledProviders }, {}), /AUTH0_ENABLED_PROVIDERS/);
  }
});
