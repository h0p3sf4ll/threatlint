'use strict';

// The SDK owns authorization URLs, PKCE, transaction state, and token validation in the browser.
// Loading this helper on desktop performs no network requests and does not load the SDK.
(() => {
  let initialization;
  let sdkLoading;
  async function loadSdk() {
    if (window.auth0?.createAuth0Client) return window.auth0;
    if (!sdkLoading) sdkLoading = new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = '/vendor/auth0-spa-js.js';
      script.async = true;
      script.addEventListener('load', () => window.auth0?.createAuth0Client
        ? resolve(window.auth0) : reject(new Error('Secure sign-in could not be loaded. Reload to try again.')), { once: true });
      script.addEventListener('error', () => reject(new Error('Secure sign-in could not be loaded. Reload to try again.')), { once: true });
      document.head.append(script);
    }).catch(error => { sdkLoading = null; throw error; });
    return sdkLoading;
  }
  async function initialize() {
    if (!initialization) initialization = (async () => {
      const response = await fetch('/auth/config', { cache: 'no-store', credentials: 'same-origin' });
      if (!response.ok) throw new Error('Sign-in options could not be loaded. Please try again.');
      const config = await response.json();
      if (config.provider !== 'auth0' || !config.domain || !config.clientId || !config.audience || !config.redirectUri) throw new Error('Sign-in is not configured. Contact your administrator.');
      const callback = new URL(config.redirectUri);
      if (callback.origin !== location.origin || callback.pathname !== '/' || callback.search || callback.hash) throw new Error('Sign-in callback does not match this application. Contact your administrator.');
      const sdk = await loadSdk();
      const client = await sdk.createAuth0Client({ domain: config.domain, clientId: config.clientId,
        cacheLocation: 'memory', authorizationParams: { redirect_uri: config.redirectUri, audience: config.audience, scope: 'openid profile email' } });
      return { client, config };
    })().catch(error => { initialization = null; throw error; });
    return initialization;
  }
  function callbackPresent() {
    const params = new URLSearchParams(location.search);
    return params.has('code') || params.has('error') || params.has('state');
  }
  async function login(provider = 'sso') {
    const { client, config } = await initialize();
    if (provider === 'sso') return client.loginWithRedirect();
    if (!['google', 'apple', 'github'].includes(provider) || !config.connections?.[provider]) throw new Error('That sign-in option is unavailable. Use your organization’s single sign-on.');
    return client.loginWithRedirect({ authorizationParams: { connection: config.connections[provider] } });
  }
  async function completeRedirect() {
    const { client, config } = await initialize();
    const params = new URLSearchParams(location.search);
    try {
      if (!params.has('state') || (!params.has('code') && !params.has('error'))) throw new Error('The sign-in response is incomplete. Please start sign-in again.');
      await client.handleRedirectCallback();
      const token = await client.getTokenSilently();
      if (typeof token !== 'string' || !token) throw new Error('The identity provider did not return an access token. Please sign in again.');
      const response = await fetch('/auth/session', { method: 'POST', credentials: 'same-origin', headers: { Authorization: `Bearer ${token}` } });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || 'Your sign-in could not be verified. Please try again.');
      return result;
    } finally {
      // Authorization codes and transaction state have no purpose in browser history after processing.
      history.replaceState({}, document.title, config.redirectUri);
    }
  }
  async function logout() {
    const { client, config } = await initialize();
    return client.logout({ logoutParams: { returnTo: config.redirectUri } });
  }
  window.ThreatlintAuth = { initialize, login, completeRedirect, callbackPresent, logout };
})();
