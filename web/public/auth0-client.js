'use strict';

// The SDK owns authorization URLs, PKCE, transaction state, and token validation in the browser.
// Loading this helper on desktop performs no network requests and does not load the SDK.
(() => {
  let initialization;
  let sdkLoading;
  const PENDING_COMPANY = 'threatlint.auth.pending-company.v1';
  function normalizeCompanySlug(value) {
    const slug = typeof value === 'string' ? value.trim().toLowerCase() : '';
    if (!/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(slug)) throw new Error('Use a company slug with 3–63 letters, numbers, and hyphens. Start and end with a letter or number.');
    return slug;
  }
  function companyFromPath() {
    const match = /^\/c\/([^/]+)(?:\/|$)/.exec(location.pathname || '/');
    return match ? normalizeCompanySlug(match[1]) : null;
  }
  function clearPendingCompany() { try { window.sessionStorage.removeItem(PENDING_COMPANY); } catch { /* routing hint only */ } }
  function bootstrapCompany() {
    const fromPath = companyFromPath();
    if (fromPath || !callbackPresent()) return fromPath;
    // This hint selects an SDK configuration only. The SDK transaction and server token checks establish identity.
    try { const value = window.sessionStorage.getItem(PENDING_COMPANY); return value ? normalizeCompanySlug(value) : null; }
    catch { clearPendingCompany(); return null; }
  }
  async function configuration(companySlug) {
    const response = await fetch(`/auth/config${companySlug ? `?company=${encodeURIComponent(companySlug)}` : ''}`, { cache: 'no-store', credentials: 'same-origin' });
    if (!response.ok) throw new Error(companySlug ? 'That company workspace is unavailable. Check its slug or contact your administrator.' : 'Sign-in options could not be loaded. Please try again.');
    const config = await response.json();
    if (config.provider !== 'auth0' || !config.domain || !config.clientId || !config.audience || !config.redirectUri) throw new Error('Sign-in is not configured. Contact your administrator.');
    const callback = new URL(config.redirectUri);
    if (callback.origin !== location.origin || callback.pathname !== '/' || callback.search || callback.hash) throw new Error('Sign-in callback does not match this application. Contact your administrator.');
    if (companySlug && (config.company?.slug !== companySlug || !config.company?.organizationId)) throw new Error('Company sign-in is not configured. Contact your administrator.');
    return config;
  }
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
    if (window.threatlintDesktop) throw new Error('The desktop workbench uses your local profile and does not require web sign-in.');
    if (!initialization) initialization = (async () => {
      const config = await configuration(bootstrapCompany());
      const sdk = await loadSdk();
      const client = await sdk.createAuth0Client({ domain: config.domain, clientId: config.clientId,
        cacheLocation: 'memory', authorizationParams: { redirect_uri: config.redirectUri, audience: config.audience, scope: 'openid profile email',
          ...(config.company ? { organization: config.company.organizationId } : {}) } });
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
    if (provider !== 'sso' && (!['google', 'apple', 'github'].includes(provider) || !config.connections?.[provider])) throw new Error('That sign-in option is unavailable. Use your organization’s single sign-on.');
    const companySlug = config.company?.slug || null;
    if (companySlug) { try { window.sessionStorage.setItem(PENDING_COMPANY, companySlug); } catch { /* SDK appState also preserves the route */ } }
    else clearPendingCompany();
    return client.loginWithRedirect({ appState: { companySlug },
      ...(provider === 'sso' ? {} : { authorizationParams: { connection: config.connections[provider] } }) });
  }
  async function completeRedirect() {
    const { client, config } = await initialize();
    const params = new URLSearchParams(location.search);
    try {
      if (!params.has('state') || (!params.has('code') && !params.has('error'))) throw new Error('The sign-in response is incomplete. Please start sign-in again.');
      const transaction = await client.handleRedirectCallback();
      const appSlug = transaction?.appState?.companySlug;
      const companySlug = appSlug == null ? null : normalizeCompanySlug(appSlug);
      if (config.company && companySlug !== config.company.slug) throw new Error('The company sign-in context changed. Please start sign-in again.');
      const companyConfig = companySlug && !config.company ? await configuration(companySlug) : config;
      const token = await client.getTokenSilently(companySlug ? { authorizationParams: { organization: companyConfig.company.organizationId } } : undefined);
      if (typeof token !== 'string' || !token) throw new Error('The identity provider did not return an access token. Please sign in again.');
      const response = await fetch('/auth/session', { method: 'POST', credentials: 'same-origin', headers: { Authorization: `Bearer ${token}`,
        ...(companySlug ? { 'X-Threatlint-Company': companySlug } : {}) } });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || 'Your sign-in could not be verified. Please try again.');
      return result;
    } finally {
      clearPendingCompany();
      // Authorization codes and transaction state have no purpose in browser history after processing.
      history.replaceState({}, document.title, config.redirectUri);
    }
  }
  async function logout() {
    const { client, config } = await initialize();
    clearPendingCompany();
    return client.logout({ logoutParams: { returnTo: config.redirectUri } });
  }
  window.ThreatlintAuth = { initialize, login, completeRedirect, callbackPresent, logout, normalizeCompanySlug, companyFromPath };
})();
