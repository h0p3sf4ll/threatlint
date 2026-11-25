'use strict';

(() => {
  const $ = id => document.getElementById(id);
  const buttons = [...document.querySelectorAll('[data-identity]')];
  const enabledProviders = new Set();
  let pending = true, currentUser = null;
  function setPending(value, status = '') {
    pending = value;
    for (const button of document.querySelectorAll('#workspace-options button')) button.disabled = value;
    for (const button of buttons) button.disabled = value || !enabledProviders.has(button.dataset.identity);
    $('identity-options').setAttribute('aria-busy', String(value));
    $('login-status').textContent = status;
  }
  function showError(error) {
    $('login-error').textContent = error?.error === 'access_denied'
      ? 'Sign-in was not completed. Choose an account to try again.'
      : error?.message || 'Secure sign-in could not complete. Please try again.';
  }
  async function request(url, options = {}) {
    const headers = { ...options.headers, ...(currentUser?.id ? { 'X-Threatlint-Profile': currentUser.id } : {}) };
    const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store', ...options, headers });
    const result = await response.json().catch(() => ({}));
    if (response.status === 409 && result.code === 'profile_changed') { location.reload(); throw new Error('Your active account changed. Reloading your workspaces…'); }
    if (!response.ok) throw new Error(result.error || 'Your workspaces could not be loaded. Try again.');
    return result;
  }
  function showProviders(config) {
    for (const provider of Array.isArray(config.enabledProviders) ? config.enabledProviders : []) enabledProviders.add(provider);
    for (const button of buttons) button.hidden = !enabledProviders.has(button.dataset.identity);
    $('identity-sso-divider').hidden = !enabledProviders.has('sso') || !['google', 'apple', 'github'].some(provider => enabledProviders.has(provider));
    if (!buttons.some(button => !button.hidden)) throw new Error('Sign-in is not configured. Contact your administrator.');
  }
  function showCompany(company) {
    if (!company) return;
    $('company-context').hidden = false;
    $('company-name').textContent = company.name;
    $('personal-login-link').hidden = false;
    $('login-title').textContent = 'Organization workspace';
    $('login-description').textContent = `Sign in to ${company.name} with your organization account.`;
  }
  function goHome(user) {
    const slug = user?.company?.slug;
    location.replace(slug ? `/c/${window.ThreatlintAuth.normalizeCompanySlug(slug)}/` : '/');
  }
  async function openOrganization(company) {
    setPending(true, `Opening ${company.name}…`);
    $('login-error').textContent = '';
    try { await window.ThreatlintAuth.loginOrganization(company); }
    catch (error) { showError(error); setPending(false); }
  }
  function personal() {
    if (!currentUser?.company) { location.replace('/'); return; }
    location.assign('/login?workspace=personal');
  }
  function renderOrganizations(organizations) {
    $('organization-list').replaceChildren();
    for (const company of organizations) {
      const button = document.createElement('button'); button.type = 'button'; button.className = 'identity-button workspace-organization';
      const name = document.createElement('span'); name.textContent = company.name;
      const arrow = document.createElement('span'); arrow.textContent = '→'; arrow.setAttribute('aria-hidden', 'true');
      button.append(name, arrow); button.addEventListener('click', () => { if (!pending) void openOrganization(company); });
      $('organization-list').append(button);
    }
  }
  async function loadWorkspaces({ automatic = false } = {}) {
    setPending(true, 'Finding your workspaces…');
    $('identity-options').hidden = true;
    $('company-context').hidden = true;
    $('personal-login-link').hidden = true;
    $('workspace-options').hidden = false;
    $('organization-create').hidden = true;
    $('organizations-retry').hidden = true;
    $('organization-list').replaceChildren();
    $('login-error').textContent = '';
    try {
      const data = await request('/auth/organizations');
      if (!data.managementAvailable) throw new Error('Organization discovery is unavailable. Try again or continue with your personal workspace.');
      if (!Array.isArray(data.organizations)) throw new Error('Your workspace list could not be verified. Try again.');
      const organizations = data.organizations;
      $('login-title').textContent = organizations.length ? 'Choose a workspace' : 'Set up your workspace';
      $('login-description').textContent = currentUser?.email ? `Signed in as ${currentUser.email}` : 'You’re signed in securely.';
      $('workspace-description').textContent = organizations.length
        ? 'You already belong to these organizations. Choose where to continue.'
        : 'Create an organization to work with your team, or continue with your personal workspace.';
      renderOrganizations(organizations);
      $('organization-create').hidden = !(data.canCreate === true && organizations.length === 0);
      if (!$('organization-create').hidden) {
        try {
          const draft = JSON.parse(window.sessionStorage.getItem('threatlint.organization-create.v1'));
          if (draft?.userId === currentUser?.id && typeof draft.name === 'string' && draft.name.length <= 120) {
            $('organization-name').value = draft.name;
            $('workspace-description').textContent = 'Finish your earlier organization setup, or continue with your personal workspace.';
          }
        } catch { /* Storage can be unavailable; the form remains usable. */ }
      }
      setPending(false);
      if (automatic && organizations.length === 1) await openOrganization(organizations[0]);
    } catch (error) {
      $('login-title').textContent = 'Your workspaces';
      $('workspace-description').textContent = 'Your personal workspace is still available. Retry to load organization membership.';
      $('organizations-retry').hidden = false;
      showError(error); setPending(false);
    }
  }
  $('personal-workspace')?.addEventListener('click', () => { if (!pending) personal(); });
  $('use-another-account')?.addEventListener('click', async () => {
    if (pending) return;
    setPending(true, 'Signing out…');
    try {
      await request('/auth/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      await window.ThreatlintAuth.logout();
    } catch (error) { showError(error); setPending(false); }
  });
  $('organizations-retry')?.addEventListener('click', () => { if (!pending) void loadWorkspaces(); });
  $('organization-create')?.addEventListener('submit', async event => {
    event.preventDefault(); if (pending) return;
    const name = $('organization-name').value.trim();
    if (!name) { $('organization-name').focus(); return; }
    setPending(true, 'Creating your organization…'); $('login-error').textContent = '';
    try {
      const storage = window.sessionStorage;
      const key = 'threatlint.organization-create.v1';
      let previous;
      try { previous = JSON.parse(storage.getItem(key)); } catch { /* a new request is safe before any network call */ }
      if (!previous || previous.userId !== currentUser?.id || previous.name !== name || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(previous.idempotencyKey || '')) {
        previous = { userId: currentUser?.id, name, idempotencyKey: crypto.randomUUID() };
        storage.setItem(key, JSON.stringify(previous));
      }
      const result = await request('/auth/organizations', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, idempotencyKey: previous.idempotencyKey }) });
      storage.removeItem(key);
      $('organization-create').hidden = true;
      $('login-title').textContent = 'Your organization is ready';
      $('workspace-description').textContent = 'Continue to your new organization. If sign-in is interrupted, choose it again below.';
      renderOrganizations([result.organization]);
      await openOrganization(result.organization);
    } catch (error) { showError(error); setPending(false); }
  });
  for (const button of buttons) button.addEventListener('click', async () => {
    if (pending || !enabledProviders.has(button.dataset.identity)) return;
    setPending(true, 'Opening secure sign-in…'); $('login-error').textContent = '';
    try { await window.ThreatlintAuth.login(button.dataset.identity); }
    catch (error) { showError(error); setPending(false); }
  });
  (async () => {
    try {
      const { config } = await window.ThreatlintAuth.initialize();
      showProviders(config); showCompany(config.company);
      if (window.ThreatlintAuth.callbackPresent()) {
        setPending(true, 'Completing sign-in…');
        const result = await window.ThreatlintAuth.completeRedirect(); currentUser = result.user;
        try { const channel = new BroadcastChannel('threatlint-auth'); channel.postMessage({ type: 'session-changed' }); channel.close(); } catch { /* other tabs recheck on focus */ }
        if (currentUser?.company || result.personalRequested) { goHome(currentUser); return; }
        await loadWorkspaces({ automatic: true }); return;
      }
      const params = new URLSearchParams(location.search);
      if (!config.company && typeof fetch === 'function' && params.get('workspace') !== 'personal') {
        const response = await fetch('/auth/session', { credentials: 'same-origin', cache: 'no-store' });
        if (response.ok) {
          const result = await response.json(); currentUser = result.user;
          if (currentUser) { await loadWorkspaces({ automatic: params.get('choose') !== '1' }); return; }
        } else if (response.status !== 401) throw new Error('Your sign-in could not be checked. Reload to try again.');
      }
      if (params.get('notice') === 'provider-logout') $('login-error').textContent = 'You are signed out of Threatlint. Your identity provider session may still be active.';
      setPending(false);
    } catch (error) { showError(error); setPending(false); }
  })();
})();
