'use strict';

(() => {
  const $ = id => document.getElementById(id);
  const buttons = [...document.querySelectorAll('[data-identity]')];
  let pending = true;
  function setPending(value, status = '') {
    pending = value;
    for (const button of buttons) button.disabled = value;
    $('identity-options').setAttribute('aria-busy', String(value));
    $('login-status').textContent = status;
  }
  function showError(error) {
    $('login-error').textContent = error?.error === 'access_denied'
      ? 'Sign-in was not completed. Choose an account to try again.'
      : error?.message || 'Secure sign-in could not complete. Please try again.';
  }
  function showCompany(company) {
    if (!company) return;
    $('company-context').hidden = false;
    $('company-name').textContent = company.name;
    $('company-slug').textContent = company.slug;
    $('company-form').hidden = true;
    $('personal-login-link').hidden = false;
    $('login-title').textContent = 'Company workspace';
    $('login-description').textContent = `Sign in to ${company.name} with an account authorized by your organization.`;
  }
  $('company-form').addEventListener('submit', event => {
    event.preventDefault();
    $('login-error').textContent = '';
    try {
      const slug = window.ThreatlintAuth.normalizeCompanySlug($('company-input').value);
      location.assign(`/c/${encodeURIComponent(slug)}/login`);
    } catch (error) { showError(error); $('company-input').focus(); }
  });
  for (const button of buttons) button.addEventListener('click', async () => {
    if (pending) return;
    setPending(true, 'Opening secure sign-in…');
    $('login-error').textContent = '';
    try { await window.ThreatlintAuth.login(button.dataset.identity); }
    catch (error) { showError(error); setPending(false); }
  });
  (async () => {
    try {
      const { config } = await window.ThreatlintAuth.initialize();
      showCompany(config.company);
      if (window.ThreatlintAuth.callbackPresent()) {
        setPending(true, 'Completing sign-in…');
        const result = await window.ThreatlintAuth.completeRedirect();
        try { const channel = new BroadcastChannel('threatlint-auth'); channel.postMessage({ type: 'session-changed' }); channel.close(); } catch { /* other tabs check identity on focus */ }
        const companySlug = result.user?.company?.slug;
        location.replace(companySlug ? `/c/${window.ThreatlintAuth.normalizeCompanySlug(companySlug)}/` : '/');
        return;
      }
      if (new URLSearchParams(location.search).get('notice') === 'provider-logout') $('login-error').textContent = 'You are signed out of Threatlint. Your identity provider session may still be active.';
      setPending(false);
    } catch (error) { showError(error); setPending(false); }
  })();
})();
