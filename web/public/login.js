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
  for (const button of buttons) button.addEventListener('click', async () => {
    if (pending) return;
    setPending(true, 'Opening secure sign-in…');
    $('login-error').textContent = '';
    try { await window.ThreatlintAuth.login(button.dataset.identity); }
    catch (error) { showError(error); setPending(false); }
  });
  (async () => {
    try {
      await window.ThreatlintAuth.initialize();
      if (window.ThreatlintAuth.callbackPresent()) {
        setPending(true, 'Completing sign-in…');
        await window.ThreatlintAuth.completeRedirect();
        try { const channel = new BroadcastChannel('threatlint-auth'); channel.postMessage({ type: 'session-changed' }); channel.close(); } catch { /* other tabs check identity on focus */ }
        location.replace('/');
        return;
      }
      if (new URLSearchParams(location.search).get('notice') === 'provider-logout') $('login-error').textContent = 'You are signed out of Threatlint. Your identity provider session may still be active.';
      setPending(false);
    } catch (error) { showError(error); setPending(false); }
  })();
})();
