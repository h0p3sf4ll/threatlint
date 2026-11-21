'use strict';

(() => {
  const $ = id => document.getElementById(id);
  let register = false;
  let registrationEnabled = false;
  let pending = false;
  function setMode(next) {
    if (pending || (next && !registrationEnabled)) return;
    register = next;
    $('login-mode').setAttribute('aria-pressed', String(!register));
    $('register-mode').setAttribute('aria-pressed', String(register));
    $('login-title').textContent = register ? 'Make it your workspace.' : 'Welcome back.';
    $('login-description').textContent = register ? 'Create a profile to save your settings and security work.' : 'Sign in to your security workbench.';
    $('display-name-field').hidden = !register;
    $('display-name').required = register;
    $('password-hint').hidden = !register;
    $('password').minLength = register ? 12 : 1;
    $('password').autocomplete = register ? 'new-password' : 'current-password';
    $('login-submit').textContent = register ? 'Create account' : 'Sign in';
    $('login-error').textContent = '';
  }
  $('login-mode').addEventListener('click', () => setMode(false));
  $('register-mode').addEventListener('click', () => setMode(true));
  $('password-visibility').addEventListener('click', () => {
    const visible = $('password').type === 'password';
    $('password').type = visible ? 'text' : 'password';
    $('password-visibility').textContent = visible ? 'Hide' : 'Show';
    $('password-visibility').setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
    $('password-visibility').setAttribute('aria-pressed', String(visible));
  });
  $('login-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (pending || !$('login-form').reportValidity()) return;
    pending = true;
    $('login-submit').disabled = true;
    $('login-form').setAttribute('aria-busy', 'true');
    $('login-submit').textContent = register ? 'Creating your profile…' : 'Signing in…';
    $('login-error').textContent = '';
    try {
      const response = await fetch(register ? '/auth/register' : '/auth/login', {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: $('email').value.trim(), password: $('password').value, ...(register ? { displayName: $('display-name').value.trim() } : {}) }),
      });
      const payload = await response.json().catch(() => ({ error: 'The server could not complete your request. Please try again.' }));
      if (!response.ok) throw new Error(payload.error || 'Sign in could not complete. Please try again.');
      $('password').value = '';
      try { const channel = new BroadcastChannel('threatlint-auth'); channel.postMessage({ type: 'session-changed' }); channel.close(); } catch { /* other tabs check on focus */ }
      location.replace('/');
    } catch (error) { $('login-error').textContent = error.message || 'The server could not be reached. Please try again.'; }
    finally { pending = false; $('login-submit').disabled = false; $('login-form').removeAttribute('aria-busy'); $('login-submit').textContent = register ? 'Create account' : 'Sign in'; }
  });
  (async () => {
    try {
      const response = await fetch('/auth/config', { cache: 'no-store' });
      if (!response.ok) throw new Error('Account options could not be loaded.');
      registrationEnabled = (await response.json()).registrationEnabled === true;
      $('login-tabs').hidden = !registrationEnabled;
      $('registration-note').textContent = registrationEnabled ? 'Your settings and reports are saved to your account.' : 'Use the account provided by your administrator.';
    } catch { $('registration-note').textContent = 'Contact your administrator if you need an account.'; }
  })();
})();
