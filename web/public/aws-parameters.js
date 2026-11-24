'use strict';
(async () => {
  const $ = id => document.getElementById(id);
  if (!$('aws-parameters-form')) return;
  try { await window.ThreatlintProfile?.ready; } catch { return; }
  let initialized = false, fields = [], timer, requestBusy = false, available = false, cliAvailable = false;
  async function api(url, method = 'GET', body) {
    const response = await (window.ThreatlintProfile?.fetch || fetch)(url, { method, headers: { 'Content-Type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) });
    const data = await response.json(); if (!response.ok) throw new Error(data.error || 'AWS operation failed.'); return data;
  }
  function render(data) {
    const active = ['starting', 'awaiting_sign_in', 'loading'].includes(data.state);
    $('aws-status').textContent = data.message || '';
    for (const id of ['aws-save', 'aws-load', 'aws-sign-in']) $(id).disabled = active || requestBusy || !available || (id !== 'aws-save' && !cliAvailable);
    for (const input of $('aws-parameters-form').querySelectorAll('input, select')) input.disabled = active || requestBusy || !available;
    $('aws-cancel').hidden = !['starting', 'awaiting_sign_in'].includes(data.state);
    $('aws-manual-sign-in').hidden = !data.verificationUrl;
    if (data.verificationUrl) $('aws-verification-url').href = data.verificationUrl; else $('aws-verification-url').removeAttribute('href');
    if (active) { clearTimeout(timer); timer = setTimeout(poll, 1500); }
  }
  function fill(data) {
    available = data.available === true; cliAvailable = data.cliAvailable === true;
    if (!available) { $('aws-error').textContent = 'Use Threatlint Desktop for local AWS browser sign-in.'; render(data); return; }
    fields = data.fields || [];
    $('aws-references-summary').textContent = `Parameter references · ${Object.values(data.settings.parameters).filter(Boolean).length} configured`;
    $('aws-profile').value = data.settings.profile; $('aws-region').value = data.settings.region; $('aws-auto-load').checked = data.settings.autoLoad;
    $('aws-profiles').replaceChildren(...(data.profiles || []).map(name => Object.assign(document.createElement('option'), { value: name })));
    $('aws-browser').replaceChildren(Object.assign(document.createElement('option'), { value: 'auto', textContent: 'Choose an installed browser automatically' }),
      ...(data.browsers || []).map(browser => Object.assign(document.createElement('option'), { value: browser.id, textContent: browser.label })));
    $('aws-parameter-bindings').replaceChildren();
    for (const field of fields) {
      const label = Object.assign(document.createElement('label'), { htmlFor: `aws-binding-${field.key}`, textContent: field.label });
      const input = Object.assign(document.createElement('input'), { id: label.htmlFor, value: data.settings.parameters[field.key] || '', placeholder: '/your-team/parameter-name', autocomplete: 'off', spellcheck: false, maxLength: 2048 });
      $('aws-parameter-bindings').append(label, input);
    }
    $('aws-error').textContent = cliAvailable ? '' : 'Install AWS CLI v2 and restart Threatlint to sign in and load parameters.';
    render(data);
  }
  async function initialize() {
    if (initialized) return;
    initialized = true;
    try { const data = await api('/api/aws/settings'); fill(data); if (data.state === 'ready') credentialsLoaded(data); } catch (error) { initialized = false; $('aws-error').textContent = error.message; }
  }
  async function save() {
    return api('/api/aws/settings', 'PUT', { profile: $('aws-profile').value.trim(), region: $('aws-region').value.trim(), autoLoad: $('aws-auto-load').checked,
      parameters: Object.fromEntries(fields.map(field => [field.key, $(`aws-binding-${field.key}`).value.trim()])) });
  }
  async function poll() {
    try {
      const data = await api('/api/aws/login'); render(data);
      if (data.state === 'ready') credentialsLoaded(data);
      if (data.state === 'failed') $('aws-error').textContent = data.message;
    } catch (error) { $('aws-error').textContent = error.message; }
  }
  function credentialsLoaded(data) { document.dispatchEvent(new CustomEvent('threatlint:credentials-loaded', { detail: { keys: data.loadedKeys || [] } })); }
  async function action(kind) {
    if (requestBusy) return;
    $('aws-error').textContent = ''; requestBusy = true;
    try {
      const saved = await save(); render(kind === 'login' ? { state: 'starting', message: 'Opening private AWS sign-in…' } : kind === 'load' ? { state: 'loading', message: 'Loading configured parameters with your AWS session…' } : saved);
      const data = kind === 'login' ? await api('/api/aws/login', 'POST', { browser: $('aws-browser').value, startUrl: $('aws-start-url').value.trim(),
        ssoRegion: $('aws-sso-region').value.trim(), accountId: $('aws-account-id').value.trim(), role: $('aws-role').value.trim() })
        : kind === 'load' ? await api('/api/aws/parameters/load', 'POST') : saved;
      requestBusy = false; render(data);
      if (data.state === 'ready') credentialsLoaded(data);
    } catch (error) { clearTimeout(timer); requestBusy = false; render({ state: 'failed', message: error.message }); $('aws-error').textContent = error.message; }
  }
  $('aws-parameters-form').addEventListener('submit', event => { event.preventDefault(); void action('save'); });
  $('aws-load').addEventListener('click', () => { void action('load'); });
  $('aws-sign-in').addEventListener('click', () => { void action('login'); });
  $('aws-cancel').addEventListener('click', async () => { clearTimeout(timer); try { render(await api('/api/aws/login', 'DELETE')); } catch (error) { $('aws-error').textContent = error.message; } });
  $('aws-verification-url').addEventListener('click', event => { event.preventDefault(); void navigator.clipboard.writeText($('aws-verification-url').href).then(() => { $('aws-status').textContent = 'Link copied. Paste it into a private browser window, then finish AWS sign-in.'; }).catch(() => { $('aws-status').textContent = 'Use the link’s context menu to copy its address into a private browser window.'; }); });
  document.addEventListener('threatlint:view', event => { if (event.detail.view === 'settings') void initialize(); });
  if (location.hash === '#settings') void initialize();
})();
