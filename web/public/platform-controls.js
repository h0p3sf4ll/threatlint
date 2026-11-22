'use strict';

/** Review-builder controls. Provider secrets stay in live form fields and request memory. */
(function (root) {
  const counts = new Map();
  let controlsLocked = false;
  let experienceReady = false;
  let experienceSaving = false;
  function integer(value, fallback, maximum) {
    const result = value === undefined || value === '' ? fallback : Number(value);
    if (!Number.isInteger(result) || result < 1 || result > maximum) throw new Error(`Choose a whole number from 1 to ${maximum}.`);
    return result;
  }
  function participant(id, values) {
    const { provider, model = '', key = '', url = '', region = '', consent } = values;
    if (!consent) throw new Error(`Authorize context sharing with the ${id} provider first.`);
    if (!['openai', 'claude', 'codex', 'claude-code', 'lmstudio', 'bedrock'].includes(provider)) throw new Error('Choose a supported independent provider.');
    if (!model.trim() && !['codex', 'claude-code'].includes(provider)) throw new Error(`Choose an explicit model for the ${id} provider.`);
    const settings = { provider, model: model.trim() };
    if (provider === 'openai') settings.openaiApiKey = key;
    if (provider === 'claude') settings.apiKey = key;
    if (provider === 'bedrock') { settings.bedrockApiKey = key; settings.bedrockRegion = region.trim(); }
    if (provider === 'lmstudio') { settings.lmstudioUrl = url.trim(); settings.lmstudioModel = model.trim(); }
    return { id, consent: true, settings };
  }
  function buildEnsemble(primarySettings, others, consent) {
    if (!consent) throw new Error('Authorize the independent model review before starting.');
    const participants = [{ id: 'primary', consent: true, settings: { ...primarySettings } }, ...others];
    if (participants.length < 2 || participants.length > 3) throw new Error('Choose two or three independent providers.');
    if (new Set(participants.map(p => p.settings.provider)).size !== participants.length) throw new Error('Choose different providers for each participant.');
    return { enabled: true, consent: true, participants, challengeRounds: 1 };
  }
  function doc() { return root.document; }
  function advanced() { return doc()?.getElementById('experience-mode')?.value === 'advanced'; }
  function values(fieldset) {
    const result = {};
    for (const input of fieldset.querySelectorAll('[data-field]')) result[input.dataset.field] = input.type === 'checkbox' ? input.checked : input.value;
    return result;
  }
  function reviewOptions({ primarySettings, agentIds }) {
    const d = doc();
    const execution = { mode: d.getElementById('pipeline-execution-mode').value,
      maxConcurrency: integer(d.getElementById('pipeline-concurrency').value, 3, 8),
      maxModelRuns: integer(d.getElementById('pipeline-model-budget').value, 24, 64),
      roleWorkerCounts: Object.fromEntries(agentIds.map(id => [id, advanced() ? counts.get(id) || 1 : 1])) };
    let ensemble;
    if (advanced() && d.getElementById('ensemble-enabled').checked) {
      const ids = d.getElementById('ensemble-third-enabled').checked ? ['second', 'third'] : ['second'];
      ensemble = buildEnsemble(primarySettings, ids.map(id => participant(id, values(d.querySelector(`[data-participant="${id}"]`)))), d.getElementById('ensemble-consent').checked);
    }
    return { execution, ...(ensemble ? { ensemble } : {}) };
  }
  function workerControl(agent, disabled) {
    const label = doc().createElement('label'); label.className = 'role-workers advanced-only';
    label.append(doc().createTextNode('Workers'));
    const input = doc().createElement('input'); input.type = 'number'; input.min = '1'; input.max = '4'; input.step = '1'; input.value = counts.get(agent.id) || 1;
    input.setAttribute('aria-label', `${agent.label || agent.id} workers`);
    input.disabled = disabled || agent.contract?.evidenceMode === 'upstream';
    input.title = input.disabled && !disabled ? 'Synthesis uses one worker to keep evidence together.' : 'Divide primary source files across up to four workers.';
    input.addEventListener('change', () => { try { counts.set(agent.id, integer(input.value, 1, 4)); } catch { input.value = counts.get(agent.id) || 1; } });
    label.append(input); return label;
  }
  function batchControls(prefix) {
    const box = doc().createElement('fieldset'); box.className = 'advanced-only scanimport-fields'; box.dataset.batchControls = prefix;
    const legend = doc().createElement('legend'); legend.textContent = 'Parallel review and budget'; box.append(legend);
    for (const [key, title, value, max] of [['maxConcurrency', 'Parallel reviewers', 3, 8], ['maxModelRuns', 'Maximum model runs', 64, 64]]) {
      const label = doc().createElement('label'); label.textContent = title;
      const input = doc().createElement('input'); input.type = 'number'; input.min = '1'; input.max = String(max); input.step = '1'; input.value = String(value);
      input.id = `${prefix}-${key}`; label.htmlFor = input.id; label.append(input); box.append(label);
    }
    return box;
  }
  function batchOptions(prefix) {
    if (!advanced()) return { maxModelRuns: 64 };
    return { maxConcurrency: integer(doc()?.getElementById(`${prefix}-maxConcurrency`)?.value, 3, 8),
      maxModelRuns: integer(doc()?.getElementById(`${prefix}-maxModelRuns`)?.value, 64, 64) };
  }
  function setLocked(locked) {
    controlsLocked = locked;
    for (const input of doc()?.querySelectorAll('#orchestration-options input, #orchestration-options select') || []) input.disabled = locked;
    lockExperience();
  }
  function lockExperience() {
    const mode = doc()?.getElementById('experience-mode');
    if (mode) mode.disabled = controlsLocked || !experienceReady || experienceSaving;
  }
  async function init() {
    const d = doc(); if (!d) return;
    const mode = d.getElementById('experience-mode'); if (!mode) return;
    const status = d.getElementById('experience-status');
    function message(text) { if (status) status.textContent = text; mode.title = text; }
    function experience(value) {
      mode.value = value;
      d.body.dataset.experience = mode.value;
      if (!advanced()) d.getElementById('ensemble-enabled').checked = false;
      d.getElementById('ensemble-options').hidden = !d.getElementById('ensemble-enabled').checked;
    }
    experience('guided'); lockExperience();
    try { await root.ThreatlintProfile?.ready; } catch { message('Experience could not be loaded. Reload to try again.'); return; }
    const profile = root.ThreatlintProfile;
    const profileId = profile?.web ? profile.user?.id : null;
    const current = () => root.ThreatlintProfile === profile && (profile?.web ? profile.user?.id === profileId : profileId === null);
    const preferences = profile?.storage || root.localStorage;
    const valid = value => value === 'guided' || value === 'advanced';
    let saved = 'guided';
    async function request(method = 'GET', value) {
      if (!current()) throw new Error('Profile changed.');
      const response = await (profile?.fetch || root.fetch)('/api/ui-preferences', { method, cache: 'no-store', credentials: 'same-origin',
        ...(value === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ experience: value }) }) });
      if (!current() || !response.ok) throw new Error('Experience request failed.');
      const data = await response.json();
      if (!current() || !data || !Object.hasOwn(data, 'preferences') || (data.preferences !== null
          && (typeof data.preferences !== 'object' || Object.keys(data.preferences).length !== 1 || !valid(data.preferences.experience)))
          || (method !== 'GET' && data.preferences === null)) throw new Error('Invalid Experience response.');
      return data.preferences;
    }
    function cache() { try { preferences?.setItem('threatlint.experience', saved); } catch { /* The durable preference remains available. */ } }
    mode.addEventListener('change', async () => {
      if (!current() || !experienceReady || experienceSaving) return;
      const selected = mode.value;
      if (!valid(selected)) { experience(saved); return; }
      experience(selected); experienceSaving = true; lockExperience(); message('');
      try {
        const value = await request('PUT', selected);
        if (!current()) return;
        saved = value.experience; experience(saved); cache();
      } catch {
        if (current()) { experience(saved); message('Experience could not be saved. Try again.'); }
      } finally {
        if (current()) { experienceSaving = false; lockExperience(); }
      }
    });
    d.getElementById('ensemble-enabled').addEventListener('change', e => { d.getElementById('ensemble-options').hidden = !e.target.checked; });
    d.getElementById('ensemble-third-enabled').addEventListener('change', e => { d.getElementById('ensemble-third').hidden = !e.target.checked; });
    for (const fieldset of d.querySelectorAll('.ensemble-participant')) {
      function providerFields() {
        const provider = fieldset.querySelector('[data-field="provider"]').value;
        for (const [name, visible] of [['key', ['openai', 'claude', 'bedrock'].includes(provider)], ['url', provider === 'lmstudio'], ['region', provider === 'bedrock']]) {
          fieldset.querySelector(`[data-field="${name}"]`).closest('label').hidden = !visible;
        }
        fieldset.querySelector('[data-field="model"]').placeholder = ['codex', 'claude-code'].includes(provider) ? 'Optional · native CLI default' : 'Explicit model ID';
      }
      fieldset.addEventListener('input', event => {
        if (event.target.dataset.field !== 'consent') { fieldset.querySelector('[data-field="consent"]').checked = false; d.getElementById('ensemble-consent').checked = false; }
        if (event.target.dataset.field === 'provider') { fieldset.querySelector('[data-field="key"]').value = ''; providerFields(); }
      });
      providerFields();
    }
    try {
      let value = await request();
      if (!current()) return;
      if (value === null) {
        let legacy;
        try { legacy = preferences?.getItem('threatlint.experience'); } catch { /* Optional migration only. */ }
        if (valid(legacy)) value = await request('PUT', legacy);
      }
      if (!current()) return;
      saved = value?.experience || 'guided'; experience(saved);
      if (value !== null) cache();
      experienceReady = true; lockExperience();
    } catch {
      if (current()) message('Experience could not be loaded. Reload to try again.');
    }
  }
  const api = { integer, participant, buildEnsemble, reviewOptions, workerControl, batchControls, batchOptions, setLocked };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.ThreatlintPlatformControls = api; init();
})(typeof window === 'undefined' ? globalThis : window);
