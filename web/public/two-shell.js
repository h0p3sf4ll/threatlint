'use strict';

/** 2Shell exposure: choose sources, repositories and branches, then follow a detect-2shell fleet scan. */
(() => {
  const $ = id => document.getElementById(id);
  const state = { sources: [], chosen: new Map(), page: 1, search: '', scanId: null, timer: null, loaded: false };
  const rank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const STATUS_LABEL = { vulnerable: 'Vulnerable', clean: 'Clean', 'not-applicable': 'Not applicable', error: 'Could not scan' };
  function node(tag, text, className) {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    return element;
  }
  async function request(url, body, { text = false } = {}) {
    if (window.ThreatlintProfile) await window.ThreatlintProfile.ready;
    const response = await (window.ThreatlintProfile?.fetch || fetch)(url, body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (text && response.ok) return response.text();
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || 'The request could not be completed.');
    return result;
  }
  function status(message, kind = '') {
    const output = $('twoshell-status');
    output.textContent = message;
    output.classList.toggle('error', kind === 'error');
    output.classList.toggle('busy', kind === 'busy');
  }
  const radio = name => document.querySelector(`input[name="${name}"]:checked`)?.value;
  const selectedSources = () => [...document.querySelectorAll('#twoshell-sources input[type=checkbox]:checked')].map(input => input.value);
  const running = () => !!state.timer;

  function controls() {
    const sources = selectedSources();
    const named = radio('twoshell-branch-scope') === 'named';
    $('twoshell-branch-list').disabled = !named || running();
    const pickerOn = radio('twoshell-repo-scope') === 'selected';
    $('twoshell-picker').hidden = !pickerOn;
    const chosenCount = sources.reduce((total, id) => total + (state.chosen.get(id)?.size || 0), 0);
    $('twoshell-repo-count').textContent = pickerOn ? `${chosenCount} CHOSEN` : 'ALL';
    const branchesOk = !named || $('twoshell-branch-list').value.trim() !== '';
    const reposOk = !pickerOn || sources.every(id => state.chosen.get(id)?.size);
    $('twoshell-start').disabled = running() || !sources.length || !branchesOk || !reposOk;
    $('twoshell-cancel').hidden = !running();
    $('twoshell-all-sources').checked = state.sources.length > 0 && sources.length === state.sources.length;
  }

  function renderSources() {
    const list = $('twoshell-sources');
    const live = state.sources;
    if (!live.length) {
      const empty = node('li', 'No connected GitHub or Azure DevOps sources. ', 'operations-empty-note');
      const link = node('button', 'Connect a source →', 'text-button'); link.type = 'button';
      link.addEventListener('click', () => document.querySelector('#view-twoshell [data-go-view="sources"]')?.click());
      empty.append(link); list.replaceChildren(empty); return;
    }
    list.replaceChildren(...live.map(source => {
      const item = node('li');
      const label = node('label', undefined, 'checkbox-label');
      const input = node('input'); input.type = 'checkbox'; input.value = source.id; input.checked = true;
      input.addEventListener('change', () => { renderPickerSources(); controls(); });
      const copy = node('span'); copy.append(node('strong', source.label || source.account), node('small', ` · ${source.source || (source.provider === 'github' ? 'GitHub' : 'Azure DevOps')}`, 'subtle'));
      label.append(input, copy); item.append(label); return item;
    }));
    renderPickerSources();
  }

  function renderPickerSources() {
    const select = $('twoshell-picker-source');
    const previous = select.value;
    const ids = selectedSources();
    select.replaceChildren(...state.sources.filter(source => ids.includes(source.id)).map(source => {
      const option = node('option', source.label || source.account); option.value = source.id; return option;
    }));
    if (ids.includes(previous)) select.value = previous;
    if (select.value !== previous) { state.page = 1; void loadRepositories(true); }
  }

  async function loadSources() {
    try {
      const all = await request('/api/scm/connections');
      state.sources = (Array.isArray(all) ? all : []).filter(item => item.connected !== false && ['github', 'azure-devops'].includes(item.provider));
      renderSources(); state.loaded = true;
      if (!running()) status(state.sources.length ? `${state.sources.length} connected source${state.sources.length === 1 ? '' : 's'} ready. Choose what to scan.` : 'Connect a GitHub or Azure DevOps source to scan repositories.');
    } catch (error) { status(error.message, 'error'); }
    controls();
  }

  async function loadRepositories(reset) {
    const sourceId = $('twoshell-picker-source').value;
    const list = $('twoshell-repositories');
    if (!sourceId || $('twoshell-picker').hidden) return;
    if (reset) { state.page = 1; list.replaceChildren(node('li', 'Loading repositories…', 'operations-empty-note')); }
    try {
      const query = new URLSearchParams({ page: String(state.page) });
      if (state.search) query.set('search', state.search);
      const result = await request(`/api/scm/connections/${encodeURIComponent(sourceId)}/repositories?${query}`);
      if (reset) list.replaceChildren();
      const chosen = state.chosen.get(sourceId) || new Set();
      state.chosen.set(sourceId, chosen);
      for (const repository of result.repositories || []) {
        const item = node('li', undefined, 'scm-repository');
        const label = node('label', undefined, 'checkbox-label two-shell-repo');
        const input = node('input'); input.type = 'checkbox'; input.value = repository.fullName; input.checked = chosen.has(repository.fullName);
        input.addEventListener('change', () => { if (input.checked) chosen.add(repository.fullName); else chosen.delete(repository.fullName); controls(); });
        const copy = node('span', undefined, 'scm-repository-copy'); copy.append(node('strong', repository.fullName), node('small', repository.defaultBranch ? `default: ${repository.defaultBranch}` : 'no default branch'));
        label.append(input, copy); item.append(label); list.append(item);
      }
      if (!list.children.length) list.append(node('li', 'No repositories match.', 'operations-empty-note'));
      $('twoshell-more').hidden = !result.hasMore;
    } catch (error) { list.replaceChildren(node('li', error.message, 'operations-empty-note')); }
    controls();
  }

  function selection() {
    const branchScope = radio('twoshell-branch-scope');
    const branches = branchScope === 'named' ? $('twoshell-branch-list').value.split(',').map(item => item.trim()).filter(Boolean) : branchScope;
    const pick = radio('twoshell-repo-scope') === 'selected';
    return { connections: selectedSources().map(connectionId => ({ connectionId, repositories: pick ? [...(state.chosen.get(connectionId) || [])] : 'all', branches })) };
  }

  function tile(label, value, tone) {
    const card = node('div', undefined, `platform-coverage-card two-shell-tile${tone ? ` tone-${tone}` : ''}`);
    card.append(node('span', String(value ?? 0), 'two-shell-tile-value'), node('strong', label));
    return card;
  }

  function renderJob(job) {
    const progress = job.progress || {};
    const total = progress.total || job.summary?.targets || 0;
    $('twoshell-progress').max = Math.max(total, 1);
    $('twoshell-progress').value = Math.min(progress.done || 0, Math.max(total, 1));
    $('twoshell-progress-label').textContent = job.status === 'running'
      ? `${progress.done || 0} of ${total || '…'} repository branches scanned`
      : `${job.status === 'completed' ? 'Completed' : job.status === 'cancelled' ? 'Cancelled' : 'Failed'} · ${progress.done || 0} of ${total} repository branches`;
    const summary = job.summary || { vulnerable: progress.vulnerable, clean: progress.clean, notApplicable: progress.notApplicable, errors: progress.errors };
    $('twoshell-tiles').replaceChildren(tile('Vulnerable', summary.vulnerable, 'bad'), tile('Clean', summary.clean, 'good'),
      tile('Not applicable', summary.notApplicable), tile('Could not scan', summary.errors, summary.errors ? 'warn' : ''));
    const rows = $('twoshell-rows');
    const results = job.result?.results;
    if (results) {
      const sorted = [...results].sort((a, b) => {
        const order = { vulnerable: 0, error: 1, clean: 2, 'not-applicable': 3 };
        return (order[a.status] ?? 4) - (order[b.status] ?? 4) || worst(a) - worst(b) || String(a.repository).localeCompare(String(b.repository));
      });
      rows.replaceChildren(...(sorted.length ? sorted.slice(0, 2000).map(resultRow) : [emptyRow('No repository branches matched this selection.')]));
      if (sorted.length > 2000) rows.append(emptyRow(`Showing 2,000 of ${sorted.length} rows. Download the JSON or report for every result.`));
    } else if (job.recent?.length) {
      rows.replaceChildren(...[...job.recent].reverse().slice(0, 200).map(event => resultRow({ ...event, findings: [] })));
    } else rows.replaceChildren(emptyRow(job.status === 'running' ? 'Planning targets…' : (job.error || 'No results.')));
    const done = job.status === 'completed';
    $('twoshell-download-json').disabled = !done; $('twoshell-download-md').disabled = !done;
  }
  function worst(result) { return Math.min(...(result.findings || []).map(finding => rank[finding.severity] ?? 9), 9); }
  function emptyRow(message) { const row = node('tr'); const cell = node('td', message, 'subtle'); cell.colSpan = 5; row.append(cell); return row; }
  function resultRow(result) {
    const row = node('tr', undefined, `two-shell-row status-${result.status}`);
    const findings = [...(result.findings || [])].sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
    const top = findings[0];
    const repo = [result.project, result.repository].filter(Boolean).join(' / ') || result.repository || '—';
    const severity = node('td'); if (top) severity.append(node('span', top.severity, `severity-badge severity-${top.severity}`)); else severity.textContent = '—';
    const fix = node('td', top ? `${top.package}@${top.version} → ${top.fixedIn || 'move to a supported line'}` : (result.status === 'error' ? (result.error || 'Could not be read') : '—'));
    if (findings.length > 1) fix.append(node('small', ` +${findings.length - 1} more`, 'subtle'));
    row.append(node('td', `${result.provider === 'azure-devops' ? 'Azure DevOps' : 'GitHub'} · ${repo}`), node('td', result.branch || '—'),
      node('td', STATUS_LABEL[result.status] || result.status), severity, fix);
    return row;
  }

  async function poll() {
    if (!state.scanId) return;
    try {
      const job = await request(`/api/detect-2shell/scans/${encodeURIComponent(state.scanId)}`);
      renderJob(job);
      if (job.status === 'running') { status(`Scanning… ${job.progress.done} of ${job.progress.total || '…'} repository branches.`, 'busy'); return; }
      clearInterval(state.timer); state.timer = null;
      if (job.status === 'completed') {
        const s = job.summary || {};
        status(s.vulnerable ? `${s.vulnerable} repository branch${s.vulnerable === 1 ? '' : 'es'} need${s.vulnerable === 1 ? 's' : ''} an upgrade. Highest severity: ${job.topSeverity || 'see results'}.`
          : s.errors ? `No affected versions found, but ${s.errors} branch${s.errors === 1 ? '' : 'es'} could not be scanned. This is not a clean result.`
            : 'No React2Shell-affected versions found in the scanned branches.', s.vulnerable ? 'error' : '');
      } else status(job.error || `Scan ${job.status}.`, 'error');
    } catch (error) { clearInterval(state.timer); state.timer = null; status(error.message, 'error'); }
    controls();
  }

  async function start(event) {
    event.preventDefault();
    if ($('twoshell-start').disabled) return;
    try {
      status('Starting detect-2shell…', 'busy');
      const { id } = await request('/api/detect-2shell/scans', selection());
      state.scanId = id;
      clearInterval(state.timer); state.timer = setInterval(() => void poll(), 1500);
      controls(); await poll();
    } catch (error) { status(error.message, 'error'); controls(); }
  }

  async function download(format) {
    if (!state.scanId) return;
    try {
      const body = await request(`/api/detect-2shell/scans/${encodeURIComponent(state.scanId)}/report?format=${format}`, undefined, { text: true });
      const url = URL.createObjectURL(new Blob([body], { type: format === 'json' ? 'application/json' : 'text/markdown' }));
      const link = node('a'); link.href = url; link.download = `detect-2shell-${state.scanId}.${format === 'json' ? 'json' : 'md'}`;
      document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    } catch (error) { status(error.message, 'error'); }
  }

  async function resume() {
    try {
      const jobs = await request('/api/detect-2shell/scans');
      const latest = Array.isArray(jobs) ? jobs[0] : null;
      if (!latest || state.scanId) return;
      state.scanId = latest.id;
      if (latest.status === 'running') { clearInterval(state.timer); state.timer = setInterval(() => void poll(), 1500); }
      await poll();
    } catch { /* No retained scans yet. */ }
  }

  function init() {
    if (!$('view-twoshell')) return;
    $('twoshell-form').addEventListener('submit', start);
    $('twoshell-refresh').addEventListener('click', () => void loadSources());
    $('twoshell-all-sources').addEventListener('change', event => {
      for (const input of document.querySelectorAll('#twoshell-sources input[type=checkbox]')) input.checked = event.target.checked;
      renderPickerSources(); controls();
    });
    for (const input of document.querySelectorAll('input[name="twoshell-repo-scope"]')) input.addEventListener('change', () => { controls(); if (!$('twoshell-picker').hidden) void loadRepositories(true); });
    for (const input of document.querySelectorAll('input[name="twoshell-branch-scope"]')) input.addEventListener('change', controls);
    $('twoshell-branch-list').addEventListener('input', controls);
    $('twoshell-picker-source').addEventListener('change', () => void loadRepositories(true));
    $('twoshell-search-button').addEventListener('click', () => { state.search = $('twoshell-search').value.trim(); void loadRepositories(true); });
    $('twoshell-search').addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); state.search = event.target.value.trim(); void loadRepositories(true); } });
    $('twoshell-more').addEventListener('click', () => { state.page += 1; void loadRepositories(false); });
    $('twoshell-cancel').addEventListener('click', async () => {
      if (!state.scanId) return;
      try { await request(`/api/detect-2shell/scans/${encodeURIComponent(state.scanId)}/cancel`, {}); status('Cancelling…', 'busy'); } catch (error) { status(error.message, 'error'); }
    });
    $('twoshell-download-json').addEventListener('click', () => void download('json'));
    $('twoshell-download-md').addEventListener('click', () => void download('markdown'));
    document.addEventListener('threatlint:view', event => { if (event.detail.view === 'twoshell') { void loadSources(); void resume(); } });
    if (location.hash === '#twoshell') { void loadSources(); void resume(); }
    controls();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
