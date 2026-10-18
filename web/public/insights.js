'use strict';

// Metrics dashboards, the Learn library, and inline help. Independent of app.js state;
// navigation requests go through the threatlint:navigate event.
(() => {
  const $ = id => document.getElementById(id);
  const Charts = () => window.ThreatlintCharts;
  const CHART_LABELS = { kpi: 'Stat tile', bar: 'Column chart', hbar: 'Bar chart', line: 'Line over time', donut: 'Donut', table: 'Table', heatmap: 'Heatmap' };
  const DIMENSION_LABELS = { severity: 'Severity', agent: 'Specialist', category: 'Discipline', workspace: 'Workspace', day: 'Day', week: 'Week', disposition: 'Disposition', confidence: 'Confidence', source: 'Source', rule: 'Finding type' };
  const state = { schema: null, dashboards: [], current: 'default', editing: null, help: null, loaded: false };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = String(text);
    return node;
  }
  function button(label, className, action, accessible) {
    const node = el('button', className, label); node.type = 'button';
    if (accessible) node.setAttribute('aria-label', accessible);
    node.addEventListener('click', action); return node;
  }
  async function api(url, options = {}) {
    const response = await fetch(url, { cache: 'no-store', ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
    if (response.status === 204) return null;
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
    return payload;
  }
  function select(options, value, label) {
    const node = el('select'); node.setAttribute('aria-label', label);
    for (const [key, caption] of options) { const option = el('option', '', caption); option.value = key; node.append(option); }
    node.value = value ?? options[0][0];
    return node;
  }

  // ── Tooltips ───────────────────────────────────────────────────────────────
  function installTips(tooltips) {
    const popover = $('tip-popover');
    for (const anchor of document.querySelectorAll('[data-tip]')) {
      const text = tooltips[anchor.dataset.tip];
      if (!text || anchor.dataset.tipReady) continue;
      anchor.dataset.tipReady = 'true';
      const trigger = el('button', 'tip-trigger', '?'); trigger.type = 'button';
      trigger.setAttribute('aria-label', `Help: ${text}`);
      const show = () => {
        popover.textContent = text; popover.hidden = false;
        const rect = trigger.getBoundingClientRect();
        popover.style.left = `${Math.max(8, Math.min(window.innerWidth - 300, rect.left - 8))}px`;
        popover.style.top = `${rect.bottom + 8}px`;
      };
      const hide = () => { popover.hidden = true; };
      trigger.addEventListener('mouseenter', show); trigger.addEventListener('focus', show);
      trigger.addEventListener('mouseleave', hide); trigger.addEventListener('blur', hide);
      trigger.addEventListener('click', event => { event.preventDefault(); event.stopPropagation(); popover.hidden ? show() : hide(); });
      anchor.append(trigger);
    }
    document.addEventListener('keydown', event => { if (event.key === 'Escape') popover.hidden = true; });
  }

  // ── Learn view ─────────────────────────────────────────────────────────────
  function playVideo(video) {
    $('video-title').textContent = video.title;
    const player = $('video-player');
    player.hidden = !video.available; $('video-missing').hidden = video.available;
    if (video.available) { player.src = `/media/${video.file}`; player.poster = `/media/${video.poster}`; }
    else player.removeAttribute('src');
    $('video-dialog').showModal();
    if (video.available) player.play().catch(() => {});
  }
  function renderLearn() {
    const { topics, videos, tooltips } = state.help;
    const grid = $('video-grid'); grid.replaceChildren();
    for (const video of videos) {
      const card = button('', 'video-card', () => playVideo(video), `Play video: ${video.title}`);
      const thumb = el('span', `video-thumb${video.available ? '' : ' missing'}`);
      if (video.available) { const image = el('img'); image.src = `/media/${video.poster}`; image.alt = ''; image.loading = 'lazy'; thumb.append(image); }
      thumb.append(el('span', 'video-play', '▶'));
      card.append(thumb, el('strong', '', video.title), el('small', '', video.available ? 'Narrated · plays offline' : 'Not rendered yet · see guide'));
      grid.append(card);
    }
    const list = $('help-topics'); list.replaceChildren();
    for (const topic of topics) {
      const card = el('article', 'help-topic'); card.id = `help-${topic.id}`;
      const head = el('div', 'help-topic-head');
      head.append(el('h3', '', topic.title), el('span', 'tag', `${topic.minutes} MIN`));
      const steps = el('ol');
      for (const step of topic.steps) {
        const item = el('li');
        // Inline code in guide text renders as <code> without HTML parsing.
        for (const [index, part] of step.split('`').entries()) item.append(index % 2 ? el('code', '', part) : document.createTextNode(part));
        steps.append(item);
      }
      card.append(head, steps);
      const video = videos.find(item => item.id === topic.video);
      if (video) card.append(button('▷ Watch the walkthrough', 'text-button', () => playVideo(video)));
      list.append(card);
    }
    const glossary = $('help-glossary'); glossary.replaceChildren();
    for (const key of ['severity', 'confidence', 'metrics-kpi', 'evidence-coverage', 'runtime-chain', 'pipeline']) {
      glossary.append(el('dt', '', key.replace('metrics-kpi', 'risk score').replaceAll('-', ' ')), el('dd', '', tooltips[key]));
    }
  }
  function openTopic(id) {
    document.dispatchEvent(new CustomEvent('threatlint:navigate', { detail: { view: 'learn' } }));
    requestAnimationFrame(() => { const node = $(`help-${id}`); node?.scrollIntoView({ block: 'start' }); node?.classList.add('highlight'); setTimeout(() => node?.classList.remove('highlight'), 1600); });
  }

  // ── Metrics and dashboards ────────────────────────────────────────────────
  function rangeFilter() {
    const days = Number($('metrics-range').value);
    return days ? { since: new Date(Date.now() - days * 86_400_000).toISOString() } : {};
  }
  function dashboard() { return state.dashboards.find(item => item.id === state.current) || state.dashboards[0]; }
  function renderDashboardSelect() {
    const node = $('dashboard-select'); node.replaceChildren();
    for (const item of state.dashboards) { const option = el('option', '', item.builtIn ? `${item.name} · built-in` : item.name); option.value = item.id; node.append(option); }
    node.value = state.current;
    $('dashboard-edit').textContent = dashboard()?.builtIn ? 'Customize' : 'Edit layout';
  }
  async function renderDashboard() {
    const current = dashboard();
    const grid = $('dashboard-grid'); grid.replaceChildren();
    if (!current) return;
    const tooltip = $('chart-tooltip');
    await Promise.all(current.widgets.map(async widget => {
      const card = el('section', `panel dashboard-widget size-${widget.size || 2}${widget.chart === 'kpi' ? ' is-kpi' : ''}`);
      const head = el('div', 'widget-head');
      head.append(el('h3', '', widget.title));
      const body = el('div', 'widget-body');
      card.append(head, body); grid.append(card);
      try {
        const data = await api('/api/metrics/query', { method: 'POST', body: JSON.stringify({ chart: widget.chart, metric: widget.metric, groupBy: widget.groupBy, columns: widget.columns, filters: { ...widget.filters, ...rangeFilter() } }) });
        Charts().render(body, widget.chart, data, { metric: widget.metric, tooltip });
        if (!['kpi', 'table', 'heatmap'].includes(widget.chart)) {
          let tabular = false;
          head.append(button('Table', 'text-button widget-toggle', event => {
            tabular = !tabular; event.currentTarget.textContent = tabular ? 'Chart' : 'Table';
            body.replaceChildren(); if (tabular) Charts().table(body, data, { metric: widget.metric }); else Charts().render(body, widget.chart, data, { metric: widget.metric, tooltip });
          }, `Toggle table view for ${widget.title}`));
        }
      } catch (error) { body.append(el('p', 'chart-empty', error.message)); }
    }));
  }
  async function loadMetrics() {
    try {
      [state.schema, state.dashboards] = await Promise.all([state.schema || api('/api/metrics/schema'), api('/api/dashboards')]);
      if (!state.dashboards.some(item => item.id === state.current)) state.current = 'default';
      renderDashboardSelect(); await renderDashboard();
    } catch (error) { $('dashboard-grid').replaceChildren(el('p', 'chart-empty', `Metrics unavailable: ${error.message}`)); }
  }

  function widgetRow(widget, index) {
    const row = el('li', 'widget-row');
    const title = el('input'); title.value = widget.title; title.maxLength = 80; title.setAttribute('aria-label', `Widget ${index + 1} title`);
    const chart = select(state.schema.charts.map(key => [key, CHART_LABELS[key] || key]), widget.chart, `Widget ${index + 1} chart`);
    const metric = select(state.schema.metrics.map(key => [key, Charts().LABELS[key] || key]), widget.metric, `Widget ${index + 1} metric`);
    const dimensions = state.schema.dimensions.map(key => [key, DIMENSION_LABELS[key] || key]);
    const groupBy = select(dimensions, widget.groupBy || 'severity', `Widget ${index + 1} group by`);
    const columns = select(dimensions, widget.columns || 'severity', `Widget ${index + 1} heatmap columns`);
    const size = select([['1', 'Small'], ['2', 'Medium'], ['4', 'Full width']], String(widget.size || 2), `Widget ${index + 1} size`);
    const severity = select([['', 'Any severity'], ...['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(key => [key, key])], widget.filters?.severity || '', `Widget ${index + 1} severity filter`);
    const sync = () => { groupBy.disabled = chart.value === 'kpi'; columns.hidden = chart.value !== 'heatmap'; };
    chart.addEventListener('change', sync); sync();
    const field = (label, control) => { const wrap = el('label', 'widget-field'); wrap.append(el('span', 'micro subtle', label), control); return wrap; };
    const controls = el('div', 'widget-controls');
    controls.append(field('TITLE', title), field('CHART', chart), field('METRIC', metric), field('GROUP BY', groupBy), field('COLUMNS', columns), field('SIZE', size), field('FILTER', severity));
    const actions = el('div', 'widget-row-actions');
    const move = direction => { const widgets = state.editing.widgets; const other = index + direction; if (other < 0 || other >= widgets.length) return; collect(); [widgets[index], widgets[other]] = [widgets[other], widgets[index]]; renderEditor(); };
    actions.append(button('↑', 'icon-button', () => move(-1), `Move widget ${index + 1} up`), button('↓', 'icon-button', () => move(1), `Move widget ${index + 1} down`),
      button('×', 'icon-button', () => { collect(); state.editing.widgets.splice(index, 1); renderEditor(); }, `Remove widget ${index + 1}`));
    row.append(el('span', 'pipeline-number', String(index + 1).padStart(2, '0')), controls, actions);
    row.collect = () => ({ id: widget.id, title: title.value, chart: chart.value, metric: metric.value, groupBy: chart.value === 'kpi' ? null : groupBy.value,
      ...(chart.value === 'heatmap' ? { columns: columns.value } : {}), size: Number(size.value), filters: severity.value ? { severity: severity.value } : {} });
    return row;
  }
  function collect() { state.editing.name = $('dashboard-name').value; state.editing.widgets = [...$('widget-editor').children].map(row => row.collect()); }
  function renderEditor() {
    $('dashboard-name').value = state.editing.name;
    $('widget-editor').replaceChildren(...state.editing.widgets.map(widgetRow));
    $('dashboard-delete').hidden = !state.editing.id;
    $('dashboard-error').textContent = '';
  }
  function openEditor(source, asCopy) {
    state.editing = { id: asCopy ? null : source?.id || null, name: asCopy ? `${source.name} (copy)` : source?.name || 'My dashboard', widgets: structuredClone(source?.widgets || []) };
    $('dashboard-editor').hidden = false; renderEditor(); $('dashboard-name').focus();
  }
  async function saveEditor() {
    collect();
    try {
      const body = JSON.stringify({ name: state.editing.name, widgets: state.editing.widgets });
      const saved = state.editing.id ? await api(`/api/dashboards/${encodeURIComponent(state.editing.id)}`, { method: 'PUT', body }) : await api('/api/dashboards', { method: 'POST', body });
      state.current = saved.id; $('dashboard-editor').hidden = true; state.editing = null;
      await loadMetrics();
    } catch (error) { $('dashboard-error').textContent = error.message; }
  }

  async function initialize() {
    if (!$('view-metrics')) return;
    $('dashboard-select').addEventListener('change', event => { state.current = event.target.value; renderDashboardSelect(); renderDashboard(); });
    $('metrics-range').addEventListener('change', renderDashboard);
    $('dashboard-new').addEventListener('click', () => openEditor({ name: 'My dashboard', widgets: [{ id: 'w1', title: 'Findings by severity', chart: 'bar', metric: 'findings', groupBy: 'severity', size: 2 }] }, false));
    $('dashboard-duplicate').addEventListener('click', () => openEditor(dashboard(), true));
    $('dashboard-edit').addEventListener('click', () => { const current = dashboard(); openEditor(current, !!current.builtIn); });
    $('dashboard-cancel').addEventListener('click', () => { $('dashboard-editor').hidden = true; state.editing = null; });
    $('dashboard-save').addEventListener('click', saveEditor);
    $('dashboard-delete').addEventListener('click', async () => {
      if (!state.editing?.id) return;
      await api(`/api/dashboards/${encodeURIComponent(state.editing.id)}`, { method: 'DELETE' });
      state.current = 'default'; $('dashboard-editor').hidden = true; await loadMetrics();
    });
    $('widget-add').addEventListener('click', () => { collect(); state.editing.widgets.push({ id: `w${Date.now().toString(36)}`, title: 'New widget', chart: 'hbar', metric: 'findings', groupBy: 'agent', size: 2 }); renderEditor(); });
    $('open-help').addEventListener('click', () => document.dispatchEvent(new CustomEvent('threatlint:navigate', { detail: { view: 'learn' } })));
    for (const node of document.querySelectorAll('[data-help-topic]')) node.addEventListener('click', () => openTopic(node.dataset.helpTopic));
    $('video-dialog').addEventListener('close', () => $('video-player').pause());
    document.addEventListener('keydown', event => {
      if (event.key === '?' && !/input|textarea|select/i.test(document.activeElement?.tagName || '') && !document.querySelector('dialog[open]')) openTopic('first-review');
    });
    document.addEventListener('threatlint:view', event => {
      if (event.detail.view === 'metrics') loadMetrics();
    });
    try {
      state.help = await api('/api/help');
      installTips(state.help.tooltips); renderLearn();
    } catch { /* Help is optional; the workbench remains usable. */ }
    if (!$('view-metrics').hidden) loadMetrics();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize, { once: true });
  else initialize();
})();
