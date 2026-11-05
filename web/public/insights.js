'use strict';

// Metrics dashboards, the Learn library, and inline help. Independent of app.js state;
// navigation requests go through the threatlint:navigate event.
(() => {
  const $ = id => document.getElementById(id);
  const Charts = () => window.ThreatlintCharts;
  const CHART_LABELS = { kpi: 'Stat tile', bar: 'Column chart', hbar: 'Bar chart', line: 'Line over time', donut: 'Donut', table: 'Table', heatmap: 'Heatmap' };
  const DIMENSION_LABELS = { severity: 'Severity', agent: 'Specialist / tracker', category: 'Discipline', workspace: 'Workspace', day: 'Day', week: 'Week', disposition: 'Disposition', confidence: 'Confidence', source: 'Source', rule: 'Finding type' };
  const TRACKER_SETTINGS = { 'servicenow-avit': 'servicenow', defectdojo: 'defectdojo' };
  const AGGREGATE_FILTERS = ['scm', 'organization', 'project', 'repository', 'branch', 'findingType',
    'riskRating', 'state', 'substate', 'assignmentGroup', 'source', 'createdFrom', 'createdTo'];
  const state = { schema: null, dashboards: [], current: 'default', source: 'all', editing: null, help: null, loaded: false,
    avitScope: { type: 'avits', avits: '', query: '' }, avitScopeTouched: false,
    avitAggregate: null, aggregateDirty: false, avitConfigured: false };

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
  function sourceFilter() { return state.source === 'all' ? {} : { source: state.source }; }
  function syncDate(value) {
    if (!value) return 'Never synced';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Never synced' : `Last synced ${date.toLocaleString()}`;
  }
  function dateLabel(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'unknown time' : date.toLocaleString();
  }
  function savedAvitScope(scope) {
    if (scope?.type === 'avits') return { type: 'avits', avits: Array.isArray(scope.avits) ? scope.avits.join(', ') : String(scope.avits || ''), query: '' };
    if (scope?.type === 'query') return { type: 'query', avits: '', query: String(scope.query || '') };
    return null;
  }
  function currentAvitScope() {
    const { type, avits, query } = state.avitScope;
    if (type === 'avits') return avits.trim() ? { type, avits: avits.trim() } : null;
    return query.trim() ? { type: 'query', query: query.trim() } : null;
  }
  function aggregateFilters() {
    const form = $('avit-aggregate-form'); const filters = {};
    for (const key of AGGREGATE_FILTERS) {
      const value = form.elements.namedItem(key)?.value.trim();
      if (value) filters[key] = value;
    }
    if (filters.scm !== 'ado') delete filters.project;  // Project is an Azure DevOps-only field.
    return filters;
  }
  function syncScmFields() {
    const form = $('avit-aggregate-form');
    const show = (form.elements.namedItem('scm')?.value || '') === 'ado';
    $('avit-project-field').hidden = !show;
    if (!show && form.elements.namedItem('project')) form.elements.namedItem('project').value = '';
  }
  function updateAggregateNote() {
    const note = $('avit-aggregate-dirty');
    $('avit-aggregate-submit').disabled = !state.avitConfigured;
    note.textContent = !state.avitConfigured ? 'Configure ServiceNow in Settings to load or refresh this summary.'
      : state.aggregateDirty ? 'Filters changed. Load the summary to see updated counts.'
        : state.avitAggregate ? 'Showing the last completed ServiceNow summary.' : 'Leave fields blank to count all readable AVITs.';
  }
  function aggregateNumber(value) { return Number.isFinite(value) && value >= 0 ? value.toLocaleString() : 'Unavailable'; }
  function aggregateBreakdown(title, values) {
    const panel = el('div', 'avit-aggregate-breakdown-card'); panel.append(el('h3', '', title));
    if (!Array.isArray(values)) { panel.append(el('p', 'small subtle', 'Unavailable with current ServiceNow permissions.')); return panel; }
    if (!values.length) { panel.append(el('p', 'small subtle', 'No matching AVITs.')); return panel; }
    const table = el('table'); const head = el('thead'); const header = el('tr');
    header.append(el('th', '', 'Value'), el('th', '', 'AVITs')); head.append(header);
    const body = el('tbody');
    for (const row of values) { const tr = el('tr'); tr.append(el('td', '', row.key || '(blank)'), el('td', '', aggregateNumber(row.count))); body.append(tr); }
    table.append(head, body); panel.append(table); return panel;
  }
  const FILTER_LABELS = { scm: 'Source code manager', organization: 'Organization', project: 'Project', repository: 'Repository',
    branch: 'Branch', findingType: 'Finding type', riskRating: 'Risk rating', state: 'State', substate: 'Substate',
    assignmentGroup: 'Assignment group', source: 'Finding source', createdFrom: 'Created from', createdTo: 'Created to' };
  const FILTER_VALUE_LABELS = {
    scm: { github: 'GitHub Enterprise', ado: 'Azure DevOps' },
    findingType: { sast: 'Static (SAST)', sca: 'SCA', secrets: 'Secret' },
    riskRating: { 1: 'Critical', 2: 'High', 3: 'Medium', 4: 'Low', 5: 'None' },
    state: { 1: 'Open', 3: 'Closed', 101: 'Resolved' },
  };
  const filterLabel = key => FILTER_LABELS[key] || key;
  const filterValueLabel = (key, value) => FILTER_VALUE_LABELS[key]?.[value] || value;
  function renderAggregate(summary) {
    state.avitAggregate = summary;
    const result = $('avit-aggregate-result'); result.replaceChildren();
    if (!summary) { result.append(el('p', 'small subtle', 'No AVIT summary loaded yet.')); updateAggregateNote(); return; }
    const applied = Object.entries(summary.filters || {}).filter(([, value]) => value !== '' && value != null);
    result.append(el('p', 'avit-aggregate-meta', `Last completed ${dateLabel(summary.asOf)} · ${applied.length ? `Filters: ${applied.map(([key, value]) => `${filterLabel(key)}: ${filterValueLabel(key, value)}`).join(' · ')}` : 'All readable AVITs'}`));
    const kpis = el('div', 'avit-aggregate-kpis');
    for (const [label, value] of [['Total AVITs', summary.total], ['Stored false-positive state', summary.falsePositive]]) {
      if (label === 'Stored false-positive state' && !Number.isFinite(value)) continue;
      const tile = el('div', 'avit-aggregate-kpi'); tile.append(el('strong', '', aggregateNumber(value)), el('span', '', label)); kpis.append(tile);
    }
    result.append(kpis);
    const breakdown = el('div', 'avit-aggregate-breakdown');
    breakdown.append(aggregateBreakdown('Risk rating', summary.riskRating), aggregateBreakdown('State', summary.state), aggregateBreakdown('Substate', summary.substate));
    result.append(breakdown);
    if (summary.limitations) result.append(el('p', 'small subtle', summary.limitations));
    updateAggregateNote();
  }
  function fillAggregateFilters(filters) {
    const form = $('avit-aggregate-form');
    for (const key of AGGREGATE_FILTERS) form.elements.namedItem(key).value = filters?.[key] || '';
    syncScmFields();
  }
  async function loadAggregate() {
    try {
      const payload = await api('/api/trackers/servicenow-avit/aggregate');
      const summary = Object.hasOwn(payload, 'summary') ? payload.summary : payload;
      if (summary && !state.aggregateDirty) fillAggregateFilters(summary.filters);
      renderAggregate(summary);
      $('avit-aggregate-error').textContent = '';
    } catch (error) { $('avit-aggregate-error').textContent = `AVIT summary unavailable: ${error.message}. The last loaded summary remains visible.`; }
  }
  async function submitAggregate(event) {
    event.preventDefault();
    const filters = aggregateFilters();
    if (filters.createdFrom && filters.createdTo && filters.createdFrom > filters.createdTo) {
      $('avit-aggregate-error').textContent = 'Created from must be on or before Created to.'; return;
    }
    const control = $('avit-aggregate-submit'); control.disabled = true; control.textContent = 'Loading…';
    $('avit-aggregate-error').textContent = '';
    try {
      const summary = await api('/api/trackers/servicenow-avit/aggregate', { method: 'POST', body: JSON.stringify({ filters }) });
      state.aggregateDirty = false; renderAggregate(summary);
    } catch (error) { $('avit-aggregate-error').textContent = `AVIT summary failed: ${error.message}. The previous summary remains visible.`; }
    finally { control.textContent = 'Load AVIT summary'; updateAggregateNote(); }
  }
  function openTrackerSettings(id) {
    const section = TRACKER_SETTINGS[id];
    document.querySelector(`.settings-nav a[href="#settings-${section}"]`)?.click();
  }
  function updateExportLink() {
    $('metrics-export').href = state.source === 'all' ? '/api/metrics/export' : `/api/metrics/export?source=${encodeURIComponent(state.source)}`;
  }
  function renderSources(sources) {
    const node = $('metrics-source'); node.replaceChildren();
    for (const source of sources) {
      if (!source?.id || source.available === false) continue;
      const option = el('option', '', source.label || source.id); option.value = source.id; node.append(option);
    }
    if (!node.options.length) { const option = el('option', '', 'All sources'); option.value = 'all'; node.append(option); }
    if (![...node.options].some(option => option.value === state.source)) state.source = 'all';
    node.value = state.source;
    updateExportLink();
  }
  function renderTrackers(trackers) {
    const cards = $('metrics-tracker-cards'); const others = $('metrics-other-tracker-list');
    cards.replaceChildren(); others.replaceChildren();
    for (const tracker of trackers) {
      if (!tracker?.id || !tracker.label) continue;
      if (!tracker.available || !Object.hasOwn(TRACKER_SETTINGS, tracker.id)) {
        const row = el('div', 'metrics-other-tracker');
        row.append(el('strong', '', tracker.label), el('span', 'small subtle', tracker.description || 'Metrics connection not available yet.'));
        others.append(row); continue;
      }
      const card = el('article', 'metrics-tracker-card');
      const heading = el('div', 'metrics-tracker-heading');
      heading.append(el('h3', '', tracker.label), el('span', `metrics-tracker-badge${tracker.connected ? ' connected' : ''}`, tracker.connected ? 'Configured' : 'Not configured'));
      const details = el('p', 'small subtle', `${Number(tracker.count || 0).toLocaleString()} saved findings · ${syncDate(tracker.lastSyncedAt)}`);
      if (tracker.id === 'servicenow-avit' && !state.avitScopeTouched) state.avitScope = savedAvitScope(tracker.scope) || { type: 'avits', avits: '', query: '' };
      if (tracker.id === 'servicenow-avit') { state.avitConfigured = !!tracker.connected; updateAggregateNote(); }
      const reconnect = tracker.connected ? null : el('p', 'small subtle', 'Configure in Settings to refresh this snapshot.');
      const actions = el('div', 'metrics-tracker-actions');
      const configure = button(tracker.connected ? 'Manage settings' : 'Configure in Settings', 'button secondary small-button', () => openTrackerSettings(tracker.id));
      const sync = button('Sync now', 'button primary small-button', () => syncTracker(tracker.id, sync));
      sync.disabled = !tracker.connected || (tracker.id === 'servicenow-avit' && !currentAvitScope());
      actions.append(configure, sync); card.append(heading, details);
      if (reconnect) card.append(reconnect);
      if (tracker.id === 'servicenow-avit') {
        const scope = el('div', 'metrics-avit-scope');
        const type = el('select'); type.id = 'metrics-avit-scope-type'; type.setAttribute('aria-label', 'ServiceNow AVIT sync scope');
        for (const [value, label] of [['avits', 'AVIT numbers'], ['query', 'Encoded query from a saved filter']]) {
          const option = el('option', '', label); option.value = value; type.append(option);
        }
        type.value = state.avitScope.type;
        const entry = el('textarea'); entry.id = 'metrics-avit-scope-input'; entry.rows = 2; entry.maxLength = 16000; entry.spellcheck = false;
        entry.setAttribute('aria-label', 'ServiceNow AVIT sync scope value');
        const note = el('p', 'small subtle');
        const update = () => {
          const isNumbers = type.value === 'avits';
          entry.value = isNumbers ? state.avitScope.avits : state.avitScope.query;
          entry.placeholder = isNumbers ? 'AVIT000000095938462, AVIT000000095938463' : 'u_repository=team/repo^state=1';
          note.textContent = isNumbers ? 'Enter specific AVIT numbers, separated by commas or spaces. Up to 500 per sync.'
            : 'Paste the encoded query from a bounded ServiceNow filter. Up to 10,000 matching AVITs; unsupported operators are rejected.';
          sync.disabled = !tracker.connected || !currentAvitScope();
        };
        type.addEventListener('change', () => { state.avitScope.type = type.value; state.avitScopeTouched = true; update(); });
        entry.addEventListener('input', () => { state.avitScope[type.value] = entry.value; state.avitScopeTouched = true; sync.disabled = !tracker.connected || !currentAvitScope(); });
        scope.append(el('label', 'small', 'Required sync scope'), type, entry, note);
        const saved = savedAvitScope(tracker.scope);
        if (saved) {
          const label = saved.type === 'avits' ? `${saved.avits.split(',').filter(Boolean).length} AVIT numbers` : `Encoded query: ${saved.query}`;
          const previous = el('details', 'metrics-saved-scope');
          previous.append(el('summary', 'small subtle', `Last successful scope · ${label.slice(0, 110)}${label.length > 110 ? '…' : ''}`), el('code', '', saved.type === 'avits' ? saved.avits : saved.query));
          scope.append(previous);
        } else scope.append(el('p', 'small subtle', 'No AVIT scope has been synced yet. Choose a scope before syncing.'));
        if (tracker.createdThrough) scope.append(el('p', 'small subtle', `Includes AVITs created through ${dateLabel(tracker.createdThrough)}.`));
        update(); card.append(scope);
      }
      card.append(actions); cards.append(card);
    }
    if (!cards.children.length) cards.append(el('p', 'chart-empty', 'No defect tracker metrics connectors are available.'));
    if (!others.children.length) others.append(el('p', 'small subtle', 'No additional tracker connectors are listed.'));
  }
  async function loadConnections() {
    try {
      const [sources, catalog] = await Promise.all([api('/api/metrics/sources'), api('/api/trackers')]);
      renderSources(sources.sources || []); renderTrackers(catalog.trackers || []);
      $('metrics-tracker-error').textContent = '';
    } catch (error) {
      $('metrics-tracker-error').textContent = `Tracker refresh failed: ${error.message}. Showing the last loaded status; sync data may be stale.`;
    }
  }
  async function syncTracker(id, control) {
    if (!Object.hasOwn(TRACKER_SETTINGS, id)) return;
    const scope = id === 'servicenow-avit' ? currentAvitScope() : null;
    if (id === 'servicenow-avit' && !scope) {
      $('metrics-tracker-error').textContent = 'Choose AVIT numbers or an encoded ServiceNow filter before syncing metrics.';
      return;
    }
    control.disabled = true; control.textContent = 'Syncing…';
    $('metrics-tracker-error').textContent = '';
    try {
      await api(`/api/trackers/${encodeURIComponent(id)}/sync`, { method: 'POST', body: JSON.stringify(scope ? { scope } : {}) });
      if (id === 'servicenow-avit') state.avitScopeTouched = false;
      await loadConnections(); await renderDashboard();
    } catch (error) {
      control.disabled = false; control.textContent = 'Sync now';
      $('metrics-tracker-error').textContent = `${id === 'servicenow-avit' ? 'ServiceNow AVIT' : 'DefectDojo'} sync failed: ${error.message}`;
    }
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
        const data = await api('/api/metrics/query', { method: 'POST', body: JSON.stringify({ chart: widget.chart, metric: widget.metric, groupBy: widget.groupBy, columns: widget.columns, filters: { ...widget.filters, ...rangeFilter(), ...sourceFilter() } }) });
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
      await Promise.all([loadConnections(), loadAggregate()]);
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
    $('metrics-source').addEventListener('change', event => { state.source = event.target.value; updateExportLink(); renderDashboard(); });
    $('metrics-range').addEventListener('change', renderDashboard);
    $('metrics-refresh-connections').addEventListener('click', loadConnections);
    $('avit-aggregate-form').addEventListener('input', () => { state.aggregateDirty = true; updateAggregateNote(); });
    $('avit-scm').addEventListener('change', syncScmFields);
    syncScmFields();
    $('avit-aggregate-form').addEventListener('submit', submitAggregate);
    $('avit-aggregate-configure').addEventListener('click', () => openTrackerSettings('servicenow-avit'));
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
      // View modules may contribute help for their own pages; server-provided entries win on a shared key or id.
      const extras = window.ThreatlintHelpExtras || {};
      state.help = { ...state.help, tooltips: { ...extras.tooltips, ...state.help.tooltips },
        topics: [...state.help.topics, ...(extras.topics || []).filter(topic => !state.help.topics.some(item => item.id === topic.id))] };
      installTips(state.help.tooltips); renderLearn();
    } catch { /* Help is optional; the workbench remains usable. */ }
    if (!$('view-metrics').hidden) loadMetrics();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize, { once: true });
  else initialize();
})();
