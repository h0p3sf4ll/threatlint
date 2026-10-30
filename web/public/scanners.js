'use strict';

/**
 * DefectDojo and SonarQube in the Workbench: their Settings sections, the DefectDojo / SonarQube review pages, and
 * Post to DefectDojo / SonarQube for imported scan reports. Independent of app.js state: workspace, model settings and
 * the runner socket come from threatlint:context; reports open through threatlint:open-report.
 * Every write is a separate confirmed request. CSP-safe: DOM nodes and textContent only; values from the tools render as text.
 */
(() => {
  const $ = id => document.getElementById(id);
  const TOOLS = {
    dojo: { label: 'DefectDojo', example: '123, DOJO-124', settings: 'defectdojo', attachments: true,
      outcomes: [['False positive', 'Word report attached, note “Closed by Threatlint as a false positive, see attached report.”, then false_p and inactive.'],
        ['True positive', 'Word report attached, note “True positive, see attached report.”, then verified (stays active).'],
        ['Ambiguous', 'Word report attached and note “Ambiguous, see attached report. …”; nothing else changes.']] },
    sonar: { label: 'SonarQube', example: 'AYxExampleKey01, SONAR-HOTSPOT-AYxExampleKey02', settings: 'sonarqube', attachments: false,
      outcomes: [['False positive', 'Comment with a summary and where the report lives, then False Positive (hotspots: Reviewed / Safe).'],
        ['True positive', 'Comment, then Confirm when the server offers it (hotspots: comment only).'],
        ['Ambiguous', 'Comment only; nothing else changes. SonarQube stores no attachments.']] },
  };
  const STAGES = { queued: 'Queued', fetching: 'Fetching', checkout: 'Cloning', triage: 'Triaging', reported: 'Reported', error: 'Error', cancelled: 'Cancelled' };
  const state = { context: null, sockets: new WeakSet(), running: null, tools: {}, job: null, post: null, saved: {} };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = String(text);
    return node;
  }
  function button(label, className, action, type = 'button') { const node = el('button', className, label); node.type = type; if (action) node.addEventListener('click', action); return node; }
  function toast(message, error) { document.dispatchEvent(new CustomEvent('threatlint:toast', { detail: { message, error } })); }
  async function api(url, options = {}) {
    const response = await fetch(url, { cache: 'no-store', ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload?.error) throw new Error(payload?.error || `Request failed (${response.status})`);
    return payload;
  }
  const text = value => (value == null ? '' : String(value));
  const ids = { form: tool => `${tool}review-form`, refs: tool => `${tool}review-references`, error: tool => `${tool}review-error`, results: tool => `${tool}review-results`,
    start: tool => `${tool}review-start`, cancel: tool => `${tool}review-cancel`, status: tool => `${tool}review-connection` };
  function goSettings(tool) {
    document.dispatchEvent(new CustomEvent('threatlint:navigate', { detail: { view: 'settings' } }));
    setTimeout(() => $(`settings-${TOOLS[tool].settings}`)?.scrollIntoView({ behavior: 'instant', block: 'start' }), 0);
  }

  // ── Settings ─────────────────────────────────────────────────────────────
  const MASK = '••••••••••••';
  async function loadSettings(tool) {
    try {
      const saved = await api(`/api/scanners/${tool}/settings`);
      state.saved[tool] = saved;
      $(`${tool}-url`).value = saved.url || '';
      $(`${tool}-token`).value = saved.hasToken ? MASK : '';
      $(`${tool}-status`).textContent = saved.hasToken ? `Configured (${saved.tokenSource === 'environment' ? 'token from the environment' : `saved in ${saved.path}`}). The token is never shown again.` : 'Not configured.';
    } catch (error) { $(`${tool}-status`).textContent = `Settings are unavailable: ${error.message}`; }
    renderConnection(tool);
  }
  async function saveSettings(event, tool) {
    event.preventDefault();
    $(`${tool}-error`).textContent = '';
    const typed = $(`${tool}-token`).value.trim();
    const body = { url: $(`${tool}-url`).value.trim(), ...(typed && typed !== MASK ? { token: typed } : {}) };
    const submit = event.target.querySelector('button[type=submit]'); submit.disabled = true;
    $(`${tool}-status`).textContent = body.url || body.token ? `Checking the token with ${TOOLS[tool].label}…` : 'Removing the saved connection…';
    try { await api(`/api/scanners/${tool}/settings`, { method: 'POST', body: JSON.stringify(body) }); await loadSettings(tool); toast(`${TOOLS[tool].label} settings saved.`); }
    catch (error) { $(`${tool}-error`).textContent = error.message; $(`${tool}-status`).textContent = ''; }
    finally { submit.disabled = false; }
  }

  // ── Review pages ─────────────────────────────────────────────────────────
  function field(label, input, note) {
    const wrap = el('div', 'scanner-field');
    const caption = el('label', '', label); caption.htmlFor = input.id;
    wrap.append(caption, input);
    if (note) wrap.append(el('p', 'field-note small subtle', note));
    return wrap;
  }
  function input(id, placeholder, attributes = {}) { const node = el('input'); node.id = id; node.placeholder = placeholder; node.autocomplete = 'off'; node.spellcheck = false; Object.assign(node, attributes); return node; }
  function select(id, options) { const node = el('select'); node.id = id; for (const [value, label] of options) { const option = el('option', '', label); option.value = value; node.append(option); } return node; }
  function filterFields(tool) {
    const grid = el('div', 'scanner-filter-grid');
    if (tool === 'dojo') {
      grid.append(field('Product id', input('dojo-filter-product', 'e.g. 3', { inputMode: 'numeric' })), field('Engagement id', input('dojo-filter-engagement', 'optional', { inputMode: 'numeric' })),
        field('Test id', input('dojo-filter-test', 'optional', { inputMode: 'numeric' })), field('Tags', input('dojo-filter-tags', 'comma-separated')),
        field('Severity', input('dojo-filter-severity', 'Critical, High')), field('Active', select('dojo-filter-active', [['true', 'Active only'], ['', 'Any'], ['false', 'Inactive only']])),
        field('Verified', select('dojo-filter-verified', [['', 'Any'], ['false', 'Unverified only'], ['true', 'Verified only']])), field('Limit', input('dojo-filter-limit', '50', { inputMode: 'numeric' })));
    } else {
      grid.append(field('Project key', input('sonar-filter-project', 'e.g. web')), field('Branch', input('sonar-filter-branch', 'main branch when blank')),
        field('Pull request', input('sonar-filter-pullRequest', 'optional')), field('Organization', input('sonar-filter-organization', 'SonarCloud only')),
        field('Types', input('sonar-filter-types', 'VULNERABILITY, SECURITY_HOTSPOT')), field('Severities', input('sonar-filter-severities', 'BLOCKER, CRITICAL')),
        field('Statuses', input('sonar-filter-statuses', 'OPEN, CONFIRMED, REOPENED / TO_REVIEW')), field('Limit', input('sonar-filter-limit', '50', { inputMode: 'numeric' })));
    }
    return grid;
  }
  function readFilter(tool) {
    const value = name => $(`${tool}-filter-${name}`)?.value.trim() || '';
    const words = name => value(name).split(/[\s,]+/).filter(Boolean);
    if (tool === 'dojo') {
      const filter = { product: value('product'), engagement: value('engagement'), test: value('test'), tags: words('tags'), severity: words('severity').map(item => item[0].toUpperCase() + item.slice(1).toLowerCase()), active: value('active'), verified: value('verified'), limit: value('limit') };
      return filter.product || filter.engagement || filter.test || filter.tags.length ? filter : null;
    }
    const filter = { project: value('project'), branch: value('branch'), pullRequest: value('pullRequest'), organization: value('organization'), types: words('types').map(item => item.toUpperCase()),
      severities: words('severities').map(item => item.toUpperCase()), statuses: words('statuses').map(item => item.toUpperCase()), limit: value('limit') };
    return filter.project ? filter : null;
  }
  function buildReview(container) {
    const tool = container.dataset.scannerTool, spec = TOOLS[tool];
    const form = el('form', 'settings-card fpreview-form scanner-review-form'); form.id = ids.form(tool); form.noValidate = true;
    const refs = el('textarea'); refs.id = ids.refs(tool); refs.rows = 3; refs.spellcheck = false; refs.placeholder = spec.example;
    const label = el('label', '', tool === 'dojo' ? 'Finding ids' : 'Issue or hotspot keys'); label.htmlFor = refs.id;
    const filters = el('details', 'scanner-filters'); filters.append(el('summary', 'small', 'Or select by filter'), filterFields(tool));
    const outcomes = el('div', 'fpreview-outcomes small subtle');
    for (const [name, detail] of spec.outcomes) { const row = el('div'); row.append(el('strong', '', name), document.createTextNode(` · ${detail}`)); outcomes.append(row); }
    const connection = el('p', 'field-note small'); connection.id = ids.status(tool); connection.setAttribute('aria-live', 'polite');
    const error = el('p', 'form-error'); error.id = ids.error(tool); error.setAttribute('role', 'alert');
    const actions = el('div', 'settings-actions');
    const cancel = button('Stop', 'button secondary hidden', () => { if (state.context?.socket?.readyState === 1) state.context.socket.send(JSON.stringify({ action: 'cancel' })); }); cancel.id = ids.cancel(tool);
    const start = button(`Review ${spec.label} findings`, 'button primary', null, 'submit'); start.id = ids.start(tool);
    const row = el('div', 'input-row'); row.append(cancel, start);
    actions.append(el('span', 'small subtle', 'Uses the model chosen in Settings. Nothing is posted until you confirm each finding.'), row);
    form.append(label, refs, el('p', 'field-note small subtle', `${tool === 'dojo' ? 'Numbers or DOJO-<id>' : 'Issue keys, or SONAR-HOTSPOT-<key> for hotspots'}, separated by commas, spaces, or new lines (up to 50).`), filters, outcomes, connection, error, actions);
    form.addEventListener('submit', event => { event.preventDefault(); start_(tool); });
    const results = el('div', 'fpreview-results'); results.id = ids.results(tool); results.setAttribute('aria-live', 'polite');
    container.replaceChildren(form, results);
  }
  function renderConnection(tool) {
    const node = $(ids.status(tool)); if (!node) return;
    const saved = state.saved[tool];
    node.replaceChildren();
    if (saved?.hasToken && saved.url) { node.className = 'field-note small subtle'; node.textContent = `Connected to ${saved.url}.`; return; }
    node.className = 'field-note small fp-status-warn';
    const link = el('a', '', `Set up ${TOOLS[tool].label} in Settings`); link.href = '#';
    link.addEventListener('click', event => { event.preventDefault(); goSettings(tool); });
    node.append(document.createTextNode(`${TOOLS[tool].label} is not configured. `), link, document.createTextNode(` or run \`threatlint ${tool} login\`.`));
  }
  function setRunning(tool, running) {
    state.running = running ? tool : null;
    for (const name of Object.keys(TOOLS)) {
      if (!$(ids.start(name))) continue;
      $(ids.start(name)).disabled = !!state.running; $(ids.refs(name)).disabled = state.running === name;
      $(ids.cancel(name)).classList.toggle('hidden', state.running !== name);
    }
  }
  function start_(tool) {
    const spec = TOOLS[tool];
    $(ids.error(tool)).textContent = '';
    const references = $(ids.refs(tool)).value.trim();
    const filter = readFilter(tool);
    if (!references && !filter) { $(ids.error(tool)).textContent = tool === 'dojo' ? 'Enter finding ids, or a product, engagement, test, or tag.' : 'Enter issue keys, or a project key.'; return; }
    const context = state.context;
    if (!(context?.models?.review || context?.settings?.model)) { $(ids.error(tool)).textContent = 'Choose a model in Settings first.'; return; }
    if (!context.ready) { $(ids.error(tool)).textContent = 'Finish the model settings (and authorize the remote provider) in Settings first.'; return; }
    if (!(state.saved[tool]?.hasToken && state.saved[tool]?.url)) { $(ids.error(tool)).textContent = `Configure ${spec.label} in Settings first.`; return; }
    if (!context.connected || context.socket?.readyState !== 1) { $(ids.error(tool)).textContent = 'The Workbench is not connected.'; return; }
    if (state.running) { $(ids.error(tool)).textContent = 'Another review is running.'; return; }
    attach(context.socket);
    state.tools = {};
    $(ids.results(tool)).replaceChildren();
    setRunning(tool, true);
    context.socket.send(JSON.stringify({ action: 'run_scanner_batch', tool, references, ...(filter ? { filter } : {}), ...context.settings }));
  }

  function card(tool, reference) {
    const id = `scanner-${tool}-${reference}`;
    let node = document.getElementById(id);
    if (node) return node;
    node = el('article', 'avit-card scanner-card'); node.id = id;
    const header = el('header'); header.append(el('span', 'avit-id', reference), el('span', 'avit-stage stage-queued', 'Queued'), el('span', 'avit-disposition'));
    node.append(header, el('div', 'avit-detail'), el('ul', 'avit-outcome'), el('div', 'avit-actions'));
    $(ids.results(tool))?.append(node);
    return node;
  }
  function renderItem(event) {
    const node = card(event.tool, event.reference);
    const stage = node.querySelector('.avit-stage');
    if (STAGES[event.stage]) { stage.textContent = STAGES[event.stage]; stage.className = `avit-stage stage-${event.stage === 'reported' ? 'done' : event.stage}`; }
    if (event.agentTool) {
      state.tools[event.reference] = (state.tools[event.reference] || 0) + 1;
      node.querySelector('.avit-detail').textContent = `Inspecting the repository (${state.tools[event.reference]} tool calls)…`;
    } else if (event.detail) node.querySelector('.avit-detail').textContent = event.detail;
    if (event.disposition) { const badge = node.querySelector('.avit-disposition'); badge.className = 'avit-disposition disposition-badge'; badge.textContent = event.disposition; }
    if (event.report && !node.querySelector('.avit-actions button')) {
      const actions = node.querySelector('.avit-actions');
      actions.append(button('Read report ↗', 'button secondary small-button', () => document.dispatchEvent(new CustomEvent('threatlint:open-report', { detail: { sessionId: event.report.sessionId, previewUrl: event.report.previewUrl } }))));
      if (event.report.docxUrl) { const word = el('a', 'button secondary small-button', '↓ Word'); word.href = event.report.docxUrl; word.download = ''; actions.append(word); }
      if (['TRUE POSITIVE', 'FALSE POSITIVE', 'AMBIGUOUS'].includes(event.disposition)) {
        const post = button(`Post to ${TOOLS[event.tool].label}…`, 'button primary small-button', () => openPost({ kind: 'review', tool: event.tool, reference: event.reference, disposition: event.disposition, reportId: event.report.id, card: node }));
        post.dataset.post = 'true'; actions.append(post);
      }
    }
  }
  function handle(event) {
    if (!event || typeof event !== 'object') return;
    if (event.type === 'scanner_batch_start') { for (const reference of event.references || []) card(event.tool, reference); }
    else if (event.type === 'scanner_item' && TOOLS[event.tool]) renderItem(event);
    else if (event.type === 'scanner_batch_complete') { setRunning(event.tool, false); toast(event.cancelled ? `${TOOLS[event.tool].label} review stopped.` : `${TOOLS[event.tool].label} review complete. Post each finding when you are ready.`); }
    else if (event.type === 'scanner_batch_error') { const tool = TOOLS[event.tool] ? event.tool : state.running; setRunning(tool, false); if (tool) $(ids.error(tool)).textContent = text(event.message); }
  }
  function attach(socket) {
    if (!socket || state.sockets.has(socket)) return;
    state.sockets.add(socket);
    socket.addEventListener('message', message => { let event; try { event = JSON.parse(message.data); } catch { return; } handle(event); });
    socket.addEventListener('close', () => { if (state.running) setRunning(state.running, false); });
  }

  // ── Confirmed posting (review results and imported scans) ────────────────
  const DESCRIBE = {
    dojo: { 'FALSE POSITIVE': ['Attach the Word report to the finding.', 'Add the note “Closed by Threatlint as a false positive, see attached report.”', 'Set false_p = true and active = false.'],
      'TRUE POSITIVE': ['Attach the Word report to the finding.', 'Add the note “True positive, see attached report.”', 'Set verified = true; it stays active.'],
      AMBIGUOUS: ['Attach the Word report to the finding.', 'Add the note “Ambiguous, see attached report. Left open pending the evidence the report names.”', 'Nothing else changes.'] },
    sonar: { 'FALSE POSITIVE': ['Add a comment with a short summary and where the full report lives (SonarQube stores no attachments).', 'Mark the issue False Positive (a hotspot: Reviewed / Safe).'],
      'TRUE POSITIVE': ['Add a comment with a short summary and where the full report lives.', 'Confirm the issue when the server offers Confirm (a hotspot keeps its status).'],
      AMBIGUOUS: ['Add a comment with a short summary and where the full report lives.', 'Nothing else changes.'] },
  };
  function openPost(post) {
    const spec = TOOLS[post.tool];
    state.post = post;
    $('scanner-post-eyebrow').textContent = `${spec.label.toUpperCase()} · CONFIRM`;
    $('scanner-post-title').textContent = `Post to ${spec.label}`;
    const steps = $('scanner-post-steps'); steps.replaceChildren();
    if (post.kind === 'review') {
      $('scanner-post-summary').textContent = `${post.reference} · ${post.disposition}`;
      for (const line of DESCRIBE[post.tool][post.disposition]) steps.append(el('li', '', line));
      $('scanner-post-reference-row').hidden = true;
    } else {
      const job = post.job, counts = job.counts || {};
      const native = ({ defectdojo: 'dojo', sonarqube: 'sonar' })[job.source] === post.tool;
      $('scanner-post-summary').textContent = `${text(job.title) || 'Scan import'} · ${Number(counts.total) || 0} findings (${Number(counts.tp) || 0} TP / ${Number(counts.fp) || 0} FP / ${Number(counts.ambiguous) || 0} ambiguous)`;
      steps.append(el('li', '', native ? `Each finding is posted to its own ${spec.label} ${post.tool === 'dojo' ? 'finding' : 'issue or hotspot'}.` : `The verdicts are posted to the ${spec.label} reference you enter (several findings on one reference combine conservatively: any true positive wins, then ambiguous).`));
      for (const line of DESCRIBE[post.tool]['FALSE POSITIVE']) steps.append(el('li', '', `False positives: ${line.charAt(0).toLowerCase()}${line.slice(1)}`));
      steps.append(el('li', '', `True positives and ambiguous findings get the matching ${post.tool === 'dojo' ? 'note (true positives are also marked verified)' : 'comment (true positives are confirmed when offered)'}.`));
      $('scanner-post-reference-row').hidden = false;
      $('scanner-post-reference-label').textContent = native ? `${spec.label} reference (optional)` : `${spec.label} reference`;
      $('scanner-post-reference').placeholder = post.tool === 'dojo' ? 'DOJO-123 or FP-001=DOJO-123' : 'AYxExampleKey01 or FP-001=AYxExampleKey01';
      $('scanner-post-reference-note').textContent = native ? 'Leave blank to post each imported finding to itself.' : 'One reference for the whole upload, or finding-id=reference pairs.';
      $('scanner-post-reference').value = '';
    }
    $('scanner-post-url-row').hidden = post.tool !== 'sonar'; $('scanner-post-url').value = '';
    $('scanner-post-semgrep-row').hidden = !(post.kind === 'review' && post.tool === 'dojo' && post.disposition === 'FALSE POSITIVE'); $('scanner-post-semgrep').checked = false;
    $('scanner-post-error').textContent = ''; $('scanner-post-result').replaceChildren();
    $('scanner-post-confirm').disabled = false; $('scanner-post-confirm').hidden = false; $('scanner-post-cancel').textContent = 'Cancel';
    $('scanner-post-footer').textContent = `Nothing changes in ${spec.label} until you confirm.`;
    $('scanner-post-dialog').showModal();
  }
  async function confirmPost(event) {
    event.preventDefault();
    const post = state.post; if (!post || $('scanner-post-confirm').disabled) return;
    const spec = TOOLS[post.tool];
    const reportUrl = $('scanner-post-url').value.trim();
    if (reportUrl && !/^https:\/\//i.test(reportUrl)) { $('scanner-post-error').textContent = 'The report location must be an https:// URL.'; return; }
    $('scanner-post-error').textContent = ''; $('scanner-post-confirm').disabled = true;
    const result = $('scanner-post-result'); result.replaceChildren(el('p', 'field-note small', `Posting to ${spec.label}…`));
    try {
      let lines;
      if (post.kind === 'review') {
        const response = await api(`/api/scanners/${post.tool}/resolve`, { method: 'POST', body: JSON.stringify({ reportId: post.reportId, reference: post.reference, confirm: true, ...(reportUrl ? { reportUrl } : {}), ...($('scanner-post-semgrep').checked ? { semgrep: true } : {}) }) });
        lines = (response.lines || []).map(line => line.replace(/^[✓!]\s*/, ''));
        post.card?.querySelector('[data-post]')?.remove();
        const outcome = post.card?.querySelector('.avit-outcome'); if (outcome) { outcome.replaceChildren(...lines.map(line => el('li', '', line))); }
      } else {
        const references = $('scanner-post-reference').value.trim();
        const response = await api(`/api/scan-import/${encodeURIComponent(post.job.id)}/scanner`, { method: 'POST', body: JSON.stringify({ tool: post.tool, confirm: true, ...(references ? { references } : {}), ...(reportUrl ? { reportUrl } : {}) }) });
        lines = (response.actions || []).map(action => [action.number || action.reference, action.detail].filter(Boolean).map(text).join(' · '));
      }
      const list = el('ul', 'scanimport-snow-actions'); for (const line of lines) list.append(el('li', '', line));
      result.replaceChildren(el('p', 'field-note small fp-status-ok', `Posted to ${spec.label}.`), list);
      $('scanner-post-confirm').hidden = true; $('scanner-post-cancel').textContent = 'Close';
      toast(`Posted to ${spec.label}.`);
    } catch (error) {
      result.replaceChildren(); $('scanner-post-error').textContent = error.message; $('scanner-post-confirm').disabled = false;
    }
  }

  // ── Wiring ───────────────────────────────────────────────────────────────
  function wire() {
    for (const container of document.querySelectorAll('.scanner-review[data-scanner-tool]')) buildReview(container);
    for (const form of document.querySelectorAll('form.scanner-settings[data-scanner-tool]')) { const tool = form.dataset.scannerTool; form.addEventListener('submit', event => { void saveSettings(event, tool); }); }
    for (const node of document.querySelectorAll('[data-scanner-post]')) {
      node.disabled = true;
      node.addEventListener('click', () => { if (state.job?.status === 'done' && state.job.reportId) openPost({ kind: 'import', tool: node.dataset.scannerPost, job: state.job }); });
    }
    $('scanner-post-form').addEventListener('submit', event => { void confirmPost(event); });
    $('scanner-post-cancel').addEventListener('click', () => $('scanner-post-dialog').close());
    document.addEventListener('threatlint:scanimport-job', event => {
      state.job = event.detail;
      for (const node of document.querySelectorAll('[data-scanner-post]')) node.disabled = !(state.job?.status === 'done' && state.job.reportId);
    });
    document.addEventListener('threatlint:context', event => { state.context = event.detail; attach(event.detail?.socket); });
    document.addEventListener('threatlint:view', event => {
      if (event.detail.view === 'settings') for (const tool of Object.keys(TOOLS)) void loadSettings(tool);
      if (event.detail.view === 'dojoreview') void loadSettings('dojo');
      if (event.detail.view === 'sonarreview') void loadSettings('sonar');
    });
    document.dispatchEvent(new CustomEvent('threatlint:request-context'));
    for (const tool of Object.keys(TOOLS)) void loadSettings(tool);
  }
  if (!$('scanner-post-dialog')) return;
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire, { once: true });
  else wire();
})();
