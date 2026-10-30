'use strict';

/**
 * Import scan report: upload an Invicti (DAST) or MobSF (mobile) report, follow its triage, open or download
 * the saved findings report, and post the outcome to ServiceNow. Independent of app.js state; workspace and
 * model come from threatlint:context, and reports open through threatlint:open-report.
 * CSP-safe: DOM nodes and textContent only. Every value from a scan report is rendered as text.
 */
(() => {
  const $ = id => document.getElementById(id);
  // The file travels base64-encoded in JSON, and the runner caps a JSON body at 7 MB.
  const MAX_BYTES = 25 * 1024 * 1024;
  const POLL_MS = 1000;
  const STEPS = ['queued', 'parsing', 'triaging', 'done'];
  const STATUS_LABELS = { queued: 'Queued', parsing: 'Parsing', triaging: 'Triaging', done: 'Done', error: 'Error' };
  const STATUS_DETAIL = { queued: 'Queued. The runner starts it shortly.', parsing: 'Parsing the report into findings…', triaging: 'Triaging each finding against the evidence…' };
  const SOURCES = { invicti: 'Invicti', mobsf: 'MobSF', defectdojo: 'DefectDojo', sonarqube: 'SonarQube', auto: 'Auto-detect' };
  const AVIT = /^AVIT\d{7,15}$/;
  const state = { workspaceChosen: false, file: null, context: null, job: null, jobId: null, pollTimer: null, lastStep: 'queued', report: null, submitting: false, posting: false };

  // Help for this page, merged into /api/help by insights.js (server entries win on a shared key or id).
  window.ThreatlintHelpExtras = {
    tooltips: {
      'scanimport-source': 'Auto-detect reads the file to tell Invicti, MobSF, DefectDojo (/api/v2/findings/ JSON), and SonarQube (/api/issues/search or /api/hotspots/search JSON) apart. Choose one explicitly if detection fails.',
      'scanimport-workspace': 'Optional. With a workspace, triage reads that repository’s source to confirm or rule out each finding. Without one, it judges the report alone.',
      'scanimport-avit': 'The ServiceNow AVIT this scan belongs to: AVIT followed by 7 to 15 digits. Needed only to post the result to ServiceNow.',
      'scanimport-servicenow': 'Attaches the Word report to the AVIT, closes false positives as Closed / False Positive with the Threatlint comment, and adds work notes to true positives and ambiguous findings. Asks first.',
      'scanimport-disposition': 'TRUE POSITIVE = the evidence supports it. FALSE POSITIVE = the evidence rules it out. AMBIGUOUS = not enough evidence either way; a person decides.',
    },
    topics: [{ id: 'scan-import', title: 'Import an Invicti or MobSF scan report', minutes: 2, steps: [
      'Export the scan: Invicti as XML or JSON, MobSF as its JSON report.',
      'Open Test → Import scan report and drop the file, or press Choose file.',
      'Leave Scanner on Auto-detect, or pick Invicti or MobSF. Optionally pick a workspace so triage can read the matching source, and enter the AVIT number.',
      'Press Import and triage. Progress moves through Queued → Parsing → Triaging → Done.',
      'Review the counts and the findings table, then press Open report, or download it as Markdown or Word. It is also listed in Findings.',
      'Press Post to ServiceNow, check what will happen, and confirm. The Word report is attached, false positives are closed, and the rest get work notes.',
    ] }],
  };

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
  function toast(message, error) { document.dispatchEvent(new CustomEvent('threatlint:toast', { detail: { message, error } })); }
  async function api(url, options = {}) {
    const response = await fetch(url, { cache: 'no-store', ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
    const payload = await response.json().catch(() => ({}));
    if (response.status === 413) throw new Error(payload.error || 'The report is too large for the runner to accept.');
    if (!response.ok || payload?.error) throw new Error(payload?.error || `Request failed (${response.status})`);
    return payload;
  }
  const text = value => (value == null ? '' : String(value));
  const count = value => (Number.isFinite(Number(value)) ? Number(value) : 0);
  const repoName = repoPath => text(repoPath).split(/[\\/]/).findLast(Boolean) || text(repoPath);
  const sourceLabel = source => SOURCES[source] || (source ? text(source) : 'Scan');
  function formatTime(value) {
    const date = new Date(typeof value === 'number' || /^\d+$/.test(text(value)) ? Number(value) : value);
    return Number.isNaN(date.getTime()) ? '' : date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }
  function normalizeAvit(value) { return text(value).trim().toUpperCase(); }
  function avitError(value, required) {
    if (!value) return required ? 'Enter the AVIT number to post to.' : '';
    return AVIT.test(value) ? '' : `Not an AVIT number: ${value} (expected AVIT followed by 7 to 15 digits, e.g. AVIT000000095938462 or AVIT0042599)`;
  }

  // ── Form ─────────────────────────────────────────────────────────────────
  function setError(message) { $('scanimport-error').textContent = message || ''; }
  function updateControls() {
    $('scanimport-start').disabled = !state.file || state.submitting || isLive(state.job?.status);
    const settings = state.context?.settings;
    const model = state.context?.models?.review || settings?.model;
    $('scanimport-model').textContent = model ? `Model: ${model} (${settings.provider}).` : 'Choose a model in Settings before importing.';
  }
  function setFile(file) {
    setError('');
    if (!file) return;
    if (!/\.(xml|json)$/i.test(file.name)) { setError(`Unsupported file: ${file.name}. Choose an Invicti XML or JSON export, a MobSF JSON report, or a DefectDojo or SonarQube findings JSON.`); return; }
    if (!file.size) { setError(`${file.name} is empty. Export the scan report again.`); return; }
    if (file.size > MAX_BYTES) { setError(`${file.name} is ${(file.size / 1024 / 1024).toFixed(1)} MB. The limit is 25 MB; export a filtered report (for example, without request/response bodies) or split it.`); return; }
    state.file = file;
    $('scanimport-file-name').textContent = `${file.name} · ${file.size < 1024 * 1024 ? `${Math.max(1, Math.round(file.size / 1024))} KB` : `${(file.size / 1024 / 1024).toFixed(1)} MB`}`;
    $('scanimport-file-name').title = file.name;
    $('scanimport-remove').classList.remove('hidden');
    $('scanimport-drop').classList.add('has-file');
    updateControls();
  }
  function clearFile() {
    state.file = null; $('scanimport-file').value = '';
    $('scanimport-file-name').textContent = 'No file selected'; $('scanimport-file-name').title = '';
    $('scanimport-remove').classList.add('hidden'); $('scanimport-drop').classList.remove('has-file');
    updateControls();
  }
  function readBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result).replace(/^data:[^,]*,/, ''));
      reader.onerror = () => reject(new Error(`Could not read ${file.name}.`));
      reader.readAsDataURL(file);
    });
  }
  async function loadWorkspaces() {
    const picker = $('scanimport-workspace');
    const previous = state.workspaceChosen ? picker.value : picker.value || state.context?.session?.id || '';
    let sessions = [];
    try { sessions = await api('/api/sessions'); } catch { /* the picker stays optional */ }
    const options = [Object.assign(el('option', '', 'No source context'), { value: '' })];
    for (const session of sessions) { const option = el('option', '', repoName(session.repoPath)); option.value = session.id; option.title = text(session.repoPath); options.push(option); }
    picker.replaceChildren(...options);
    picker.value = sessions.some(session => session.id === previous) ? previous : '';
  }
  async function submit(event) {
    event.preventDefault(); setError('');
    if (!state.file) { setError('Choose a scan report first.'); return; }
    const avit = normalizeAvit($('scanimport-avit').value);
    const invalid = avitError(avit, false);
    if (invalid) { setError(invalid); $('scanimport-avit').focus(); return; }
    state.submitting = true; updateControls();
    try {
      const content = await readBase64(state.file);
      // The model settings the run uses (keys stay in memory; the server never saves them).
      const body = { ...(state.context?.settings || {}), filename: state.file.name, content, source: $('scanimport-source').value };
      if ($('scanimport-workspace').value) body.workspaceId = $('scanimport-workspace').value;
      if (avit) body.avit = avit;
      const created = await api('/api/scan-import', { method: 'POST', body: JSON.stringify(body) });
      $('scanimport-avit').value = avit;
      startJob({ id: created.id, status: created.status || 'queued', source: body.source, title: state.file.name, avit }, true);
      clearFile();
    } catch (error) { setError(error.message); }
    finally { state.submitting = false; updateControls(); }
  }

  // ── Progress and result ──────────────────────────────────────────────────
  function isLive(status) { return ['queued', 'parsing', 'triaging'].includes(status); }
  function startJob(job, fresh) {
    clearTimeout(state.pollTimer);
    state.jobId = job.id; state.job = job; state.report = null; state.lastStep = 'queued';
    if (fresh) state.avit = job.avit || '';
    renderJob(job);
    $('scanimport-job').hidden = false;
    if (fresh) $('scanimport-job').scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    void poll(job.id);
  }
  async function poll(id) {
    if (id !== state.jobId) return;
    let job;
    try { job = await api(`/api/scan-import/${encodeURIComponent(id)}`); }
    catch (error) {
      if (id !== state.jobId) return;
      $('scanimport-status').textContent = `Could not read the import status: ${error.message} Retrying…`;
      state.pollTimer = setTimeout(() => poll(id), POLL_MS * 3); return;
    }
    if (id !== state.jobId) return;
    state.job = job; renderJob(job);
    if (isLive(job.status)) state.pollTimer = setTimeout(() => poll(id), POLL_MS);
    else { updateControls(); void loadHistory(); if (job.status === 'done') void resolveReport(job); }
  }
  function renderSteps(status) {
    if (STEPS.includes(status)) state.lastStep = status;
    const reached = STEPS.indexOf(state.lastStep);
    for (const item of $('scanimport-steps').children) {
      const index = STEPS.indexOf(item.dataset.step);
      item.className = status === 'error' && index === reached ? 'error' : index < reached || status === 'done' ? 'complete' : index === reached ? 'current' : '';
      if (item.className === 'current') item.setAttribute('aria-current', 'step'); else item.removeAttribute('aria-current');
    }
  }
  function renderJob(job) {
    const status = STATUS_LABELS[job.status] ? job.status : 'queued';
    $('scanimport-job-eyebrow').textContent = `${sourceLabel(job.source).toUpperCase()} IMPORT`;
    $('scanimport-job-title').textContent = text(job.title) || 'Importing scan report';
    $('scanimport-job-target').textContent = job.target ? `Target · ${text(job.target)}` : '';
    const pill = $('scanimport-job-status'); pill.textContent = STATUS_LABELS[status].toUpperCase(); pill.className = `operations-pill scanimport-pill-${status}`;
    renderSteps(status);
    const output = $('scanimport-status'); output.classList.toggle('scanimport-status-error', status === 'error');
    if (status === 'error') output.textContent = errorMessage(job.error);
    else if (status === 'done') output.textContent = `Triage complete · ${count(job.counts?.total)} finding${count(job.counts?.total) === 1 ? '' : 's'} · the report is saved in Findings.`;
    else output.textContent = STATUS_DETAIL[status];
    $('scanimport-result').hidden = status !== 'done';
    if (status === 'done') renderResult(job);
    updateControls();
  }
  function errorMessage(error) {
    const message = text(error) || 'The import failed.';
    if (/model/i.test(message) && /(configur|choose|select|no )/i.test(message)) return `${message} Choose a model in Settings, then import the file again.`;
    return message;
  }
  function renderResult(job) {
    const counts = job.counts || {};
    $('scanimport-count-total').textContent = count(counts.total);
    $('scanimport-count-tp').textContent = count(counts.tp);
    $('scanimport-count-fp').textContent = count(counts.fp);
    $('scanimport-count-ambiguous').textContent = count(counts.ambiguous);
    const rows = (Array.isArray(job.findings) ? job.findings : []).map(finding => {
      const row = el('tr');
      const cell = (value, className) => { const td = el('td', className); if (value instanceof Node) td.append(value); else td.textContent = text(value); return td; };
      const severity = text(finding.severity).toUpperCase() || 'UNSPECIFIED';
      const badge = el('span', `severity-badge severity-${/^[A-Z]+$/.test(severity) ? severity : 'UNSPECIFIED'}`, severity);
      const disposition = text(finding.disposition).toUpperCase();
      const dispositionBadge = disposition ? el('span', `disposition-badge scanimport-disposition-${disposition === 'TRUE POSITIVE' ? 'tp' : disposition === 'FALSE POSITIVE' ? 'fp' : 'ambiguous'}`, disposition) : '—';
      row.append(cell(finding.id, 'scanimport-mono'), cell(finding.title, 'scanimport-wrap'), cell(badge), cell(dispositionBadge), cell(finding.confidence || '—'), cell(finding.location || '—', 'scanimport-mono scanimport-wrap'));
      return row;
    });
    if (!rows.length) { const row = el('tr'); const td = el('td', 'operations-empty-note', 'The report contained no findings.'); td.colSpan = 6; row.append(td); rows.push(row); }
    $('scanimport-findings').replaceChildren(...rows);
    setReportLinks(state.report);
    $('scanimport-post').disabled = !job.reportId;
    // scanners.js offers Post to DefectDojo / SonarQube for the same finished import.
    document.dispatchEvent(new CustomEvent('threatlint:scanimport-job', { detail: job }));
  }
  function setReportLinks(report) {
    for (const [id, url] of [['scanimport-download-md', report?.mdUrl], ['scanimport-download-docx', report?.docxUrl]]) {
      const link = $(id);
      if (url) { link.href = url; link.removeAttribute('aria-disabled'); link.removeAttribute('tabindex'); }
      else { link.removeAttribute('href'); link.setAttribute('aria-disabled', 'true'); link.tabIndex = -1; }
    }
    $('scanimport-download-docx').title = report && !report.docxUrl ? 'Word export is unavailable on this machine' : '';
    $('scanimport-open-report').disabled = !report;
  }
  // The finished import is a normal saved report: find its metadata (download and reader URLs) by id.
  async function resolveReport(job) {
    if (!job.reportId) { setReportLinks(null); return; }
    let found = null;
    if (job.report?.previewUrl) found = { report: job.report, sessionId: job.report.sessionId || job.workspaceId || null };
    else {
      try {
        const sessions = await api('/api/sessions');
        const preferred = job.workspaceId || $('scanimport-workspace').value;
        sessions.sort((a, b) => (b.id === preferred) - (a.id === preferred));
        for (const session of sessions) {
          const reports = await api(`/api/session/${encodeURIComponent(session.id)}/reports`).catch(() => []);
          const report = reports.find(item => item.id === job.reportId);
          if (report) { found = { report, sessionId: session.id }; break; }
        }
      } catch { /* shown below */ }
    }
    if (job.id !== state.jobId) return;
    state.report = found ? { ...found.report, sessionId: found.sessionId } : null;
    setReportLinks(state.report);
    if (!found) $('scanimport-status').textContent = 'Triage complete, but the saved report could not be found in any workspace. Refresh Findings, or import the file again.';
  }
  function openReport() {
    if (!state.report) return;
    document.dispatchEvent(new CustomEvent('threatlint:open-report', { detail: { sessionId: state.report.sessionId, previewUrl: state.report.previewUrl } }));
  }

  // ── ServiceNow ───────────────────────────────────────────────────────────
  function openServiceNow() {
    const job = state.job; if (!job || job.status !== 'done') return;
    const counts = job.counts || {};
    const fp = count(counts.fp), open = count(counts.tp) + count(counts.ambiguous);
    const title = text(job.title) || 'Scan import', target = text(job.target);
    $('scanimport-snow-summary').textContent = `${title}${target && !title.includes(target.replace(/^https?:\/\//, '')) ? ` · ${target}` : ''}${/\bfindings?\b/i.test(title) ? '' : ` · ${count(counts.total)} findings`}`;
    $('scanimport-snow-fp').textContent = `Close ${fp} false positive${fp === 1 ? '' : 's'} as Closed / False Positive with the Threatlint comment.`;
    $('scanimport-snow-open').textContent = `Add work notes to ${open} true positive and ambiguous finding${open === 1 ? '' : 's'} (${count(counts.tp)} true positive, ${count(counts.ambiguous)} ambiguous); they stay open.`;
    $('scanimport-snow-avit').value = state.avit || job.avit || normalizeAvit($('scanimport-avit').value);
    $('scanimport-snow-error').textContent = ''; $('scanimport-snow-result').replaceChildren();
    $('scanimport-snow-confirm').disabled = false; $('scanimport-snow-confirm').hidden = false;
    $('scanimport-snow-cancel').textContent = 'Cancel';
    $('scanimport-snow-dialog').showModal();
    $('scanimport-snow-avit').focus();
  }
  async function postServiceNow(event) {
    event.preventDefault();
    if (state.posting || !state.job) return;
    const avit = normalizeAvit($('scanimport-snow-avit').value);
    const invalid = avitError(avit, true);
    $('scanimport-snow-error').textContent = invalid;
    if (invalid) { $('scanimport-snow-avit').focus(); return; }
    state.posting = true; $('scanimport-snow-confirm').disabled = true;
    const result = $('scanimport-snow-result'); result.replaceChildren(el('p', 'field-note small', `Posting to ${avit}…`));
    try {
      const response = await api(`/api/scan-import/${encodeURIComponent(state.job.id)}/servicenow`, { method: 'POST', body: JSON.stringify({ avit, confirm: true }) });
      state.avit = avit;
      const actions = Array.isArray(response.actions) ? response.actions : [];
      const list = el('ul', 'scanimport-snow-actions');
      for (const action of actions) list.append(el('li', '', typeof action === 'string' ? action : [action.action || action.type, action.number || action.finding || action.id, action.detail || action.result || action.status].filter(Boolean).map(text).join(' · ')));
      result.replaceChildren(el('p', 'field-note small fp-status-ok', `Posted to ${avit}. ${actions.length} action${actions.length === 1 ? '' : 's'} applied:`), list);
      $('scanimport-snow-confirm').hidden = true; $('scanimport-snow-cancel').textContent = 'Close';
      toast(`Posted to ServiceNow ${avit}.`);
    } catch (error) {
      result.replaceChildren();
      let message = error.message;
      if (/not readable|cannot read|not found|no access|permission/i.test(message)) message += ' Check the AVIT number, or ask your ServiceNow administrator to give the integration account read access to it.';
      $('scanimport-snow-error').textContent = message;
      $('scanimport-snow-confirm').disabled = false;
    } finally { state.posting = false; }
  }

  // ── History ──────────────────────────────────────────────────────────────
  async function loadHistory() {
    const list = $('scanimport-history');
    let items;
    try { items = await api('/api/scan-import'); }
    catch (error) { list.replaceChildren(el('li', 'operations-empty-note fp-status-warn', `Import history is unavailable: ${error.message}`)); return; }
    items = Array.isArray(items) ? items : Array.isArray(items?.imports) ? items.imports : [];
    if (!items.length) { list.replaceChildren(el('li', 'operations-empty-note', 'No imports yet. Your imported scan reports appear here.')); return; }
    list.replaceChildren(...items.map(item => {
      const row = el('li', `report-card scanimport-history-item${item.id === state.jobId ? ' selected' : ''}`);
      const info = el('div', 'report-card-info');
      const counts = item.counts || {};
      const when = formatTime(item.createdAt || item.created || item.updatedAt);
      const meta = [sourceLabel(item.source), item.target ? text(item.target) : '', when, item.status === 'done' ? `${count(counts.tp)} TP · ${count(counts.fp)} FP · ${count(counts.ambiguous)} ambiguous` : ''].filter(Boolean).join(' · ');
      info.append(el('h3', 'operations-break', text(item.title) || 'Scan import'), el('p', 'operations-break', meta));
      if (item.status === 'error' && item.error) info.append(el('div', 'report-card-status', text(item.error)));
      const status = STATUS_LABELS[item.status] ? item.status : 'queued';
      const actions = el('div', 'report-card-actions');
      actions.append(el('span', `operations-pill scanimport-pill-${status}`, STATUS_LABELS[status].toUpperCase()),
        button(status === 'done' ? 'View result' : isLive(status) ? 'Follow' : 'Details', 'button secondary small-button', () => startJob(item, false), `View import ${text(item.title) || item.id}`));
      row.append(el('span', 'agent-monogram', ({ mobsf: 'MO', invicti: 'IN', defectdojo: 'DD', sonarqube: 'SQ' })[item.source] || 'SC'), info, actions);
      return row;
    }));
  }

  // ── Wiring ───────────────────────────────────────────────────────────────
  function wire() {
    const drop = $('scanimport-drop');
    $('scanimport-choose').addEventListener('click', () => $('scanimport-file').click());
    $('scanimport-file').addEventListener('change', event => { setFile(event.target.files[0]); event.target.value = ''; });
    $('scanimport-remove').addEventListener('click', clearFile);
    for (const type of ['dragenter', 'dragover']) drop.addEventListener(type, event => { event.preventDefault(); drop.classList.add('dragging'); });
    drop.addEventListener('dragleave', event => { if (!drop.contains(event.relatedTarget)) drop.classList.remove('dragging'); });
    drop.addEventListener('drop', event => {
      event.preventDefault(); drop.classList.remove('dragging');
      const files = event.dataTransfer?.files;
      if (files?.length > 1) { setError('Drop one scan report at a time.'); return; }
      setFile(files?.[0]);
    });
    // A file dropped outside the zone must not navigate the window away (browser and Electron alike).
    for (const type of ['dragover', 'drop']) window.addEventListener(type, event => { if (!drop.contains(event.target) && event.dataTransfer?.types?.includes('Files')) event.preventDefault(); });
    $('scanimport-form').addEventListener('submit', event => { submit(event).catch(error => setError(error.message)); });
    $('scanimport-avit').addEventListener('input', () => { if ($('scanimport-error').textContent.startsWith('Not an AVIT')) setError(''); });
    $('scanimport-workspace').addEventListener('change', () => { state.workspaceChosen = true; });
    $('scanimport-open-repo').addEventListener('click', () => $('choose-repo').click());
    $('scanimport-refresh').addEventListener('click', () => { void loadHistory(); void loadWorkspaces(); });
    $('scanimport-open-report').addEventListener('click', openReport);
    $('scanimport-post').addEventListener('click', openServiceNow);
    $('scanimport-snow-form').addEventListener('submit', postServiceNow);
    $('scanimport-snow-cancel').addEventListener('click', () => $('scanimport-snow-dialog').close());
    for (const id of ['scanimport-download-md', 'scanimport-download-docx']) $(id).addEventListener('click', event => { if (!$(id).getAttribute('href')) event.preventDefault(); });
    document.addEventListener('threatlint:context', event => {
      const previous = state.context?.session?.id; state.context = event.detail; updateControls();
      if (event.detail.session?.id && event.detail.session.id !== previous && !$('view-scanimport').hidden) { state.workspaceChosen = false; $('scanimport-workspace').value = ''; void loadWorkspaces(); }
    });
    document.addEventListener('threatlint:view', event => { if (event.detail.view === 'scanimport') { void loadWorkspaces(); void loadHistory(); } });
    document.dispatchEvent(new CustomEvent('threatlint:request-context'));
    if (!$('view-scanimport').hidden) { void loadWorkspaces(); void loadHistory(); }
  }
  if (!$('view-scanimport')) return;
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire, { once: true });
  else wire();
})();
