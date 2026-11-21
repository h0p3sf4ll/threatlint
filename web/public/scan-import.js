'use strict';

/**
 * Triage a scan report: upload a PDF or supported XML/JSON export, follow its triage, open or download
 * the saved findings report, and post the outcome to ServiceNow. Independent of app.js state; workspace and
 * model come from threatlint:context, and reports open through threatlint:open-report.
 * CSP-safe: DOM nodes and textContent only. Every value from a scan report is rendered as text.
 */
(() => {
  const $ = id => document.getElementById(id);
  // The scan import endpoint accepts files up to 25 MB before base64 encoding.
  const MAX_BYTES = 25 * 1024 * 1024;
  const MAX_EVIDENCE_CHARS = 16_000;
  const POLL_MS = 1000;
  const STEPS = ['queued', 'parsing', 'triaging', 'done'];
  const STATUS_LABELS = { queued: 'Queued', parsing: 'Parsing', triaging: 'Triaging', done: 'Done', error: 'Error' };
  const STATUS_DETAIL = { queued: 'Queued. The runner starts it shortly.', parsing: 'Parsing the report into findings…', triaging: 'Triaging each finding against the evidence…' };
  const SOURCES = { invicti: 'Invicti', mobsf: 'MobSF', defectdojo: 'DefectDojo', sonarqube: 'SonarQube', generic: 'PDF report', auto: 'Auto-detect' };
  const AVIT = /^AVIT\d{7,15}$/;
  const TICKET = /^(?:(?:AVIT|ISST)\d{7,15}|SCTASK\d{7,10})$/;
  const state = { workspaceChosen: false, file: null, context: null, job: null, jobId: null, pollTimer: null, lastStep: 'queued', report: null, submitting: false, posting: false, snow: null };

  // Help for this page, merged into /api/help by insights.js (server entries win on a shared key or id).
  window.ThreatlintHelpExtras = {
    tooltips: {
      'scanimport-source': 'Use Auto-detect for PDF reports and supported XML or JSON exports. Choose a specific format if you know which export you have.',
      'scanimport-workspace': 'For source-based review, pick the workspace at the scanned revision. For findings about a deployed service, add evidence from the matching environment.',
      'scanimport-avit': 'Optional ServiceNow destination. Enter an AVIT, ISST, or SCTASK now or when you post.',
      'scanimport-servicenow': 'Choose an AVIT, ISST, or SCTASK and confirm the attachment. Scan imports keep the existing AVIT verdict workflow. ISST and SCTASK posting attaches the report only.',
      'scanimport-disposition': 'TRUE POSITIVE = supported or retained as unverified when safety is not proven. FALSE POSITIVE = evidence disproves the finding beyond reasonable doubt.',
    },
    topics: [{ id: 'scan-import', title: 'Triage a scan report (Finding Review)', minutes: 2, steps: [
      'Export a detailed report with individual findings. Choose PDF with selectable text, or use a supported XML or JSON export.',
      'Open Test → Triage a scan report and drop the file, or press Choose file.',
      'Leave Report format on Auto-detect unless you know the export format. Select the workspace at the scanned revision, or add sanitized evidence from the matching deployment.',
      'Choose a model in Settings and authorize remote sharing if needed. Press Triage findings to review the evidence. Without a model, the import extracts findings for later review.',
      'Review the counts and the findings table, then press Open report, or download it as Markdown or Word. It is also listed in Findings.',
      'To post a result, choose a connected tracker and review what will change before confirming.',
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
    const response = await (window.ThreatlintProfile?.fetch || fetch)(url, { cache: 'no-store', ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
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
  function normalizeTicket(value) { return text(value).trim().toUpperCase(); }
  function ticketError(value, required) {
    if (!value) return required ? 'Enter an AVIT, ISST, or SCTASK number to post to.' : '';
    return TICKET.test(value) ? '' : `Invalid ServiceNow ticket number: ${value}. Use an AVIT or ISST with 7 to 15 digits, or an SCTASK with 7 to 10 digits.`;
  }

  // ── Form ─────────────────────────────────────────────────────────────────
  function setError(message, { reveal = false } = {}) {
    const alert = $('scanimport-error');
    alert.textContent = message || '';
    if (message && reveal && !$('view-scanimport').hidden) alert.scrollIntoView({ block: 'nearest' });
  }
  function setAvitError(message) {
    $('scanimport-avit-error').textContent = message;
    if (message) $('scanimport-avit').setAttribute('aria-invalid', 'true');
    else $('scanimport-avit').removeAttribute('aria-invalid');
  }
  const reviewSettings = () => state.context?.ready ? state.context.settings : null;
  const MODEL_REVIEW_HINT = 'Choose a model in Settings and authorize remote sharing if needed.';
  function updateControls() {
    const start = $('scanimport-start');
    const settings = reviewSettings();
    start.disabled = !state.file || state.submitting || isLive(state.job?.status);
    start.textContent = settings ? 'Triage findings' : 'Import without review';
    const model = state.context?.models?.review || settings?.model;
    $('scanimport-model').textContent = settings ? `Review model: ${model || settings.provider}.` : MODEL_REVIEW_HINT;
  }
  function setFile(file) {
    if (!file) return;
    if (!/\.(pdf|xml|json)$/i.test(file.name)) { rejectFile(`Unsupported file: ${file.name}. Choose a PDF report or a supported XML or JSON export.`); return; }
    if (!file.size) { rejectFile(`${file.name} is empty. Export the scan report again.`); return; }
    if (file.size > MAX_BYTES) { rejectFile(`${file.name} is ${(file.size / 1024 / 1024).toFixed(1)} MB. The limit is 25 MB. Export a smaller report or split it.`); return; }
    setError('');
    state.file = file;
    $('scanimport-file-name').textContent = `${file.name} · ${file.size < 1024 * 1024 ? `${Math.max(1, Math.round(file.size / 1024))} KB` : `${(file.size / 1024 / 1024).toFixed(1)} MB`}`;
    $('scanimport-file-name').title = file.name;
    $('scanimport-remove').classList.remove('hidden');
    $('scanimport-drop').classList.add('has-file');
    updateControls();
  }
  function clearFile() {
    setError('');
    state.file = null; $('scanimport-file').value = '';
    $('scanimport-file-name').textContent = 'No file selected'; $('scanimport-file-name').title = '';
    $('scanimport-remove').classList.add('hidden'); $('scanimport-drop').classList.remove('has-file');
    updateControls();
  }
  function rejectFile(message) {
    clearFile();
    setError(message);
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
    const file = state.file;
    if (!file) { setError('Choose a scan report first.', { reveal: true }); return; }
    const number = normalizeTicket($('scanimport-avit').value);
    const invalid = ticketError(number, false);
    setAvitError(invalid);
    if (invalid) { $('scanimport-avit').focus(); return; }
    const evidenceInput = $('scanimport-evidence');
    const evidenceDraft = evidenceInput.value;
    const supportingEvidence = evidenceDraft.trim();
    if (supportingEvidence.length > MAX_EVIDENCE_CHARS) { setError('Keep supporting evidence to 16,000 characters or fewer.', { reveal: true }); return; }
    if (supportingEvidence && !reviewSettings()) { setError(`Supporting evidence requires model review. ${MODEL_REVIEW_HINT}`, { reveal: true }); return; }
    state.submitting = true; updateControls();
    try {
      const content = await readBase64(file);
      // The shared ready flag includes the user's session consent for remote model review.
      const settings = reviewSettings();
      if (supportingEvidence && !settings) throw new Error(`Supporting evidence requires model review. ${MODEL_REVIEW_HINT}`);
      const body = { ...settings, filename: file.name, content, source: $('scanimport-source').value };
      if ($('scanimport-workspace').value) body.workspaceId = $('scanimport-workspace').value;
      if (number) body[AVIT.test(number) ? 'avit' : 'number'] = number;
      if (supportingEvidence) body.supportingEvidence = supportingEvidence;
      const created = await api('/api/scan-import', { method: 'POST', body: JSON.stringify(body) });
      $('scanimport-avit').value = number;
      startJob({ id: created.id, status: created.status || 'queued', source: body.source, title: file.name, number }, true);
      if (evidenceInput.value === evidenceDraft) evidenceInput.value = '';
      if (state.file === file) clearFile();
    } catch (error) {
      if (state.file === file) setError(error.message, { reveal: true });
    }
    finally { state.submitting = false; updateControls(); }
  }

  // ── Progress and result ──────────────────────────────────────────────────
  function isLive(status) { return ['queued', 'parsing', 'triaging'].includes(status); }
  function startJob(job, fresh) {
    clearTimeout(state.pollTimer);
    state.jobId = job.id; state.job = job; state.report = null; state.lastStep = 'queued';
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
    $('scanimport-job-title').textContent = text(job.title) || 'Triaging scan report';
    $('scanimport-job-target').textContent = job.target ? `Target · ${text(job.target)}` : '';
    const pill = $('scanimport-job-status'); pill.textContent = STATUS_LABELS[status].toUpperCase(); pill.className = `operations-pill scanimport-pill-${status}`;
    renderSteps(status);
    const output = $('scanimport-status');
    const total = count(job.counts?.total);
    const parsedOnly = status === 'done' && total > 0 && job.reviewedCount === 0;
    const warning = ['triaging', 'done'].includes(status) ? text(job.warning) : '';
    output.classList.toggle('scanimport-status-error', status === 'error');
    output.classList.toggle('fp-status-warn', parsedOnly || !!warning);
    if (status === 'error') output.textContent = errorMessage(job.error);
    else if (status === 'done') {
      const summary = parsedOnly ? 'Report saved without model review' : 'Triage complete';
      const reportStatus = job.reportUnavailable ? 'The saved report has been removed from Findings.' : 'Saved in Findings.';
      output.textContent = `${summary} · ${total} finding${total === 1 ? '' : 's'}. ${reportStatus}${warning ? ` ${warning}` : ''}`;
    } else output.textContent = warning || STATUS_DETAIL[status];
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
    const legacy = counts.unverified == null && counts.ambiguous != null;
    $('scanimport-count-unverified').textContent = count(legacy ? counts.ambiguous : counts.unverified);
    $('scanimport-count-unverified-label').textContent = legacy ? 'Ambiguous' : 'Unverified true positives';
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
      if (url) { link.href = window.ThreatlintProfile?.url?.(url) || url; link.removeAttribute('aria-disabled'); link.removeAttribute('tabindex'); }
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
    if (state.job?.reportUnavailable) return;
    state.report = found ? { ...found.report, sessionId: found.sessionId } : null;
    setReportLinks(state.report);
    if (!found) $('scanimport-status').textContent = 'Triage complete, but the saved report could not be found in any workspace. Refresh Findings, or import the file again.';
  }
  function openReport() {
    if (!state.report) return;
    document.dispatchEvent(new CustomEvent('threatlint:open-report', { detail: { sessionId: state.report.sessionId, previewUrl: state.report.previewUrl } }));
  }

  // ── ServiceNow ───────────────────────────────────────────────────────────
  function updateServiceNowSteps() {
    const number = normalizeTicket($('scanimport-snow-avit').value);
    const counts = state.snow?.counts;
    const avitUpdate = Boolean(counts && count(counts.total) && AVIT.test(number));
    const unverified = count(counts?.unverified);
    $('scanimport-snow-attachment').textContent = avitUpdate ? 'Attach the Word report to the AVIT.' : 'Attach the saved review. Uses Word when available and Markdown otherwise.';
    $('scanimport-snow-verdict').textContent = avitUpdate
      ? count(counts.fp) === count(counts.total) ? 'Close this AVIT as Closed / False Positive after its evidence is attached.'
        : `Add a work note on this AVIT${unverified ? ` (${unverified} unverified finding${unverified === 1 ? '' : 's'})` : ''}.`
      : 'Attachment only.';
  }

  function openServiceNow(report) {
    if (state.posting || $('scanimport-snow-dialog').open) return;
    if (report) {
      if (!report.id || report.agentId !== 'appsec-fp-reviewer') return;
      state.snow = { reportId: report.id };
      $('scanimport-snow-summary').textContent = text(report.title || report.label || 'Finding Review');
      $('scanimport-snow-avit').value = '';
    } else {
      const job = state.job;
      if (job?.status !== 'done' || !job.reportId || job.reportUnavailable) return;
      state.snow = { jobId: job.id, reportId: job.reportId, counts: job.counts };
      $('scanimport-snow-summary').textContent = text(job.title || 'Scan import');
      const savedNumber = job.number || (typeof job.avit === 'string' ? job.avit : '');
      $('scanimport-snow-avit').value = savedNumber || normalizeTicket($('scanimport-avit').value);
    }
    updateServiceNowSteps();
    $('scanimport-snow-error').textContent = ''; $('scanimport-snow-result').replaceChildren();
    $('scanimport-snow-confirm').disabled = false; $('scanimport-snow-confirm').hidden = false;
    $('scanimport-snow-cancel').textContent = 'Cancel';
    $('scanimport-snow-dialog').showModal();
    $('scanimport-snow-avit').focus();
  }
  async function postServiceNow(event) {
    event.preventDefault();
    const destination = state.snow;
    if (state.posting || !destination) return;
    const number = normalizeTicket($('scanimport-snow-avit').value);
    const invalid = ticketError(number, true);
    $('scanimport-snow-error').textContent = invalid;
    if (invalid) { $('scanimport-snow-avit').focus(); return; }
    state.posting = true; $('scanimport-snow-confirm').disabled = true;
    const result = $('scanimport-snow-result'); result.replaceChildren(el('p', 'field-note small', `Posting to ${number}…`));
    try {
      const url = destination.jobId ? `/api/scan-import/${encodeURIComponent(destination.jobId)}/servicenow` : '/api/servicenow/attach-review';
      const body = destination.jobId && AVIT.test(number) ? { avit: number } : { number, ...(!destination.jobId ? { reportId: destination.reportId } : {}) };
      const response = await api(url, { method: 'POST', body: JSON.stringify({ ...body, confirm: true }) });
      if (destination.jobId && state.job?.id === destination.jobId) state.job = { ...state.job, number };
      const actions = Array.isArray(response.actions) ? response.actions : [];
      const list = el('ul', 'scanimport-snow-actions');
      for (const action of actions) list.append(el('li', '', typeof action === 'string' ? action : [action.action || action.type, action.number || action.finding || action.id, action.detail || action.result || action.status].filter(Boolean).map(text).join(' · ')));
      result.replaceChildren(el('p', `field-note small ${response.ok === false ? 'fp-status-warn' : 'fp-status-ok'}`, response.ok === false ? `Review the outcome for ${number}.` : `Posted to ${number}.`), list);
      $('scanimport-snow-confirm').hidden = true; $('scanimport-snow-cancel').textContent = 'Close';
      if (response.ok !== false) toast(`Posted to ServiceNow ${number}.`);
    } catch (error) {
      result.replaceChildren();
      let message = error.message;
      if (/not readable|cannot read|not found|no access|permission/i.test(message)) message += ' Check the ticket number and the integration account’s access.';
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
      const reviewCount = counts.unverified == null && counts.ambiguous != null ? `${count(counts.ambiguous)} ambiguous` : `${count(counts.unverified)} unverified TP`;
      const meta = [sourceLabel(item.source), item.target ? text(item.target) : '', when, item.status === 'done' ? `${count(counts.tp)} TP · ${count(counts.fp)} FP · ${reviewCount}` : ''].filter(Boolean).join(' · ');
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
      if (files?.length > 1) { rejectFile('Drop one scan report at a time.'); return; }
      setFile(files?.[0]);
    });
    // A file dropped outside the zone must not navigate the window away (browser and Electron alike).
    for (const type of ['dragover', 'drop']) window.addEventListener(type, event => { if (!drop.contains(event.target) && event.dataTransfer?.types?.includes('Files')) event.preventDefault(); });
    $('scanimport-form').addEventListener('submit', event => { submit(event).catch(error => setError(error.message, { reveal: true })); });
    $('scanimport-avit').addEventListener('input', () => setAvitError(''));
    $('scanimport-workspace').addEventListener('change', () => { state.workspaceChosen = true; });
    $('scanimport-open-repo').addEventListener('click', () => $('choose-repo').click());
    $('scanimport-refresh').addEventListener('click', () => { void loadHistory(); void loadWorkspaces(); });
    $('scanimport-open-report').addEventListener('click', openReport);
    $('scanimport-post').addEventListener('click', () => openServiceNow());
    document.addEventListener('threatlint:attach-review-servicenow', event => openServiceNow(event.detail));
    $('scanimport-snow-avit').addEventListener('input', () => { $('scanimport-snow-error').textContent = ''; updateServiceNowSteps(); });
    $('scanimport-snow-form').addEventListener('submit', postServiceNow);
    $('scanimport-snow-cancel').addEventListener('click', () => $('scanimport-snow-dialog').close());
    for (const id of ['scanimport-download-md', 'scanimport-download-docx']) $(id).addEventListener('click', event => { if (!$(id).getAttribute('href')) event.preventDefault(); });
    document.addEventListener('threatlint:context', event => {
      const previous = state.context?.session?.id; state.context = event.detail; updateControls();
      if (event.detail.session?.id && event.detail.session.id !== previous && !$('view-scanimport').hidden) { state.workspaceChosen = false; $('scanimport-workspace').value = ''; void loadWorkspaces(); }
    });
    document.addEventListener('threatlint:report-deleted', event => {
      if (state.job?.reportId !== event.detail?.reportId) return;
      state.report = null;
      state.job = { ...state.job, reportId: null, reportUnavailable: true, report: null };
      renderJob(state.job);
    });
    document.addEventListener('threatlint:view', event => { if (event.detail.view === 'scanimport') { void loadWorkspaces(); void loadHistory(); } });
    document.dispatchEvent(new CustomEvent('threatlint:request-context'));
    if (!$('view-scanimport').hidden) { void loadWorkspaces(); void loadHistory(); }
  }
  if (!$('view-scanimport')) return;
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire, { once: true });
  else wire();
})();
