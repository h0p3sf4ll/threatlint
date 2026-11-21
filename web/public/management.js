'use strict';

// Organization integrations and ticket lifecycle. Secrets stay out of browser storage.
(async () => {
  const $ = id => document.getElementById(id);
  if (!$('view-management')) return;
  try { await window.ThreatlintProfile?.ready; } catch { return; }
  const profile = window.ThreatlintProfile;
  const state = { connections: [], providers: [], findings: [], access: null, category: 'general', reports: [], sessions: [], contextSession: null, ticket: null, initialized: false, busy: false };
  const fallbackProviders = [
    { id: 'jira', label: 'Jira Cloud', kind: 'tracker', fields: [{ name: 'baseUrl', label: 'Jira site URL', type: 'url', required: true, placeholder: 'https://your-company.atlassian.net' }, { name: 'username', label: 'Account email', type: 'email', required: true }, { name: 'project', label: 'Project key', required: true, placeholder: 'SEC' }, { name: 'issueType', label: 'Issue type', placeholder: 'Task' }, { name: 'closeTransitionId', label: 'False-positive close transition ID', placeholder: 'e.g. 31' }] },
    { id: 'azure-boards', label: 'Azure Boards', kind: 'tracker', fields: [{ name: 'organization', label: 'Organization', required: true }, { name: 'project', label: 'Project', required: true }, { name: 'issueType', label: 'Work item type', placeholder: 'Bug' }, { name: 'closeState', label: 'False-positive closed state', placeholder: 'Closed' }] },
    { id: 'github-issues', label: 'GitHub Issues', kind: 'tracker', fields: [{ name: 'repository', label: 'Repository', required: true, placeholder: 'owner/repository' }] },
    { id: 'github', label: 'GitHub', kind: 'scm', fields: [{ name: 'organization', label: 'Organization (optional)' }] },
    { id: 'azure-devops', label: 'Azure DevOps', kind: 'scm', fields: [{ name: 'organization', label: 'Organization', required: true }] },
  ];
  const node = (tag, cls, value) => { const n = document.createElement(tag); if (cls) n.className = cls; if (value !== undefined) n.textContent = value; return n; };
  function button(label, action, cls = 'button secondary small-button') { const b = node('button', cls, label); b.type = 'button'; b.addEventListener('click', () => action(b)); return b; }
  function option(value, label) { const n = node('option', '', label); n.value = value; return n; }
  function toast(message, error = false) { document.dispatchEvent(new CustomEvent('threatlint:toast', { detail: { message, error } })); }
  function navigate(view) { document.dispatchEvent(new CustomEvent('threatlint:navigate', { detail: { view } })); }
  async function api(path, { body, ...options } = {}) {
    const response = await (profile?.fetch || fetch)(path, { ...options, headers: { 'Content-Type': 'application/json', ...options.headers }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Request failed (${response.status})`);
    return result;
  }
  function can(permission) { return state.access?.permissions?.[permission] === true; }
  function providerFor(id) { return state.providers.find(p => p.id === id) || fallbackProviders.find(p => p.id === id); }
  function trackerConnections() { return state.connections.filter(c => c.kind === 'tracker' && c.enabled !== false); }
  function selectedConnectionLabel(c) { return `${c.name} · ${providerFor(c.provider)?.label || c.provider}${c.isDefault ? ' · default' : ''}`; }
  function chooseCategory(category) {
    if (!['general', 'integrations', 'scanners', 'access'].includes(category)) category = 'general';
    state.category = category;
    for (const panel of document.querySelectorAll('[data-settings-panel]')) panel.hidden = panel.dataset.settingsPanel !== category;
    for (const item of document.querySelectorAll('.settings-nav [data-settings-category]')) {
      item.classList.toggle('active', item.dataset.settingsCategory === category);
      item.setAttribute('aria-pressed', String(item.dataset.settingsCategory === category));
    }
    if (category === 'integrations') void loadConnections();
    if (category === 'access') void loadAccess();
  }
  function applyAccess() {
    for (const item of document.querySelectorAll('[data-management-admin]')) item.disabled = !can('manageSettings');
    for (const item of document.querySelectorAll('[data-management-write]')) item.disabled = !can('manageFindings');
    for (const form of document.querySelectorAll('.settings-sections > form')) {
      const allowed = form.id === 'settings-form' ? can('review') : can('manageSettings');
      form.inert = !allowed;
      form.classList.toggle('management-readonly', !allowed);
    }
    $('management-current-role').textContent = state.access?.role || 'Unavailable';
    document.body.classList.toggle('management-viewer', !can('review'));
    for (const id of ['runtime-scan-form', 'chat-form', 'fpreview-form', 'scanimport-form']) { const form = $(id); if (form) form.inert = !can('review'); }
    if ($('scm-connection-form')) $('scm-connection-form').inert = !can('review');
    let sourceNotice = $('management-source-role-notice');
    if (!sourceNotice) { sourceNotice = node('p', 'management-role-notice'); sourceNotice.id = 'management-source-role-notice'; $('scm-connection-form')?.before(sourceNotice); }
    sourceNotice.hidden = can('review'); sourceNotice.textContent = 'Viewer access allows reading saved findings and reports. Ask an administrator to enable reviews or source access.';
    let notice = $('management-role-notice');
    if (!notice) { notice = node('p', 'management-role-notice'); notice.id = 'management-role-notice'; document.querySelector('.settings-layout')?.before(notice); }
    notice.hidden = can('manageSettings'); notice.textContent = can('review') ? 'You can choose your review model. Ask an administrator to change shared integrations or saved service credentials.' : 'Viewer access can read these settings. Ask an administrator to change organization configuration.';
    const company = profile?.user?.company;
    $('management-scope').textContent = company ? `Shared with ${company.name}. Administrators manage connections; analysts can work with findings.` : 'Connections are saved in your workspace. Add separate named connections for each team or account.';
    $('management-access-scope').textContent = company ? `Roles apply within ${company.name}. Access is enforced by the server.` : 'This is your personal workspace. You have administrator access.';
  }
  async function loadAccess() {
    try {
      state.access = await api('/api/access');
      applyAccess(); renderMembers(); $('management-access-error').textContent = '';
    } catch (error) { $('management-access-error').textContent = error.message; }
  }
  function renderMembers() {
    const list = $('management-members'); list.replaceChildren();
    if (!can('manageMembers')) { $('management-members-note').textContent = 'Ask an administrator to change organization roles.'; return; }
    const members = Array.isArray(state.access.members) ? state.access.members : [];
    $('management-members-note').textContent = members.length ? 'Members appear after signing in. Role changes take effect on their next request.' : 'Company administrators can assign roles to members after they sign in. Personal workspaces have one owner.';
    if (!members.length) return;
    list.append(node('h3', '', 'Organization members'));
    for (const member of members) {
      const row = node('div', 'management-member'); const info = node('div');
      info.append(node('strong', '', member.displayName || member.email || member.userId), node('span', 'small subtle', member.email || member.userId));
      const select = node('select'); select.setAttribute('aria-label', `Role for ${member.displayName || member.email || member.userId}`);
      select.append(...(state.access.roles || ['administrator', 'analyst', 'viewer']).map(role => option(role, role)));
      select.value = member.role;
      const save = button('Save role', async b => {
        b.disabled = true;
        try { await api('/api/access/members', { method: 'POST', body: { userId: member.userId, role: select.value } }); await loadAccess(); toast('Member role updated.'); }
        catch (error) { $('management-access-error').textContent = error.message; b.disabled = false; }
      });
      row.append(info, select, save); list.append(row);
    }
  }
  async function loadConnections() {
    try {
      const payload = await api('/api/management/connections');
      state.connections = Array.isArray(payload.connections) ? payload.connections : [];
      state.providers = Array.isArray(payload.providers) && payload.providers.length ? payload.providers : fallbackProviders;
      renderConnections(); fillTrackerFilters(); $('management-connections-error').textContent = '';
    } catch (error) { $('management-connections-error').textContent = error.message; }
  }
  function renderConnections() {
    const list = $('management-connections'); list.replaceChildren();
    const kind = $('management-connection-kind').value;
    const entries = state.connections.filter(c => !kind || c.kind === kind);
    if (!entries.length) {
      const empty = node('div', 'management-empty'); empty.append(node('h3', '', 'Connect the tools your teams use.'), node('p', 'subtle', 'Add Jira, Azure Boards, or GitHub Issues for ticket management, and source control accounts for repository access.'));
      list.append(empty); return;
    }
    for (const connection of entries) {
      const card = node('article', 'management-connection'); const heading = node('div', 'management-connection-heading'); const info = node('div');
      info.append(node('strong', '', connection.name), node('p', 'subtle small', `${providerFor(connection.provider)?.label || connection.provider} · ${connection.kind === 'scm' ? 'Source control' : 'Issue tracker'}`));
      const status = node('span', `management-badge${connection.enabled === false ? ' muted' : ''}`, connection.enabled === false ? 'Disabled' : connection.isDefault ? 'Default' : 'Enabled');
      heading.append(info, status); card.append(heading);
      const scope = [connection.baseUrl, connection.organization, connection.project, connection.repository].filter(Boolean).join(' / ');
      if (scope) card.append(node('p', 'management-connection-scope subtle small', scope));
      const actions = node('div', 'management-actions');
      if (connection.kind === 'scm') {
        const activate = button('Use in Connect source', async b => {
          b.disabled = true;
          try { await api(`/api/management/connections/${encodeURIComponent(connection.id)}/activate`, { method: 'POST', body: {} }); navigate('sources'); $('scm-refresh-connections')?.click(); toast(`${connection.name} is ready in Connect source.`); }
          catch (error) { toast(error.message, true); } finally { b.disabled = !can('review') || connection.enabled === false; }
        }); activate.disabled = !can('review') || connection.enabled === false; actions.append(activate);
      }
      const test = button('Test', async b => { b.disabled = true; try { await api(`/api/management/connections/${encodeURIComponent(connection.id)}/test`, { method: 'POST', body: {} }); toast(`${connection.name} connected successfully.`); } catch (error) { toast(error.message, true); } finally { b.disabled = !can('manageSettings'); } });
      const edit = button('Edit', () => openConnection(connection));
      const remove = button('Remove', async b => {
        if (!confirm(`Remove ${connection.name}? Connections with tracked findings must be disabled instead to preserve history.`)) return;
        b.disabled = true;
        try { await api(`/api/management/connections/${encodeURIComponent(connection.id)}`, { method: 'DELETE' }); await loadConnections(); toast('Connection removed.'); }
        catch (error) { toast(error.message, true); b.disabled = false; }
      }, 'button secondary small-button management-danger');
      for (const control of [test, edit, remove]) { control.dataset.managementAdmin = ''; control.disabled = !can('manageSettings'); }
      actions.append(test, edit, remove); card.append(actions); list.append(card);
    }
  }
  function openConnection(connection = null) {
    if (!can('manageSettings')) return;
    $('management-connection-form').reset(); $('management-connection-id').value = connection?.id || '';
    $('management-connection-name').value = connection?.name || '';
    const select = $('management-connection-provider'); select.replaceChildren();
    for (const kind of ['tracker', 'scm']) {
      const group = node('optgroup'); group.label = kind === 'tracker' ? 'Issue trackers' : 'Source control';
      for (const p of state.providers.filter(item => item.kind === kind)) group.append(option(p.id, p.label));
      select.append(group);
    }
    select.value = connection?.provider || state.providers[0]?.id || 'jira'; select.disabled = !!connection;
    $('management-connection-enabled').checked = connection?.enabled !== false;
    $('management-connection-default').checked = connection?.isDefault === true;
    $('management-connection-token').value = ''; $('management-connection-token').required = !connection?.hasToken;
    $('management-token-note').textContent = connection?.hasToken ? 'A token is saved. Leave this field empty to keep it, or enter a replacement.' : 'The token is saved in the workspace runtime and is never returned to this page.';
    $('management-connection-title').textContent = connection ? 'Edit connection' : 'Add a connection';
    $('management-connection-error').textContent = ''; renderConnectionFields(connection); $('management-connection-dialog').showModal();
  }
  function renderConnectionFields(connection = {}) {
    connection = connection || {};
    const provider = providerFor($('management-connection-provider').value); const container = $('management-connection-fields'); container.replaceChildren();
    for (const field of provider?.fields || []) {
      if (!/^[A-Za-z][A-Za-z0-9]{0,50}$/.test(field.name) || field.name === 'token') continue;
      const id = `management-field-${field.name}`; const label = node('label', '', field.label || field.name); label.htmlFor = id;
      const input = node('input'); input.id = id; input.name = field.name; input.type = ['url', 'email', 'number', 'password'].includes(field.type) ? field.type : 'text'; input.required = !!field.required; input.maxLength = 1000; input.autocomplete = 'off'; input.placeholder = field.placeholder || ''; input.value = connection[field.name] || '';
      container.append(label, input);
      if (field.name === 'closeTransitionId') container.append(node('p', 'field-note small subtle', 'Choose the Jira workflow transition that closes a false positive. Closure also posts the reviewed evidence as a comment.'));
    }
  }
  async function saveConnection(event) {
    event.preventDefault(); if (!can('manageSettings')) return;
    const submit = $('management-save-connection'); submit.disabled = true; $('management-connection-error').textContent = '';
    try {
      const provider = providerFor($('management-connection-provider').value);
      const payload = { name: $('management-connection-name').value.trim(), provider: provider.id, kind: provider.kind, enabled: $('management-connection-enabled').checked, isDefault: $('management-connection-default').checked };
      const id = $('management-connection-id').value; if (id) payload.id = id;
      for (const input of $('management-connection-fields').querySelectorAll('input')) payload[input.name] = input.value.trim();
      const token = $('management-connection-token').value.trim(); if (token) payload.token = token;
      await api('/api/management/connections', { method: 'POST', body: payload }); $('management-connection-token').value = ''; $('management-connection-dialog').close(); await loadConnections(); toast('Connection saved.');
    } catch (error) { $('management-connection-error').textContent = error.message; }
    finally { submit.disabled = false; }
  }
  function fillTrackerFilters() {
    const select = $('management-tracker-filter'); const previous = select.value;
    select.replaceChildren(option('', 'All trackers'), ...state.connections.filter(c => c.kind === 'tracker').map(c => option(c.id, c.name))); select.value = previous;
  }
  function isFalsePositive(item) { return /false[ -]?positive/i.test(item.disposition || ''); }
  function isClosed(item) { return isFalsePositive(item) || /^(?:RESOLVED|REMEDIATED|CLOSED)$/i.test(item.disposition || '') || /closed|done|resolved|removed|completed/i.test(item.state || ''); }
  function safeLink(url, label) {
    let parsed; try { parsed = new URL(url); } catch { return node('span', '', label); }
    if (parsed.protocol !== 'https:') return node('span', '', label);
    const a = node('a', '', label); a.href = parsed.href; a.target = '_blank'; a.rel = 'noopener noreferrer'; return a;
  }
  async function loadFindings() {
    $('management-findings').setAttribute('aria-busy', 'true');
    try {
      const payload = await api('/api/management/findings'); state.findings = Array.isArray(payload.findings) ? payload.findings : [];
      if (Array.isArray(payload.connections)) state.connections = payload.connections;
      fillTrackerFilters(); renderFindings(); $('management-findings-error').textContent = '';
    } catch (error) { $('management-findings-error').textContent = error.message; }
    finally { $('management-findings').setAttribute('aria-busy', 'false'); }
  }
  function renderFindings() {
    $('management-count-total').textContent = state.findings.length;
    $('management-count-open').textContent = state.findings.filter(item => !isClosed(item)).length;
    $('management-count-fp').textContent = state.findings.filter(isFalsePositive).length;
    const search = $('management-search').value.trim().toLowerCase(); const selected = $('management-tracker-filter').value; const filter = $('management-state-filter').value;
    const rows = state.findings.filter(item => (!selected || item.connectionId === selected) && (!search || [item.title, item.externalId, item.findingId, item.provider].filter(Boolean).join(' ').toLowerCase().includes(search)) && (!filter || (filter === 'false-positive' ? isFalsePositive(item) : filter === 'closed' ? isClosed(item) : !isClosed(item))));
    const list = $('management-findings'); list.replaceChildren();
    if (!rows.length) {
      const empty = node('div', 'management-empty'); empty.append(node('h3', '', state.findings.length ? 'No tickets match these filters.' : 'Bring your findings into one view.'), node('p', 'subtle', state.findings.length ? 'Try another tracker, status, or search term.' : 'Connect an issue tracker in Settings, then create a ticket from a report or import existing ticket IDs.'));
      if (!state.findings.length) empty.append(button('Manage integrations', () => { navigate('settings'); chooseCategory('integrations'); }));
      list.append(empty); return;
    }
    for (const finding of rows) {
      const row = node('article', 'management-finding'); const info = node('div', 'management-finding-info'); const title = node('h3'); title.append(safeLink(finding.url, `${finding.externalId} · ${finding.title || 'Security finding'}`));
      const connection = state.connections.find(c => c.id === finding.connectionId);
      info.append(title, node('p', 'small subtle', `${connection?.name || 'Removed connection'} · ${providerFor(finding.provider)?.label || finding.provider}${finding.findingId ? ` · ${finding.findingId}` : ''}${finding.generated ? ' · Created by Threatlint' : ' · Imported'}`));
      const details = node('div', 'management-finding-meta'); details.append(node('span', 'management-badge', isFalsePositive(finding) ? 'False positive' : finding.state || 'Open'));
      if (finding.severity && finding.severity !== 'UNSPECIFIED') details.append(node('span', `management-severity severity-${String(finding.severity).toLowerCase()}`, finding.severity));
      if (finding.updatedAt) { const date = new Date(finding.updatedAt); if (!Number.isNaN(date.getTime())) details.append(node('span', 'small subtle', `Updated ${date.toLocaleDateString()}`)); }
      info.append(details); row.append(info);
      if (!isClosed(finding)) {
        const close = button('Close as false positive', () => openTicket('close', finding)); close.disabled = !can('manageFindings') || !connection || connection.enabled === false; row.append(close);
      }
      list.append(row);
    }
  }
  function fillTrackers(select) {
    const trackers = trackerConnections(); select.replaceChildren(option('', trackers.length ? 'Choose an issue tracker' : 'Add an issue tracker in Settings first'), ...trackers.map(c => option(c.id, selectedConnectionLabel(c))));
    select.value = trackers.find(c => c.isDefault)?.id || (trackers.length === 1 ? trackers[0].id : '');
  }
  async function openTicket(mode, finding = null) {
    if (!can('manageFindings')) return;
    state.ticket = { mode, finding }; $('management-ticket-form').reset(); $('management-ticket-error').textContent = ''; $('management-ticket-preview').textContent = '';
    const closing = mode === 'close'; $('management-ticket-title').textContent = closing ? `Close ${finding.externalId} as false positive` : 'Create a ticket';
    $('management-ticket-eyebrow').textContent = closing ? 'EVIDENCE-BACKED CLOSURE' : 'FINDING TO TICKET';
    $('management-ticket-description').textContent = closing ? `Select the false-positive review for this exact ticket. Its Original finding field must name ${finding.reviewReference || finding.externalId} or the full ticket URL. The server verifies the decision and evidence.` : 'Choose a saved finding and the tracker that owns remediation.';
    $('management-ticket-tracker-row').hidden = closing; $('management-ticket-tracker').required = !closing; fillTrackers($('management-ticket-tracker'));
    $('management-close-confirm-row').hidden = !closing; $('management-close-confirm').required = closing;
    $('management-ticket-submit').textContent = closing ? 'Confirm false-positive closure' : 'Create ticket';
    $('management-ticket-note').textContent = closing ? 'Only a verified FALSE POSITIVE review can close this ticket.' : 'The ticket includes the finding and its report reference.';
    $('management-ticket-workspace').replaceChildren(option('', 'Loading workspaces…')); $('management-ticket-report').replaceChildren(); $('management-ticket-finding').replaceChildren();
    $('management-ticket-dialog').showModal();
    try {
      state.sessions = await api('/api/sessions');
      const sessions = state.sessions.filter(s => s.reportCount > 0);
      $('management-ticket-workspace').replaceChildren(option('', sessions.length ? 'Choose a report workspace' : 'Run a review first to create a saved report'), ...sessions.map(s => option(s.id, String(s.repoPath).split(/[\\/]/).filter(Boolean).slice(-2).join('/'))));
      const selected = sessions.find(s => s.id === (state.ticket.finding?.sessionId || state.contextSession))?.id || sessions[0]?.id || ''; $('management-ticket-workspace').value = selected;
      if (selected) await loadTicketReports();
    } catch (error) { $('management-ticket-error').textContent = error.message; }
  }
  async function loadTicketReports() {
    const workspace = $('management-ticket-workspace').value; state.reports = [];
    $('management-ticket-report').replaceChildren(option('', 'Loading reports…')); $('management-ticket-finding').replaceChildren(); $('management-ticket-preview').textContent = '';
    if (!workspace) { $('management-ticket-report').replaceChildren(option('', 'Choose a workspace first')); return; }
    try {
      const reports = await api(`/api/session/${encodeURIComponent(workspace)}/reports`);
      if (workspace !== $('management-ticket-workspace').value) return;
      state.reports = reports.filter(report => state.ticket.mode !== 'close' || report.agentId === 'appsec-fp-reviewer');
      $('management-ticket-report').replaceChildren(option('', state.reports.length ? 'Choose a report' : state.ticket.mode === 'close' ? 'No false-positive reviews in this workspace' : 'No saved reports'), ...state.reports.map(r => option(r.id, `${r.title || r.label} · ${new Date(r.timestamp).toLocaleString()}`)));
      const matching = state.reports.find(r => r.id === state.ticket.finding?.reportId)?.id || state.reports[0]?.id || ''; $('management-ticket-report').value = matching; fillTicketFindings();
    } catch (error) { $('management-ticket-error').textContent = error.message; }
  }
  function fillTicketFindings() {
    const report = state.reports.find(r => r.id === $('management-ticket-report').value);
    const findings = (report?.findings || []).filter(f => state.ticket.mode !== 'close' || (f.disposition === 'FALSE POSITIVE' && !f.unverified));
    $('management-ticket-finding').replaceChildren(option('', findings.length ? 'Choose a finding' : state.ticket.mode === 'close' ? 'No verified false positives in this report' : 'No structured findings in this report'), ...findings.map(f => option(f.id, `${f.id} · ${f.title}`)));
    $('management-ticket-finding').value = findings.find(f => f.id === state.ticket.finding?.findingId)?.id || findings[0]?.id || ''; updateTicketPreview();
  }
  function updateTicketPreview() {
    const report = state.reports.find(r => r.id === $('management-ticket-report').value); const finding = report?.findings?.find(f => f.id === $('management-ticket-finding').value);
    $('management-ticket-preview').textContent = finding ? [finding.severity, finding.disposition, ...(finding.evidence || []).slice(0, 2)].filter(Boolean).join(' · ') : '';
  }
  async function submitTicket(event) {
    event.preventDefault(); if (!can('manageFindings')) return;
    const b = $('management-ticket-submit'); b.disabled = true; $('management-ticket-error').textContent = '';
    try {
      const closing = state.ticket.mode === 'close';
      const body = { reportId: $('management-ticket-report').value, findingId: $('management-ticket-finding').value, ...(closing ? { confirm: $('management-close-confirm').checked } : { connectionId: $('management-ticket-tracker').value }) };
      const path = closing ? `/api/management/findings/${encodeURIComponent(state.ticket.finding.id)}/close` : '/api/management/findings/create';
      await api(path, { method: 'POST', body }); $('management-ticket-dialog').close(); await loadFindings(); toast(closing ? 'False-positive closure confirmed by the tracker.' : 'Ticket created and linked to the finding.');
    } catch (error) { $('management-ticket-error').textContent = error.message; }
    finally { b.disabled = false; }
  }
  async function syncFindings(buttonNode) {
    buttonNode.disabled = true; $('management-findings-error').textContent = ''; $('management-sync-status').textContent = 'Reading the latest ticket status…';
    try {
      const errors = []; let cursor = null; let pages = 0; let synced = 0;
      const connectionId = $('management-tracker-filter').value;
      do {
        const payload = await api('/api/management/findings/sync', { method: 'POST', body: { ...(connectionId ? { connectionId } : {}), ...(cursor ? { cursor } : {}) } });
        errors.push(...(Array.isArray(payload.errors) ? payload.errors : [])); synced += payload.findings?.length || 0;
        cursor = payload.nextCursor || null; pages++;
        $('management-sync-status').textContent = `Synced ${synced} ticket${synced === 1 ? '' : 's'}${payload.total ? ` of ${payload.total}` : ''}…`;
      } while (cursor && pages < 100);
      if (cursor) errors.push({ id: 'Sync', error: 'More tickets remain. Run sync again to continue.' });
      await loadFindings();
      $('management-sync-status').textContent = errors.length ? `Sync finished with ${errors.length} ticket${errors.length === 1 ? '' : 's'} requiring attention. Successful updates are shown.` : 'Ticket status is up to date.';
      if (errors.length) $('management-findings-error').textContent = errors.map(e => `${e.id || 'Ticket'}: ${e.error || 'Could not sync'}`).join(' · ');
    } catch (error) { $('management-sync-status').textContent = ''; $('management-findings-error').textContent = error.message; }
    finally { buttonNode.disabled = !can('manageFindings'); }
  }
  for (const item of document.querySelectorAll('[data-settings-category]')) item.addEventListener('click', () => chooseCategory(item.dataset.settingsCategory));
  $('management-add-connection').addEventListener('click', () => openConnection()); $('management-refresh-connections').addEventListener('click', loadConnections); $('management-connection-kind').addEventListener('change', renderConnections);
  $('management-connection-dialog').addEventListener('close', () => { $('management-connection-token').value = ''; });
  $('management-connection-provider').addEventListener('change', () => renderConnectionFields()); $('management-connection-form').addEventListener('submit', saveConnection);
  $('management-configure').addEventListener('click', () => { navigate('settings'); chooseCategory('integrations'); });
  $('management-refresh').addEventListener('click', loadFindings); $('management-search').addEventListener('input', renderFindings); $('management-tracker-filter').addEventListener('change', renderFindings); $('management-state-filter').addEventListener('change', renderFindings); $('management-sync').addEventListener('click', event => syncFindings(event.currentTarget));
  $('management-create').addEventListener('click', () => openTicket('create')); $('management-ticket-workspace').addEventListener('change', loadTicketReports); $('management-ticket-report').addEventListener('change', fillTicketFindings); $('management-ticket-finding').addEventListener('change', updateTicketPreview); $('management-ticket-form').addEventListener('submit', submitTicket);
  $('management-import').addEventListener('click', () => { if (!can('manageFindings')) return; $('management-import-form').reset(); fillTrackers($('management-import-tracker')); $('management-import-error').textContent = ''; $('management-import-dialog').showModal(); });
  $('management-import-form').addEventListener('submit', async event => {
    event.preventDefault(); const b = $('management-import-submit'); b.disabled = true; $('management-import-error').textContent = '';
    try {
      const payload = await api('/api/management/findings/import', { method: 'POST', body: { connectionId: $('management-import-tracker').value, ids: $('management-import-ids').value } });
      await loadFindings();
      if (payload.errors?.length) $('management-import-error').textContent = `${payload.findings?.length || 0} imported. ${payload.errors.map(e => `${e.id}: ${e.error}`).join(' · ')}`;
      else { $('management-import-dialog').close(); toast('Tickets imported.'); }
    }
    catch (error) { $('management-import-error').textContent = error.message; } finally { b.disabled = false; }
  });
  document.addEventListener('threatlint:view', event => {
    if (event.detail.view === 'settings') { chooseCategory(state.category); void loadAccess(); }
    if (event.detail.view === 'management') { void Promise.all([loadConnections(), loadFindings(), loadAccess()]).then(() => { renderConnections(); renderFindings(); }); }
  });
  document.addEventListener('threatlint:settings-section', event => { const section = event.detail.section; chooseCategory(section === 'integrations' ? 'integrations' : section === 'access' ? 'access' : (['servicenow', 'semgrep', 'ado', 'github', 'defectdojo', 'sonarqube'].includes(section) || section?.startsWith('tracker-')) ? 'scanners' : 'general'); });
  document.addEventListener('threatlint:context', event => { state.contextSession = event.detail.session?.id || null; });
  document.addEventListener('threatlint:ticket-create', async event => {
    await loadConnections();
    await openTicket('create', event.detail);
  });
  await loadAccess();
  if (!state.providers.length) state.providers = fallbackProviders; applyAccess(); chooseCategory(state.category);
  if (!$('view-management').hidden) { await loadConnections(); await loadFindings(); }
})();
