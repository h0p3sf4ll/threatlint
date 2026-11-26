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
    if (response.status === 401 && profile?.web) location.replace('/login');
    const result = await response.json();
    if (!response.ok) throw Object.assign(new Error(result.error || `Request failed (${response.status})`), { status: response.status });
    return result;
  }
  function can(permission) { return state.access?.permissions?.[permission] === true; }
  const issuePull = { sources: [], selected: new Set(), types: new Map(), results: new Map(), controls: [], busy: false, loading: false, version: 0 };
  const avits = { items: [], filters: {}, nextOffset: null, busy: false, dirty: true };
  function initializeAvits() {
    // Share the Metrics filter form so field names, choice values, and available filters stay aligned.
    const form = $('avit-aggregate-form').cloneNode(true);
    form.reset();
    for (const element of [form, ...form.querySelectorAll('[id]')]) if (element.id) element.id = `management-${element.id}`;
    form.id = 'management-avit-form';
    for (const input of form.querySelectorAll('[list]')) input.setAttribute('list', `management-${input.getAttribute('list')}`);
    form.querySelectorAll('datalist').forEach(list => list.replaceChildren());
    const submit = form.querySelector('[type="submit"]'); submit.disabled = false; submit.textContent = 'Load AVITs';
    const note = form.querySelector('#management-avit-aggregate-dirty'); note.textContent = 'Filters apply to AVIT records in ServiceNow.';
    const project = form.elements.namedItem('project');
    const syncScm = () => { const ado = form.elements.namedItem('scm').value === 'ado'; project.closest('label').hidden = !ado; if (!ado) project.value = ''; };
    syncScm(); form.elements.namedItem('scm').addEventListener('change', syncScm);
    form.addEventListener('input', () => { avits.dirty = true; $('management-avits-more').disabled = true; note.textContent = 'Filters changed. Load AVITs to update the records.'; invalidateIssuePull(); });
    form.addEventListener('submit', event => { event.preventDefault(); void loadAvits(false); });
    form.querySelector('#management-avit-aggregate-configure').addEventListener('click', () => document.dispatchEvent(new CustomEvent('threatlint:settings-open', { detail: { section: 'servicenow' } })));
    $('management-avit-filters').append(form);
    $('management-avits-more').addEventListener('click', () => { void loadAvits(true); });
    for (const field of ['organization', 'project', 'repository', 'branch']) {
      const input = form.elements.namedItem(field); let timer, controller, version = 0;
      const suggest = async () => {
        const current = ++version; controller?.abort(); controller = new AbortController();
        const params = new URLSearchParams({ field, q: input.value.trim() });
        for (const name of ['scm', 'organization', 'project', 'repository', 'branch']) {
          const value = form.elements.namedItem(name).value.trim(); if (name !== field && value) params.set(name, value);
        }
        try {
          const result = await api(`/api/trackers/servicenow-avit/context-values?${params}`, { signal: controller.signal });
          if (current === version) $(input.getAttribute('list')).replaceChildren(...(result.values || []).map(value => option(value, value)));
        } catch { if (current === version) $(input.getAttribute('list')).replaceChildren(); }
      };
      input.addEventListener('focus', () => { void suggest(); });
      input.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(suggest, 250); });
    }
  }
  async function loadAvits(append) {
    if (avits.busy || (issuePull.busy && issuePull.selected.has('servicenow-avit')) || (append && (avits.dirty || avits.nextOffset === null))) return;
    const filters = append ? avits.filters : Object.fromEntries([...new FormData($('management-avit-form'))].filter(([, value]) => value.trim()).map(([key, value]) => [key, value.trim()]));
    if (filters.scm !== 'ado') delete filters.project;
    avits.busy = true; $('management-avit-error').textContent = '';
    $('management-avit-form').querySelector('[type="submit"]').disabled = true;
    $('management-avits-more').disabled = true;
    $('management-avit-status').textContent = 'Loading AVITs from ServiceNow…';
    // Keep the filter set fixed while a page is in flight.
    for (const input of $('management-avit-form').querySelectorAll('input, select')) input.disabled = true;
    try {
      const result = await api('/api/trackers/servicenow-avit/items', { method: 'POST', body: { filters, offset: append ? avits.nextOffset : 0 } });
      if (!Array.isArray(result.items)) throw new Error('Invalid AVIT response');
      avits.items = [...new Map((append ? [...avits.items, ...result.items] : result.items).map(item => [item.id, item])).values()];
      avits.filters = result.filters; avits.nextOffset = result.nextOffset; avits.dirty = false;
      const list = $('management-avits'); list.replaceChildren();
      for (const item of avits.items) {
        const row = node('article', 'management-finding'); const info = node('div', 'management-finding-info');
        const title = node('h3'); title.append(safeLink(item.url, `${item.number} · ${item.title}`));
        info.append(title, node('p', 'small subtle', [item.organization, item.project, item.repository, item.branch].filter(Boolean).join(' / ')),
          node('p', 'small subtle', [item.riskRating, item.state, item.substate, item.source].filter(Boolean).join(' · ')));
        row.append(info); list.append(row);
      }
      $('management-avit-status').textContent = avits.items.length ? `${avits.items.length} AVITs loaded${avits.nextOffset !== null ? ' · more records available' : ''}.` : avits.nextOffset !== null ? 'No readable AVITs on this page. More pages are available.' : 'No matching readable AVITs.';
      $('management-avit-aggregate-dirty').textContent = 'Showing AVITs for the last loaded filters.';
      $('management-avits-more').hidden = avits.nextOffset === null;
    } catch (error) {
      $('management-avit-error').textContent = `${error.message}. Previously loaded AVITs remain visible.`;
      $('management-avit-status').textContent = 'AVIT refresh failed.';
    } finally {
      avits.busy = false;
      for (const input of $('management-avit-form').querySelectorAll('input, select')) input.disabled = false;
      $('management-avit-form').querySelector('[type="submit"]').disabled = false;
      $('management-avits-more').disabled = avits.dirty;
    }
  }
  function automaticServiceNow(value) { return value?.provider === 'servicenow-avit' || value?.credentialSource === 'servicenow-settings'; }
  function pullOnly(value) { return value?.pullOnly === true || automaticServiceNow(value) || providerFor(value?.provider)?.pullOnly === true; }
  function issueSource(id) { return issuePull.sources.find(source => source.id === id); }
  function refreshPullControls() {
    const locked = issuePull.busy || issuePull.loading;
    const allowed = can('manageFindings');
    for (const control of issuePull.controls) {
      control.checkbox.disabled = locked || !allowed || !control.source.available;
      if (control.type) control.type.disabled = locked || !allowed || !issuePull.selected.has(control.source.id);
    }
    $('management-pull-state').disabled = locked || !allowed;
    $('management-pull-all').disabled = locked || !allowed || !issuePull.sources.some(source => source.available);
    $('management-pull-clear').disabled = locked || !allowed || issuePull.selected.size === 0;
    $('management-pull-refresh').disabled = locked;
    $('management-pull-start').disabled = locked || !allowed || issuePull.selected.size === 0;
    $('management-pull-selection').textContent = issuePull.selected.size ? `${issuePull.selected.size} source${issuePull.selected.size === 1 ? '' : 's'} selected` : 'Choose sources to pull.';
    const snowSelected = issuePull.selected.has('servicenow-avit');
    $('management-pull-snow-note').hidden = !snowSelected;
    $('management-pull-snow-filters').disabled = issuePull.busy;
    if (snowSelected) {
      const form = $('management-avit-form');
      if (form) for (const input of form.querySelectorAll('input, select, button')) input.disabled = avits.busy || issuePull.busy;
    }
    for (const control of $('management-pull-results').querySelectorAll('button')) control.disabled = locked || !allowed;
  }
  function invalidateIssuePull() {
    if (issuePull.busy) return;
    issuePull.results.clear();
    $('management-pull-results').replaceChildren();
    $('management-pull-status').textContent = issuePull.selected.size ? 'Sources or filters changed. Pull selected sources to refresh the inbox.' : '';
    refreshPullControls();
  }
  function selectIssueSources(all) {
    if (issuePull.busy || issuePull.loading || !can('manageFindings')) return;
    issuePull.selected = new Set(all ? issuePull.sources.filter(source => source.available).map(source => source.id) : []);
    renderPullSources(); invalidateIssuePull();
  }
  function renderPullSources() {
    const list = $('management-pull-sources'); list.replaceChildren(); issuePull.controls = [];
    if (!issuePull.sources.length) {
      list.append(node('p', 'subtle', 'No issue sources are available. Add Jira, Azure Boards, or GitHub Issues in Integrations, or configure ServiceNow in Settings.'));
      return;
    }
    issuePull.sources.forEach((source, index) => {
      const row = node('div', `management-pull-source${source.available ? '' : ' unavailable'}`);
      const label = node('label', 'management-pull-source-choice');
      const checkbox = node('input'); checkbox.type = 'checkbox'; checkbox.checked = issuePull.selected.has(source.id); checkbox.value = source.id;
      const info = node('span'); info.append(node('strong', '', source.name), node('span', 'small subtle', automaticServiceNow(source) ? 'ServiceNow AVITs · uses ServiceNow Settings' : providerFor(source.provider)?.label || source.provider));
      label.append(checkbox, info); row.append(label);
      const control = { source, checkbox };
      checkbox.addEventListener('change', () => {
        if (checkbox.disabled) return;
        if (checkbox.checked) issuePull.selected.add(source.id); else issuePull.selected.delete(source.id);
        invalidateIssuePull();
      });
      if (['jira', 'azure-boards'].includes(source.provider)) {
        const typeLabel = node('label', 'management-pull-type', source.provider === 'jira' ? 'Issue type' : 'Work item type');
        const input = node('input'); input.type = 'text'; input.maxLength = 200; input.autocomplete = 'off'; input.id = `management-pull-type-${index}`;
        input.value = issuePull.types.get(source.id) ?? source.issueType ?? ''; input.placeholder = 'Use connection default';
        typeLabel.htmlFor = input.id; typeLabel.append(input); row.append(typeLabel); control.type = input;
        input.addEventListener('input', () => { issuePull.types.set(source.id, input.value); invalidateIssuePull(); });
      }
      if (!source.available) row.append(node('p', 'small subtle management-pull-source-note', source.error || 'Configure this source in Settings before pulling issues.'));
      issuePull.controls.push(control); list.append(row);
    });
    refreshPullControls();
  }
  async function loadIssueSources() {
    if (issuePull.busy) return;
    const version = ++issuePull.version; issuePull.loading = true; refreshPullControls();
    $('management-pull-sources').setAttribute('aria-busy', 'true'); $('management-pull-error').textContent = '';
    try {
      const result = await api('/api/management/issue-sources');
      if (!Array.isArray(result.sources)) throw new Error('Connected issue sources could not be loaded. Try refreshing sources.');
      const sources = result.sources.filter(source => source && typeof source.id === 'string' && typeof source.name === 'string' && source.kind === 'tracker' && ['jira', 'azure-boards', 'github-issues', 'servicenow-avit'].includes(source.provider));
      if (new Set(sources.map(source => source.id)).size !== sources.length) throw new Error('Connected issue sources could not be verified. Try refreshing sources.');
      if (version !== issuePull.version) return;
      issuePull.sources = sources;
      issuePull.selected = new Set([...issuePull.selected].filter(id => sources.some(source => source.id === id && source.available)));
      if (Array.isArray(result.providers) && result.providers.length) state.providers = result.providers;
      renderPullSources(); invalidateIssuePull(); fillTrackerFilters(); renderFindings();
    } catch (error) { if (version === issuePull.version) $('management-pull-error').textContent = `${error.message} Previously saved issues remain in the inbox.`; }
    finally {
      if (version === issuePull.version) { issuePull.loading = false; $('management-pull-sources').setAttribute('aria-busy', 'false'); refreshPullControls(); }
    }
  }
  function sourcePullFilters(source) {
    if (automaticServiceNow(source)) {
      const filters = Object.fromEntries([...new FormData($('management-avit-form'))].filter(([, value]) => value.trim()).map(([key, value]) => [key, value.trim()]));
      if (filters.scm !== 'ado') delete filters.project;
      return filters;
    }
    const filters = { state: $('management-pull-state').value || 'all' };
    const type = (issuePull.types.get(source.id) ?? source.issueType ?? '').trim();
    if (['jira', 'azure-boards'].includes(source.provider) && type) filters.issueType = type;
    return filters;
  }
  function renderPullResults() {
    const list = $('management-pull-results'); list.replaceChildren();
    for (const [id, result] of issuePull.results) {
      const row = node('li', `management-pull-result${result.error ? ' has-error' : ''}`); const info = node('div');
      info.append(node('strong', '', result.name));
      info.append(node('p', result.error ? 'form-error' : 'small subtle', result.pending ? 'Pulling issues…' : result.error || `${result.imported} issue${result.imported === 1 ? '' : 's'} added or updated on this page.`));
      row.append(info);
      if (!result.pending && result.error) row.append(button('Retry source', () => pullIssues({ retry: id })));
      else if (!result.pending && result.nextCursor) row.append(button('Load more', () => pullIssues({ more: id })));
      list.append(row);
    }
    refreshPullControls();
  }
  async function pullIssues({ more, retry } = {}) {
    if (issuePull.busy || issuePull.loading || !can('manageFindings')) return;
    let requests;
    if (more || retry) {
      const previous = issuePull.results.get(more || retry);
      if (!previous || (more && (!previous.nextCursor || previous.error)) || (retry && !previous.error)) return;
      requests = [{ ...previous.request, ...(more ? { cursor: previous.nextCursor } : {}) }];
    } else {
      requests = issuePull.sources.filter(source => source.available && issuePull.selected.has(source.id)).map(source => ({ connectionId: source.id, filters: sourcePullFilters(source) }));
    }
    if (!requests.length) return;
    if (avits.busy && requests.some(request => automaticServiceNow(issueSource(request.connectionId)))) { $('management-pull-error').textContent = 'Wait for the ServiceNow AVIT load to finish before pulling these sources.'; return; }
    issuePull.busy = true; $('management-pull-error').textContent = '';
    if (!more && !retry) issuePull.results.clear();
    for (const request of requests) issuePull.results.set(request.connectionId, { name: issueSource(request.connectionId)?.name || 'Issue source', request, pending: true, imported: 0, nextCursor: null });
    renderPullResults();
    let accountChanged = false;
    try {
      for (let start = 0; start < requests.length; start += 10) {
        const batch = requests.slice(start, start + 10);
        $('management-pull-status').textContent = `Pulling ${requests.length} source${requests.length === 1 ? '' : 's'}…`;
        try {
          const result = await api('/api/management/findings/pull', { method: 'POST', body: { sources: batch } });
          if (!Array.isArray(result.sources)) throw new Error('The pull response could not be verified. Retry the affected sources.');
          for (const request of batch) {
            const row = issuePull.results.get(request.connectionId); const matches = result.sources.filter(source => source.connectionId === request.connectionId);
            const response = matches.length === 1 ? matches[0] : null;
            Object.assign(row, { pending: false, imported: Number.isSafeInteger(response?.imported) && response.imported >= 0 ? response.imported : 0,
              nextCursor: typeof response?.nextCursor === 'string' && response.nextCursor ? response.nextCursor : null,
              error: response ? (typeof response.error === 'string' ? response.error : '') : 'This source did not return a result. Retry this source.' });
          }
        } catch (error) {
          for (const request of batch) Object.assign(issuePull.results.get(request.connectionId), { pending: false, error: error.message });
          if ([401, 409].includes(error.status)) { accountChanged = true; break; }
        }
        renderPullResults();
      }
    } finally {
      for (const result of issuePull.results.values()) if (result.pending) Object.assign(result, { pending: false, error: 'This source was not pulled. Refresh your account and try again.' });
      const refreshed = !accountChanged && await loadFindings();
      issuePull.busy = false; renderPullResults();
      const errors = [...issuePull.results.values()].filter(result => result.error).length;
      $('management-pull-status').textContent = accountChanged ? 'Your account changed. Reload before pulling more issues.' : !refreshed ? 'Pull finished. The inbox refresh failed; previously shown issues remain visible.' : errors ? `Pull finished. ${errors} source${errors === 1 ? ' needs' : 's need'} attention; successful issues are saved in the inbox.` : 'Pull finished. Issues are saved in the inbox.';
    }
  }
  function providerFor(id) { return state.providers.find(p => p.id === id) || fallbackProviders.find(p => p.id === id); }
  function trackerConnections() { return state.connections.filter(c => c.kind === 'tracker' && c.enabled !== false && !pullOnly(c)); }
  function selectedConnectionLabel(c) { return `${c.name} · ${providerFor(c.provider)?.label || c.provider}${c.isDefault ? ' · default' : ''}`; }
  function chooseCategory(category) {
    if (!['general', 'integrations', 'scanners', 'access', 'aws'].includes(category)) category = 'general';
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
    if ($('scm-connection-entry')) $('scm-connection-entry').inert = !can('review');
    let sourceNotice = $('management-source-role-notice');
    if (!sourceNotice) { sourceNotice = node('p', 'management-role-notice'); sourceNotice.id = 'management-source-role-notice'; $('scm-connection-entry')?.before(sourceNotice); }
    sourceNotice.hidden = can('review'); sourceNotice.textContent = 'Viewer access allows reading saved findings and reports. Ask an administrator to enable reviews or source access.';
    let notice = $('management-role-notice');
    if (!notice) { notice = node('p', 'management-role-notice'); notice.id = 'management-role-notice'; document.querySelector('.settings-layout')?.before(notice); }
    notice.hidden = can('manageSettings'); notice.textContent = can('review') ? 'You can choose your review model. Ask an administrator to change shared integrations or saved service credentials.' : 'Viewer access can read these settings. Ask an administrator to change organization configuration.';
    const company = profile?.user?.company;
    $('management-scope').textContent = company ? `Shared with ${company.name}. Administrators manage connections; analysts can work with findings.` : 'Connections are saved in your workspace. Add separate named connections for each team or account.';
    $('management-access-scope').textContent = company ? `Roles apply within ${company.name}. Access is enforced by the server.` : 'This is your personal workspace. You have administrator access.';
    refreshPullControls();
  }
  async function loadAccess() {
    try {
      state.access = await api('/api/access');
      applyAccess(); renderMembers(); $('management-access-error').textContent = '';
    } catch (error) { $('management-access-error').textContent = error.message; }
  }
  function renderMembers() {
    const list = $('management-members'); list.replaceChildren();
    if (!profile?.user?.company) { $('management-members-note').textContent = 'Your personal workspace belongs to you. Use Workspaces to open an organization.'; return; }
    if (!can('manageMembers')) { $('management-members-note').textContent = 'Ask an administrator to change organization access.'; return; }
    const members = Array.isArray(state.access.members) ? state.access.members : [];
    $('management-members-note').textContent = 'All organization members are listed, including people who have not opened this workspace yet. Changes apply to their next request.';
    list.append(node('h3', '', `Organization members (${members.length})`));
    for (const member of members) {
      const row = node('div', 'management-member'); const info = node('div');
      info.append(node('strong', '', member.displayName || member.email || 'Organization member'), node('span', 'small subtle', member.email || member.subject || member.userId));
      if (member.blocked) info.append(node('span', 'small subtle', 'Access removed. Restore access explicitly to let this member return.'));
      const select = node('select'); select.setAttribute('aria-label', `Role for ${member.displayName || member.email || member.subject || member.userId}`);
      select.append(...(state.access.roles || ['administrator', 'analyst', 'viewer']).map(role => option(role, role)));
      select.value = member.role;
      const save = button(member.blocked ? 'Restore access' : 'Save role', async b => {
        b.disabled = true;
        try {
          const target = member.subject ? { subject: member.subject } : { userId: member.userId };
          await api('/api/access/members', { method: 'POST', body: { ...target, role: select.value } });
          await loadAccess(); toast('Member role updated.');
        } catch (error) { $('management-access-error').textContent = error.message; b.disabled = false; }
      });
      row.append(info, select, save);
      if (member.subject) row.append(button('Remove access', async b => {
        if (!window.confirm(`Remove ${member.displayName || member.email || 'this member'} from ${profile.user.company.name}? They will lose access to this organization.`)) return;
        b.disabled = true;
        try {
          const result = await api(`/api/access/members/${encodeURIComponent(member.subject)}`, { method: 'DELETE' });
          if (result.signedOut) { location.replace('/login'); return; }
          await loadAccess(); toast('Organization access removed.');
        }
        catch (error) { $('management-access-error').textContent = error.message; b.disabled = false; }
      }));
      list.append(row);
    }
    renderAddMember(list);
  }
  function renderAddMember(list) {
    const form = node('form', 'management-add-member'); form.setAttribute('aria-label', 'Add an organization member');
    const heading = node('h3', '', 'Add a member');
    const help = node('p', 'small subtle', 'Enter the email they use to sign in to Threatlint. They must sign in once before you can add them. Choose the correct sign-in account if more than one is listed.');
    const label = node('label', '', 'Member email'); const email = node('input'); email.type = 'email'; email.required = true; email.maxLength = 254; email.autocomplete = 'off'; label.append(email);
    const choices = node('select'); choices.setAttribute('aria-label', 'Sign-in account to add'); choices.hidden = true;
    const role = node('select'); role.setAttribute('aria-label', 'New member role'); role.append(...(state.access.roles || []).map(value => option(value, value))); role.value = 'analyst';
    const resultNote = node('p', 'small subtle'); resultNote.setAttribute('role', 'status');
    let candidates = new Set(), version = 0;
    const add = button('Add member', async b => {
      if (!candidates.has(choices.value)) return;
      b.disabled = true;
      try { await api('/api/access/members', { method: 'POST', body: { subject: choices.value, role: role.value } }); await loadAccess(); toast('Member added to this organization.'); }
      catch (error) { $('management-access-error').textContent = error.message; b.disabled = false; }
    }, 'button primary small-button'); add.disabled = true;
    const find = button('Find account', async b => {
      if (!email.reportValidity()) return;
      const current = ++version, value = email.value.trim(); b.disabled = true; add.disabled = true; choices.hidden = true; candidates = new Set();
      resultNote.textContent = 'Checking sign-in accounts…'; $('management-access-error').textContent = '';
      try {
        const result = await api(`/api/access/candidates?email=${encodeURIComponent(value)}`);
        if (current !== version) return;
        const users = Array.isArray(result.users) ? result.users : [];
        choices.replaceChildren(...(users.length > 1 ? [option('', 'Choose a sign-in account')] : []), ...users.map(user => option(user.subject, `${user.displayName || user.email} · ${user.provider || 'SSO'}`)));
        candidates = new Set(users.map(user => user.subject)); choices.hidden = users.length === 0; add.disabled = !candidates.has(choices.value);
        resultNote.textContent = users.length ? 'Select the account and access level, then add the member.' : 'No sign-in account found. Ask them to sign in to Threatlint first, then try again.';
      } catch (error) { if (current === version) { resultNote.textContent = ''; $('management-access-error').textContent = error.message; } }
      finally { b.disabled = false; }
    });
    email.addEventListener('input', () => { version++; candidates.clear(); choices.hidden = true; add.disabled = true; resultNote.textContent = ''; });
    choices.addEventListener('change', () => { add.disabled = !candidates.has(choices.value); });
    form.addEventListener('submit', event => { event.preventDefault(); find.click(); });
    const controls = node('div', 'management-actions'); controls.append(find, choices, role, add);
    form.append(heading, help, label, controls, resultNote); list.append(form);
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
    const entries = state.connections.filter(c => !automaticServiceNow(c) && (!kind || c.kind === kind));
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
          try {
            const activated = await api(`/api/management/connections/${encodeURIComponent(connection.id)}/activate`, { method: 'POST', body: {} });
            navigate('sources');
            document.dispatchEvent(new CustomEvent('threatlint:source-activated', { detail: { connectionId: activated.connection.id } }));
            toast(`${connection.name} is ready in Connect source.`);
          }
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
    if (!can('manageSettings') || automaticServiceNow(connection)) return;
    $('management-connection-form').reset(); $('management-connection-id').value = connection?.id || '';
    $('management-connection-name').value = connection?.name || '';
    const select = $('management-connection-provider'); select.replaceChildren();
    for (const kind of ['tracker', 'scm']) {
      const group = node('optgroup'); group.label = kind === 'tracker' ? 'Issue trackers' : 'Source control';
      if (kind === 'scm' && !connection) group.append(option('github-app', 'GitHub App · use saved installation'));
      for (const p of state.providers.filter(item => item.kind === kind && !item.pullOnly && !automaticServiceNow(item) && item.id !== 'servicenow-avit')) group.append(option(p.id, p.id === 'github' ? 'GitHub · access token' : p.label));
      select.append(group);
    }
    select.value = connection?.provider || state.providers.find(item => !item.pullOnly && item.id !== 'servicenow-avit')?.id || 'jira'; select.disabled = !!connection;
    $('management-connection-enabled').checked = connection?.enabled !== false;
    $('management-connection-default').checked = connection?.isDefault === true;
    $('management-connection-token').value = ''; $('management-connection-token').required = !connection?.hasToken;
    $('management-token-note').textContent = connection?.hasToken ? 'A token is saved. Leave this field empty to keep it, or enter a replacement.' : 'The token is saved in the workspace runtime and is never returned to this page.';
    $('management-connection-title').textContent = connection ? 'Edit connection' : 'Add a connection';
    $('management-connection-error').textContent = ''; renderConnectionFields(connection); $('management-connection-dialog').showModal();
  }
  function renderConnectionFields(connection = {}) {
    connection = connection || {};
    const appMode = $('management-connection-provider').value === 'github-app';
    $('management-connection-name-row').hidden = appMode;
    $('management-connection-name').required = !appMode;
    $('management-connection-token-row').hidden = appMode;
    $('management-connection-token').required = !appMode && !connection.hasToken && !$('management-connection-id').value;
    $('management-connection-token').value = '';
    $('management-connection-enabled').closest('.management-connection-options').hidden = appMode;
    $('management-save-connection').textContent = appMode ? 'Use or configure GitHub App' : 'Save connection';
    $('management-connection-auth-note').textContent = appMode ? 'Uses the saved App installation. No personal token is needed.' : 'Use a token scoped to this project or repository.';
    const provider = providerFor($('management-connection-provider').value); const container = $('management-connection-fields'); container.replaceChildren();
    if (appMode) {
      container.append(node('p', 'field-note small subtle', 'Use the GitHub App already saved for this workspace. Installation tokens are created by the runner; no personal access token is required. If setup needs attention, the App settings will open.'));
      return;
    }
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
      if ($('management-connection-provider').value === 'github-app') {
        const saved = await api('/api/github/settings');
        if (saved.configured) {
          const connections = await api('/api/scm/reconnect', { method: 'POST', body: { provider: 'github' } });
          const app = connections.find(item => item.source === 'GitHub App' && item.connected !== false);
          if (app) {
            $('management-connection-dialog').close(); navigate('sources');
            document.dispatchEvent(new CustomEvent('threatlint:source-activated', { detail: { connectionId: app.id } }));
            toast('Connected using the saved GitHub App.'); return;
          }
        }
        $('management-connection-dialog').close();
        document.dispatchEvent(new CustomEvent('threatlint:settings-open', { detail: { section: 'github' } }));
        return;
      }
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
    // The current-profile ServiceNow alias is only a pull target. Saved inbox rows
    // belong to their persisted instance descriptor, which may outlive Settings changes.
    const sources = state.connections.filter(source => source.kind === 'tracker' && source.id !== 'servicenow-avit');
    select.replaceChildren(option('', 'All sources'), ...sources.map(source => option(source.id, source.name)));
    select.value = sources.some(source => source.id === previous) ? previous : '';
  }
  function isFalsePositive(item) { return /false[ -]?positive/i.test(item.disposition || ''); }
  function isClosed(item) { return isFalsePositive(item) || /^(?:RESOLVED|REMEDIATED|CLOSED)$/i.test(item.disposition || '') || /closed|done|resolved|removed|completed/i.test(item.state || ''); }
  function safeLink(url, label) {
    let parsed; try { parsed = new URL(url); } catch { return node('span', '', label); }
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password) return node('span', '', label);
    const a = node('a', '', label); a.href = parsed.href; a.target = '_blank'; a.rel = 'noopener noreferrer'; return a;
  }
  async function loadFindings() {
    $('management-findings').setAttribute('aria-busy', 'true');
    try {
      const payload = await api('/api/management/findings'); state.findings = Array.isArray(payload.findings) ? payload.findings : [];
      if (Array.isArray(payload.connections)) state.connections = payload.connections;
      fillTrackerFilters(); renderFindings(); $('management-findings-error').textContent = '';
      return true;
    } catch (error) { $('management-findings-error').textContent = error.message; return false; }
    finally { $('management-findings').setAttribute('aria-busy', 'false'); }
  }
  function renderFindings() {
    $('management-count-total').textContent = state.findings.length;
    $('management-count-open').textContent = state.findings.filter(item => !isClosed(item)).length;
    $('management-count-fp').textContent = state.findings.filter(isFalsePositive).length;
    const search = $('management-search').value.trim().toLowerCase(); const selected = $('management-tracker-filter').value; const filter = $('management-state-filter').value;
    const rows = state.findings.filter(item => (!selected || item.connectionId === selected) && (!search || [item.title, item.externalId, item.findingId, item.provider, item.issueType, state.connections.find(c => c.id === item.connectionId)?.name, issueSource(item.connectionId)?.name].filter(Boolean).join(' ').toLowerCase().includes(search)) && (!filter || (filter === 'false-positive' ? isFalsePositive(item) : filter === 'closed' ? isClosed(item) : !isClosed(item))));
    const list = $('management-findings'); list.replaceChildren();
    if (!rows.length) {
      const empty = node('div', 'management-empty'); empty.append(node('h3', '', state.findings.length ? 'No issues match these filters.' : 'Your issue inbox is ready.'), node('p', 'subtle', state.findings.length ? 'Try another source, status, or search term.' : 'Choose sources above and pull issues, import ticket IDs, or create a ticket from a saved finding.'));
      if (!state.findings.length) empty.append(button('Manage integrations', () => { navigate('settings'); chooseCategory('integrations'); }));
      list.append(empty); return;
    }
    for (const finding of rows) {
      const row = node('article', 'management-finding'); const info = node('div', 'management-finding-info'); const title = node('h3'); title.append(safeLink(finding.url, `${finding.externalId} · ${finding.title || 'Security finding'}`));
      const connection = state.connections.find(c => c.id === finding.connectionId) || issueSource(finding.connectionId);
      info.append(title, node('p', 'small subtle', `${connection?.name || 'Removed connection'} · ${providerFor(finding.provider)?.label || finding.provider}${finding.findingId ? ` · ${finding.findingId}` : ''}${finding.generated ? ' · Created by Threatlint' : ' · Read from source'}`));
      const details = node('div', 'management-finding-meta'); details.append(node('span', 'management-badge', isFalsePositive(finding) ? 'False positive' : finding.state || 'Open'));
      if (finding.issueType) details.append(node('span', 'management-badge muted', finding.issueType));
      if (finding.severity && finding.severity !== 'UNSPECIFIED') details.append(node('span', `management-severity severity-${String(finding.severity).toLowerCase()}`, finding.severity));
      if (finding.updatedAt) { const date = new Date(finding.updatedAt); if (!Number.isNaN(date.getTime())) details.append(node('span', 'small subtle', `Updated ${date.toLocaleDateString()}`)); }
      info.append(details); row.append(info);
      if (!isClosed(finding) && !pullOnly(connection) && !automaticServiceNow(finding)) {
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
    if (!can('manageFindings') || (mode === 'close' && (automaticServiceNow(finding) || pullOnly(state.connections.find(c => c.id === finding?.connectionId))))) return;
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
      const errors = []; let cursor = null; let pages = 0; let synced = 0; let skippedReadOnly = 0;
      const connectionId = $('management-tracker-filter').value;
      if (automaticServiceNow(issueSource(connectionId) || state.connections.find(connection => connection.id === connectionId))) {
        $('management-sync-status').textContent = 'Use Pull issues to refresh ServiceNow AVIT records.'; return;
      }
      do {
        const payload = await api('/api/management/findings/sync', { method: 'POST', body: { ...(connectionId ? { connectionId } : {}), ...(cursor ? { cursor } : {}) } });
        errors.push(...(Array.isArray(payload.errors) ? payload.errors : [])); synced += payload.findings?.length || 0;
        if (Number.isSafeInteger(payload.skippedReadOnly) && payload.skippedReadOnly > 0) skippedReadOnly = Math.max(skippedReadOnly, payload.skippedReadOnly);
        cursor = payload.nextCursor || null; pages++;
        $('management-sync-status').textContent = `Synced ${synced} ticket${synced === 1 ? '' : 's'}${payload.total ? ` of ${payload.total}` : ''}…`;
      } while (cursor && pages < 100);
      if (cursor) errors.push({ id: 'Sync', error: 'More tickets remain. Run sync again to continue.' });
      await loadFindings();
      $('management-sync-status').textContent = errors.length ? `Sync finished with ${errors.length} ticket${errors.length === 1 ? '' : 's'} requiring attention. Successful updates are shown.` : 'Ticket status is up to date.';
      if (skippedReadOnly) $('management-sync-status').textContent += ` ${skippedReadOnly} ServiceNow AVIT record${skippedReadOnly === 1 ? ' is' : 's are'} refreshed with Pull issues.`;
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
  $('management-pull-refresh').addEventListener('click', loadIssueSources);
  $('management-pull-all').addEventListener('click', () => selectIssueSources(true));
  $('management-pull-clear').addEventListener('click', () => selectIssueSources(false));
  $('management-pull-state').addEventListener('change', invalidateIssuePull);
  $('management-pull-start').addEventListener('click', () => { void pullIssues(); });
  $('management-pull-snow-filters').addEventListener('click', () => $('management-avits-title').scrollIntoView({ behavior: 'smooth', block: 'start' }));
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
    if (event.detail.view === 'management') { void Promise.all([loadConnections(), loadFindings(), loadIssueSources(), loadAccess()]).then(() => { renderConnections(); renderFindings(); }); }
  });
  document.addEventListener('threatlint:settings-section', event => { const section = event.detail.section; chooseCategory(section === 'aws' ? 'aws' : ['integrations', 'github'].includes(section) ? 'integrations' : section === 'access' ? 'access' : (['servicenow', 'semgrep', 'ado', 'defectdojo', 'sonarqube'].includes(section) || section?.startsWith('tracker-')) ? 'scanners' : 'general'); });
  document.addEventListener('threatlint:context', event => { state.contextSession = event.detail.session?.id || null; });
  document.addEventListener('threatlint:ticket-create', async event => {
    await loadConnections();
    await openTicket('create', event.detail);
  });
  initializeAvits();
  await loadAccess();
  if (!state.providers.length) state.providers = fallbackProviders; applyAccess(); chooseCategory(state.category);
  if (!$('view-management').hidden) { await Promise.all([loadConnections(), loadFindings(), loadIssueSources()]); }
})();
