'use strict';

(() => {
  const $ = id => document.getElementById(id);
  const trackers = { github: 'GitHub Issues', jira: 'Jira', 'azure-devops': 'Azure DevOps Boards' };
  let context;
  const node = (tag, text) => { const value = document.createElement(tag); if (text) value.textContent = text; return value; };
  const navigate = view => document.dispatchEvent(new CustomEvent('threatlint:navigate', { detail: { view } }));
  async function api(url, body, method) {
    const result = await fetch(url, { method: method || (body ? 'POST' : 'GET'), headers: { 'Content-Type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) });
    const data = await result.json(); if (!result.ok) throw new Error(data.error || 'Request failed'); return data;
  }
  function field(parent, id, title, type = 'text', placeholder = '') {
    const label = node('label', title); label.htmlFor = id;
    const input = node('input'); input.id = id; input.type = type; input.placeholder = placeholder; input.autocomplete = 'off';
    parent.append(label, input); return input;
  }
  function settings(id, label) {
    const form = node('form'); form.className = 'settings-card'; form.id = `issue-settings-${id}`;
    const anchor = node('span'); anchor.id = `settings-tracker-${id}`; anchor.className = 'settings-anchor';
    form.append(anchor, node('h2', label));
    const fields = {};
    if (id === 'github') fields.repository = field(form, `tracker-${id}-repository`, 'Repository', 'text', 'owner/repository');
    if (id === 'jira') {
      fields.url = field(form, 'tracker-jira-url', 'Jira Cloud URL', 'url', 'https://team.atlassian.net');
      fields.email = field(form, 'tracker-jira-email', 'Account email', 'email');
      fields.query = field(form, 'tracker-jira-query', 'Security findings JQL', 'text', 'project = SEC');
    }
    if (id === 'azure-devops') { fields.organization = field(form, 'tracker-ado-organization', 'Organization'); fields.project = field(form, 'tracker-ado-project', 'Project'); }
    const token = field(form, `tracker-${id}-token`, 'API token (leave blank to retain saved token)', 'password');
    const permissions = id === 'github' ? 'Issues: read and Metadata: read on the selected repository.' : id === 'jira' ? 'Read issues in the selected projects; use a Jira Cloud API token for this account.' : 'Work Items: Read (vso.work) on the selected project.';
    form.append(node('p', `Used for Finding triage and Metrics. ${permissions} Saved locally with restricted file permissions.`));
    const status = node('p'); status.setAttribute('aria-live', 'polite');
    const save = node('button', `Save ${label}`); save.type = 'submit'; save.className = 'button primary';
    const remove = node('button', 'Disconnect'); remove.type = 'button'; remove.className = 'button secondary';
    form.append(status, save, remove);
    let loadVersion = 0;
    form.addEventListener('input', () => { loadVersion++; });
    async function load() {
      const version = ++loadVersion;
      try { const config = await api(`/api/issue-trackers/${id}/settings`); if (version !== loadVersion) return; for (const [key, input] of Object.entries(fields)) input.value = config[key] || ''; status.textContent = config.hasToken ? 'Configured. Token is never returned to the page.' : 'Not configured.'; }
      catch (error) { status.textContent = error.message; }
    }
    form.addEventListener('submit', async event => {
      event.preventDefault(); loadVersion++; save.disabled = true; status.textContent = 'Checking connection…';
      try { await api(`/api/issue-trackers/${id}/settings`, { ...Object.fromEntries(Object.entries(fields).map(([key, input]) => [key, input.value.trim()])), ...(token.value ? { token: token.value } : {}) }); await load(); }
      catch (error) { status.textContent = error.message; } finally { token.value = ''; save.disabled = false; }
    });
    remove.addEventListener('click', async () => { try { await api(`/api/issue-trackers/${id}/settings`, null, 'DELETE'); await load(); } catch (error) { status.textContent = error.message; } });
    $('sonar-form').parentNode.append(form);
    const link = node('a', label); link.href = `#settings-tracker-${id}`; document.querySelector('.settings-nav').append(link);
    document.addEventListener('threatlint:view', event => { if (event.detail.view === 'settings') void load(); });
  }
  function wire() {
    if ($('view-security')) {
      for (const view of ['workbench', 'security', 'sources']) {
        const nav = node('div'); nav.className = 'operations-button-row'; nav.setAttribute('aria-label', 'Review code workflow');
        for (const [destination, label] of [['workbench', 'Specialist review'], ['security', 'Run scanners'], ['sources', 'Connect source']]) {
          const button = node('button', label); button.type = 'button'; button.className = `button ${destination === view ? 'primary' : 'secondary'}`;
          button.addEventListener('click', () => navigate(destination)); nav.append(button);
        }
        $(`view-${view}`).prepend(nav);
      }
    }
    const root = $('unified-triage'); if (!root) return;
    const selector = node('select'); selector.id = 'triage-source'; selector.setAttribute('aria-label', 'Finding source');
    for (const [id, label] of Object.entries({ servicenow: 'ServiceNow', ...trackers, dojo: 'DefectDojo', sonar: 'SonarQube', report: 'Scan report upload' })) {
      const option = node('option', label); option.value = id; selector.append(option);
    }
    const label = node('label', 'Finding source'); label.htmlFor = selector.id; root.append(label, selector);
    const panels = { servicenow: $('fpreview-form') };
    for (const tool of ['dojo', 'sonar']) { panels[tool] = document.querySelector(`.scanner-review[data-scanner-tool="${tool}"]`); root.append(panels[tool]); }
    const form = node('form'); form.className = 'settings-card'; form.noValidate = true;
    const refs = field(form, 'triage-ticket-refs', 'Ticket IDs', 'text', 'SEC-123, SEC-124');
    const source = field(form, 'triage-ticket-source', 'Source code link (optional)', 'url', 'https://github.com/team/repository');
    const branch = field(form, 'triage-ticket-branch', 'Source branch (optional)');
    const useWorkspace = node('input'); useWorkspace.type = 'checkbox'; useWorkspace.id = 'triage-ticket-workspace';
    const useLabel = node('label', 'Use the current workspace for source context'); useLabel.prepend(useWorkspace); form.append(useLabel);
    form.append(node('p', 'Tickets are untrusted evidence. Add the matching source revision for stronger verdicts. Scanner tuning requires a proven false positive and an exact scanner target.'));
    const start = node('button', 'Triage tickets'); start.className = 'button primary'; start.type = 'submit';
    const error = node('p'); error.setAttribute('role', 'alert'); form.append(start, error); root.append(form);
    const upload = node('button', 'Upload a scan report →'); upload.type = 'button'; upload.className = 'button primary'; upload.addEventListener('click', () => navigate('scanimport')); root.append(upload);
    function choose(value = selector.value) {
      selector.value = value;
      for (const [id, panel] of Object.entries(panels)) panel.hidden = id !== value;
      $('fpreview-results').hidden = value !== 'servicenow';
      form.hidden = !Object.hasOwn(trackers, value); upload.hidden = value !== 'report';
      refs.placeholder = value === 'github' ? '#123, #124 (configured repository)' : value === 'azure-devops' ? '123, ADO-124' : 'SEC-123, SEC-124';
    }
    selector.addEventListener('change', () => choose());
    document.addEventListener('threatlint:triage-source', event => choose(event.detail.source));
    form.addEventListener('submit', async event => {
      event.preventDefault(); error.textContent = '';
      if (!context?.ready) { error.textContent = 'Choose a model in Settings and authorize sharing before triaging tickets.'; return; }
      if (source.value.trim() && useWorkspace.checked) { error.textContent = 'Choose either the current workspace or a source link.'; return; }
      start.disabled = true;
      try {
        const result = await api(`/api/issue-trackers/${selector.value}/triage`, { ...context.settings, references: refs.value.trim(),
          ...(useWorkspace.checked ? { workspaceId: context.session?.id } : {}), ...(source.value.trim() ? { sourceUrl: source.value.trim(), sourceBranch: branch.value.trim() } : {}) });
        navigate('scanimport'); document.dispatchEvent(new CustomEvent('threatlint:triage-accepted', { detail: result }));
      } catch (failure) { error.textContent = failure.message; } finally { start.disabled = false; }
    });
    for (const [id, name] of Object.entries(trackers)) settings(id, name);
    choose();
    document.addEventListener('threatlint:context', event => { context = event.detail; });
    document.dispatchEvent(new CustomEvent('threatlint:request-context'));
    api('/api/semgrep/engine').then(status => { $('scanner-engine-description').textContent = status.descriptor;
      if ($('security-semgrep')) { const label = $('security-semgrep').parentNode.querySelector('span'); if (label) label.textContent = `${status.engine === 'pro' ? 'Semgrep Pro' : 'Semgrep Community Edition'} · source code`; $('security-semgrep').parentNode.title = status.descriptor; } }).catch(() => { $('scanner-engine-description').textContent = 'Semgrep engine status unavailable'; });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire, { once: true }); else wire();
})();
