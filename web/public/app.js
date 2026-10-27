/* global marked, DOMPurify */
'use strict';

(() => {
  const $ = id => document.getElementById(id);
  const desktop = window.threatlintDesktop;
  const PRESETS = [
    { id: 'full', title: 'Security baseline', icon: '◎', description: 'Understand your exposure, credentials, and dependency trust.', agents: ['appsec-threat-modeler', 'appsec-secrets-scanner', 'appsec-dependency-auditor'], label: 'DISCOVER & PRIORITIZE' },
    { id: 'pr', title: 'Pull request review', icon: '⌘', description: 'Review the change. Trace its impact. Make a scoped merge decision.', agents: ['appsec-code-reviewer', 'appsec-api-security-reviewer', 'appsec-auth-reviewer'], label: 'REVIEW & VALIDATE' },
    { id: 'triage', title: 'Find signal in the noise', icon: '⌁', description: 'Turn scanner findings into defensible verdicts and proposed fixes.', agents: ['appsec-fp-reviewer'], label: 'TRIAGE & REMEDIATE' },
    { id: 'verify', title: 'Close the loop', icon: '✓', description: 'Verify remediation, check bypasses, and understand what changed.', agents: ['appsec-verify-fix', 'appsec-threat-delta'], label: 'VERIFY & COMPARE' },
    { id: 'codegen', title: 'Check AI-generated code', icon: '✦', description: 'Catch insecure defaults in code your assistant just wrote, before you commit.', agents: ['appsec-secure-codegen-reviewer', 'appsec-code-reviewer'], label: 'GENERATE SAFELY' },
    { id: 'runtime', title: 'Explain a runtime scan', icon: '⌁', description: 'Correlate runtime observations with the source that produced them.', agents: ['appsec-runtime-reviewer', 'appsec-security-test-planner'], label: 'RUNTIME → SOURCE' },
  ];
  const DEFAULTS = { provider: 'lmstudio', model: '', models: { lmstudio: '', claude: '', openai: '', copilot: '' }, lmstudioUrl: 'http://localhost:1234/v1', snowInstance: '' };
  const FP_REVIEWER = 'appsec-fp-reviewer';
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem('threatlint.preferences.v2') || '{}'); } catch { /* preferences are optional */ }
  const state = {
    agents: [], skills: [], sessions: [], reports: [], pipeline: ['appsec-threat-modeler', 'appsec-secrets-scanner', 'appsec-dependency-auditor'],
    statuses: {}, session: null, attachment: null, running: false, connected: false, ws: null,
    preferences: { ...DEFAULTS, ...saved, models: { ...DEFAULTS.models, ...saved.models } },
    credentials: { claude: '', openai: '', copilot: '', snowClientId: '', snowClientSecret: '' }, consent: new Set(), config: { providers: {} }, preset: 'full',
    view: 'workbench', report: null, asked: (() => { try { return localStorage.getItem('threatlint.asked') === '1'; } catch { return false; } })(), activityCount: 0, toastTimer: null, reconnectTimer: null, intentionalClose: false,
  };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }
  function button(text, className, action, title) {
    const node = el('button', className, text);
    node.type = 'button';
    if (title) { node.title = title; node.setAttribute('aria-label', title); }
    node.addEventListener('click', action);
    return node;
  }
  function toast(message, error = false) {
    clearTimeout(state.toastTimer);
    $('toast').textContent = message;
    $('toast').classList.toggle('error', error);
    $('toast').classList.remove('hidden');
    state.toastTimer = setTimeout(() => $('toast').classList.add('hidden'), error ? 8500 : 4000);
  }
  async function request(url, options = {}) {
    const response = await fetch(url, { ...options, headers: { 'Content-Type': 'application/json', ...options.headers } });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
    return payload;
  }
  function safeMarkdown(container, text) {
    if (!window.marked || !window.DOMPurify) { container.textContent = text; return; }
    container.innerHTML = DOMPurify.sanitize(marked.parse(String(text), { gfm: true, breaks: false }), {
      USE_PROFILES: { html: true }, FORBID_TAGS: ['img', 'style', 'form', 'input', 'button', 'iframe', 'object'], FORBID_ATTR: ['style', 'srcset'],
    });
    // Evidence links are not arbitrary filesystem/navigation capabilities.
    for (const anchor of container.querySelectorAll('a')) {
      const href = anchor.getAttribute('href') || '';
      if (!href.startsWith('https://') && !href.startsWith('#')) anchor.removeAttribute('href');
      else if (href.startsWith('https://')) { anchor.target = '_blank'; anchor.rel = 'noopener noreferrer'; }
    }
  }
  function agentById(id) { return state.agents.find(agent => agent.id === id); }
  function repoName(repoPath) { return repoPath.split(/[\\/]/).findLast(Boolean) || repoPath; }
  function formatTime(value) { return new Date(value).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); }
  function selectedModel() { return state.preferences.models[state.preferences.provider] || ''; }
  function cloudProvider() {
    if (state.preferences.provider !== 'lmstudio') return true;
    try { return !['localhost', '127.0.0.1', '[::1]'].includes(new URL(state.preferences.lmstudioUrl).hostname); } catch { return true; }
  }
  function consentKey() { return state.preferences.provider === 'lmstudio' ? state.preferences.lmstudioUrl : state.preferences.provider; }
  function showView(name) {
    const titles = { fpreview: 'False positive review', settings: 'Settings', workbench: 'Review code', sources: 'Connect source', runtime: 'Scan running app', reports: 'Findings', chat: 'Ask Threatlint', metrics: 'Metrics', agents: 'Agents', skills: 'Skills', learn: 'Learn & videos' };
    if (!Object.hasOwn(titles, name)) return;
    state.view = name;
    if (name === 'settings') loadSettingsForm();
    for (const view of document.querySelectorAll('.view')) { const active = view.id === `view-${name}`; view.hidden = !active; view.classList.toggle('active', active); }
    for (const item of document.querySelectorAll('[data-view]')) { item.classList.toggle('active', item.dataset.view === name); item.setAttribute('aria-current', item.dataset.view === name ? 'page' : 'false'); }
    $('breadcrumb-title').textContent = titles[name];
    document.dispatchEvent(new CustomEvent('threatlint:view', { detail: { view: name } }));
    history.replaceState(null, '', `#${name}`);
    window.scrollTo({ top: 0, behavior: 'instant' });
  }

  function renderPresets() {
    $('playbook-count').textContent = `${PRESETS.length} PLAYBOOKS`;
    $('workflow-presets').replaceChildren(...PRESETS.map(preset => {
      const node = button('', `workflow-card${state.preset === preset.id ? ' selected' : ''}`, () => {
        if (state.running) return;
        state.pipeline = [...preset.agents]; state.statuses = {}; state.preset = preset.id;
        renderPipeline(); renderPresets(); renderAgents();
        if (preset.id === 'triage' && !state.attachment) toast('Attach scanner findings, enter ServiceNow AVITs, or specify a findings path in the review scope.');
      });
      node.disabled = state.running;
      const top = el('div', 'workflow-top'); top.append(el('span', 'workflow-icon', preset.icon), el('span', 'workflow-arrow', '↗'));
      const meta = el('div', 'workflow-meta'); meta.append(el('span', '', `${preset.agents.length} AGENT${preset.agents.length > 1 ? 'S' : ''}`), el('b', '', preset.label));
      node.append(top, el('h3', '', preset.title), el('p', '', preset.description), meta);
      return node;
    }));
  }
  function renderPipeline() {
    $('pipeline-count').textContent = state.pipeline.length;
    $('pipeline-list').replaceChildren();
    if (!state.pipeline.length) $('pipeline-list').append(el('li', 'pipeline-empty', 'A focused review starts with the right specialist.'));
    state.pipeline.forEach((id, index) => {
      const agent = agentById(id);
      const status = state.statuses[id] || 'ready';
      const item = el('li', `pipeline-item ${status}`); item.dataset.agentId = id;
      const info = el('div', 'pipeline-item-info'); info.append(el('strong', '', agent?.label || id), el('small', '', `${agent?.skills?.length || 3} skills · ${agent?.category || 'Analysis'}`));
      item.append(el('span', 'pipeline-number', String(index + 1).padStart(2, '0')), el('span', 'agent-monogram', agent?.initials || 'TL'), info);
      if (state.running || status !== 'ready') item.append(el('span', 'pipeline-status', { ready: 'Queued', running: 'Reviewing…', complete: 'Complete', error: 'Failed', cancelled: 'Stopped', interrupted: 'Interrupted' }[status] || status));
      const actions = el('div', 'pipeline-actions');
      const move = direction => {
        if (state.running) return;
        const other = index + direction;
        [state.pipeline[index], state.pipeline[other]] = [state.pipeline[other], state.pipeline[index]];
        state.preset = ''; renderPipeline(); renderPresets();
      };
      const up = button('↑', 'icon-button', () => move(-1), `Move ${agent?.label} up`); up.disabled = state.running || index === 0;
      const down = button('↓', 'icon-button', () => move(1), `Move ${agent?.label} down`); down.disabled = state.running || index === state.pipeline.length - 1;
      const remove = button('×', 'icon-button', () => {
        if (state.running) return;
        state.pipeline.splice(index, 1); state.preset = ''; renderPipeline(); renderPresets(); renderAgents();
      }, `Remove ${agent?.label}`); remove.disabled = state.running;
      actions.append(up, down, remove); item.append(actions); $('pipeline-list').append(item);
    });
    updateRunControls();
  }
  // Other view modules receive a copy of the workspace and model settings; credentials go only to the runner socket.
  function publishContext() {
    const provider = state.preferences.provider;
    document.dispatchEvent(new CustomEvent('threatlint:context', { detail: Object.freeze({
      session: state.session ? { id: state.session.id, repoPath: state.session.repoPath } : null,
      connected: state.connected, ready: !!selectedModel() && (!cloudProvider() || state.consent.has(consentKey())),
      reports: state.reports.length, ran: state.reports.length > 0,
      socket: state.ws, settings: { provider, model: selectedModel(), lmstudioUrl: state.preferences.lmstudioUrl, lmstudioModel: state.preferences.models.lmstudio,
        ...providerKeys(provider) },
    }) }));
    for (const [step, done] of [['repo', !!state.session], ['model', !!selectedModel()], ['run', state.reports.length > 0], ['fix', state.reports.length > 0 && state.asked]]) {
      document.querySelector(`#onboarding [data-step="${step}"]`)?.classList.toggle('done', done);
    }
    $('onboarding').hidden = !!state.session && !!selectedModel() && state.reports.length > 0 && state.asked;
  }
  function updateRunControls() {
    publishContext();
    $('start-run').disabled = state.running || !state.connected || !state.session || !state.pipeline.length;
    $('cancel-run').classList.toggle('hidden', !state.running);
    $('clear-pipeline').disabled = state.running;
    $('browse-agents').disabled = state.running;
    $('target').disabled = state.running;
    $('attach-findings').disabled = state.running;
    $('avit-list').disabled = state.running;
    $('avit-section').hidden = !state.pipeline.includes(FP_REVIEWER);
    $('remove-attachment').disabled = state.running;
    $('choose-repo').disabled = state.running;
    $('settings-button').disabled = state.running;
    $('configure-provider').disabled = state.running;
    let summary = `${state.pipeline.length} specialist${state.pipeline.length > 1 ? 's' : ''} ready · ${selectedModel() || 'configure a model'}`;
    if (!state.pipeline.length) summary = 'Add at least one specialist';
    if (!state.session) summary = 'Choose a repository to get started';
    if (!state.connected) summary = 'Connecting to the local runner…';
    if (state.running) summary = 'Review in progress · source remains unchanged';
    $('run-summary').textContent = summary;
    $('run-status-dot').classList.toggle('waiting', !state.session);
  }
  function toggleAgent(id) {
    if (state.running) { toast('Wait until the current pipeline has finished.', true); return; }
    const index = state.pipeline.indexOf(id);
    if (index >= 0) state.pipeline.splice(index, 1); else state.pipeline.push(id);
    state.statuses = {}; state.preset = '';
    renderPipeline(); renderPresets(); renderAgents();
    toast(index < 0 ? `${agentById(id)?.label} added to your pipeline.` : 'Specialist removed.');
  }
  function renderAgents() {
    const search = $('agent-search').value.toLowerCase().trim();
    const category = $('agent-category').value;
    const agents = state.agents.filter(agent => (!category || agent.category === category) && `${agent.label} ${agent.description} ${agent.skills.map(skill => skill.name).join(' ')}`.toLowerCase().includes(search));
    $('agent-results-count').textContent = `${agents.length} specialists`;
    $('agent-grid').replaceChildren(...agents.map(agent => {
      const added = state.pipeline.includes(agent.id);
      const card = el('article', `agent-card${added ? ' added' : ''}`);
      const top = el('div', 'agent-card-top'); top.append(el('span', 'agent-monogram', agent.initials), el('span', 'agent-category', agent.category.toUpperCase()));
      const chips = el('div', 'skill-chips');
      for (const skill of agent.skills) chips.append(el('span', 'skill-chip', skill.name));
      const footer = el('div', 'agent-card-footer');
      const add = button(added ? '✓ In pipeline' : '＋ Add to pipeline', `button ${added ? 'secondary' : 'primary'} small-button`, () => toggleAgent(agent.id)); add.disabled = state.running;
      footer.append(button('View expertise ↗', 'text-button', () => openAgent(agent)), add);
      card.append(top, el('h3', '', agent.label), el('p', '', agent.description), chips, footer);
      return card;
    }));
    if (!agents.length) $('agent-grid').append(el('div', 'agent-card-empty', 'No matching specialists. Try another discipline or search.'));
  }
  function openAgent(agent) {
    $('detail-eyebrow').textContent = `${agent.category.toUpperCase()} / ${agent.skills.length} REQUIRED SKILLS`;
    $('detail-title').textContent = agent.label;
    const content = $('detail-content'); content.replaceChildren(el('p', 'detail-description', agent.description));
    const output = el('div', 'detail-section'); output.append(el('h3', '', 'Your deliverable'), el('p', '', agent.deliverable));
    const input = el('div', 'detail-section'); input.append(el('h3', '', 'Recommended input'), el('p', '', agent.inputHint));
    const skills = el('div', 'detail-section'); skills.append(el('h3', '', 'Skills loaded into every analysis'));
    for (const skill of agent.skills) {
      const row = el('div', 'detail-skill'); row.append(el('strong', '', skill.name), el('p', '', skill.description), button('Read workflow →', 'text-button', () => openSkill(state.skills.find(item => item.id === skill.id)))); skills.append(row);
    }
    content.append(output, input, skills);
    const add = button(state.pipeline.includes(agent.id) ? 'Remove from pipeline' : 'Add to pipeline →', 'button primary', () => { toggleAgent(agent.id); $('detail-dialog').close(); }); add.disabled = state.running;
    $('detail-footer').replaceChildren(el('span', 'small subtle', 'Analysis only. Every fix is a proposal.'), add);
    if (!$('detail-dialog').open) $('detail-dialog').showModal();
  }
  function renderSkills() {
    const query = $('skill-search').value.toLowerCase().trim();
    const skills = state.skills.filter(skill => `${skill.name} ${skill.description}`.toLowerCase().includes(query));
    $('skills-grid').replaceChildren(...skills.map(skill => {
      const card = button('', 'skill-card', () => openSkill(skill));
      const title = el('h3'); title.append(el('span', '', '◇'), document.createTextNode(skill.name));
      const footer = el('footer'); footer.append(el('span', '', `${skill.agents.length} specialist${skill.agents.length > 1 ? 's' : ''} equipped`), el('span', '', 'Read workflow ↗'));
      card.append(title, el('p', '', skill.description), footer); return card;
    }));
    if (!skills.length) $('skills-grid').append(el('p', 'subtle', 'No matching workflows.'));
  }
  function openSkill(skill) {
    if (!skill) return;
    $('detail-eyebrow').textContent = 'REQUIRED SKILL / READ-ONLY WORKFLOW';
    $('detail-title').textContent = skill.name.replace(/^./, character => character.toUpperCase());
    const article = el('article', 'markdown'); safeMarkdown(article, skill.body);
    $('detail-content').replaceChildren(article);
    $('detail-footer').replaceChildren(el('span', 'small subtle', `Loaded for ${skill.agents.length} specialist${skill.agents.length > 1 ? 's' : ''}.`), button('View specialists →', 'button secondary', () => { $('detail-dialog').close(); $('agent-search').value = skill.name; renderAgents(); showView('agents'); }));
    if (!$('detail-dialog').open) $('detail-dialog').showModal();
  }

  async function refreshSessions() {
    state.sessions = await request('/api/sessions');
    renderSessions();
  }
  function renderSessions() {
    $('session-list').replaceChildren(...state.sessions.slice(0, 8).map(session => {
      const node = button('', `session-button${session.id === state.session?.id ? ' selected' : ''}`, () => { if (state.running) { toast('Stop the current review before changing workspace.', true); return; } openSession(session).catch(error => toast(error.message, true)); });
      node.title = session.repoPath;
      node.append(el('span', '', '▱'), el('span', 'session-name', repoName(session.repoPath)), el('small', '', session.reportCount));
      return node;
    }));
    if (!state.sessions.length) $('session-list').append(el('p', 'subtle small', 'No workspaces yet.'));
  }
  async function openSession(session) {
    const data = await request(`/api/session/${session.id}`);
    state.session = data;
    $('workspace-label').textContent = repoName(data.repoPath);
    $('workspace-label').title = data.repoPath;
    $('reports-workspace').textContent = data.repoPath;
    localStorage.setItem('threatlint.last-session.v2', data.id);
    await refreshReports(); renderSessions(); updateRunControls();
  }
  async function refreshReports() {
    if (!state.session) { state.reports = []; renderReports(); return; }
    state.reports = await request(`/api/session/${state.session.id}/reports`);
    $('stat-reports').textContent = state.reports.length;
    $('report-nav-count').textContent = state.reports.length;
    $('stat-reports-note').textContent = state.reports.length ? 'Saved locally · ready for handoff' : 'Ready when you are';
    renderReports(); publishContext();
  }
  function renderReports() {
    const list = $('report-list'); list.replaceChildren();
    if (!state.reports.length) {
      const empty = el('div', 'empty-state');
      empty.append(el('span', 'empty-symbol', '▤'), el('h3', '', 'Your next decision starts here.'), el('p', '', state.session ? 'Run a specialist to create your first source-grounded findings report. Reports stay available when you return.' : 'Open a repository to access its saved reports, or explore the clearly labelled example.'), button('See a sample findings report ↗', 'button secondary', openExample));
      list.append(empty); return;
    }
    for (const report of state.reports) {
      const agent = agentById(report.agentId);
      const card = el('article', 'report-card');
      const info = el('div', 'report-card-info'); info.append(el('h3', '', report.label), el('p', '', `${formatTime(report.timestamp)} · ${report.findings?.length || 0} parsed findings · ${report.hasDocx ? 'Markdown + Word' : 'Markdown'}`));
      if (report.quality?.issues?.length) info.append(el('div', 'report-card-status', `${report.quality.issues.length} format item${report.quality.issues.length > 1 ? 's' : ''} need review`));
      const actions = el('div', 'report-card-actions'); actions.append(button('Read report ↗', 'button primary small-button', () => openReportUrl(report.previewUrl).catch(error => toast(error.message, true))));
      const download = el('a', 'button secondary small-button', '↓ Markdown'); download.href = report.mdUrl; download.download = ''; actions.append(download);
      if (report.docxUrl) { const word = el('a', 'button secondary small-button', '↓ Word'); word.href = report.docxUrl; word.download = ''; actions.append(word); }
      card.append(el('span', 'agent-monogram', agent?.initials || 'TL'), info, actions); list.append(card);
    }
  }
  async function openReportUrl(url) { const report = await request(url); openReport(report); }
  async function openExample() { try { openReport(await request('/api/examples/fp-review')); } catch (error) { toast(error.message, true); } }
  function openReport(report) {
    state.report = report;
    $('report-reader-title').textContent = report.example ? 'Findings & remediation · Example' : report.label || 'Security findings report';
    $('report-reader-eyebrow').textContent = report.example ? 'SYNTHETIC EXAMPLE · NOT A SCAN' : 'SOURCE-GROUNDED / HUMAN REVIEW REQUIRED';
    const quality = $('report-quality'); quality.replaceChildren(); quality.className = 'report-quality';
    quality.classList.toggle('example', !!report.example);
    quality.classList.toggle('warning', !report.example && !!report.quality?.issues?.length);
    quality.append(document.createTextNode(report.example ? 'Illustrative report only. These are fictional paths and findings, not results from your repository.' : 'Automated format checks are not a security approval. Proposed fixes and tests require engineering review.'));
    if (report.quality?.issues?.length) {
      const details = el('details');
      details.append(el('summary', '', `${report.quality.issues.length} report-format warnings`));
      const list = el('ul');
      for (const issue of report.quality.issues) list.append(el('li', '', issue));
      details.append(list); quality.append(details);
    }
    $('report-ask').hidden = !!report.example || !report.id;
    for (const [id, url] of [['download-md', report.mdUrl], ['download-docx', report.docxUrl]]) {
      $(id).classList.toggle('hidden', !url || report.example); if (url) $(id).href = url; else $(id).removeAttribute('href');
    }
    $('reader-finding-count').textContent = report.findings?.length || 0;
    $('severity-filter').value = ''; $('disposition-filter').value = '';
    safeMarkdown($('report-markdown'), report.markdown);
    selectReportTab('full'); renderFindings();
    if (!$('report-dialog').open) $('report-dialog').showModal();
  }
  // Hands a report or finding to the Ask Threatlint view; chat.js owns the conversation.
  function askAbout(context, question) {
    if ($('report-dialog').open) $('report-dialog').close();
    showView('chat');
    document.dispatchEvent(new CustomEvent('threatlint:ask', { detail: { context, question } }));
  }
  function selectReportTab(tab) {
    const full = tab === 'full';
    $('report-tab-full').classList.toggle('active', full); $('report-tab-findings').classList.toggle('active', !full);
    $('report-markdown').classList.toggle('hidden', !full); $('report-findings').classList.toggle('hidden', full); $('finding-filters').classList.toggle('hidden', full);
    document.querySelector('.report-reader-body').scrollTop = 0;
  }
  function renderFindings() {
    const severity = $('severity-filter').value, disposition = $('disposition-filter').value;
    const findings = (state.report?.findings || []).filter(finding => (!severity || finding.severity === severity) && (!disposition || finding.disposition === disposition));
    const list = $('report-findings'); list.replaceChildren();
    for (const finding of findings) {
      const card = el('article', 'finding-card'); const header = el('div', 'finding-card-header');
      header.append(el('span', 'finding-id', finding.id), el('h3', '', finding.title), el('span', `severity-badge severity-${finding.severity}`, finding.severity));
      if (finding.disposition) header.append(el('span', 'disposition-badge', finding.disposition));
      const body = el('div', 'markdown'); safeMarkdown(body, finding.body);
      const actions = el('div', 'finding-card-actions');
      if (!state.report.example && state.report.id && state.report.agentId === FP_REVIEWER && finding.disposition === 'FALSE POSITIVE') {
        actions.append(button('Close FP & tune Semgrep…', 'button primary small-button', () => openFalsePositiveActions(finding)));
      }
      if (!state.report.example && state.report.id) actions.append(button('✦ Ask how to fix this', 'button secondary small-button', () => askAbout({ type: 'finding', reportId: state.report.id, findingId: finding.id, label: `${finding.id} · ${finding.title}` }, `How do I fix ${finding.id} in this codebase? Show the change and a regression test.`)));
      card.append(header, body, actions); list.append(card);
    }
    if (!findings.length) { const empty = el('div', 'empty-state'); empty.append(el('h3', '', 'No findings match this view.'), el('p', '', state.report?.findings?.length ? 'Adjust the severity or disposition filter.' : 'No structured finding blocks were detected. Read the full report for conclusions, scope, and limitations.')); list.append(empty); }
  }

  // Pre-fills from the finding's Original finding line: "AVIT000000095938462; rule.id; path/file.js:42".
  function falsePositiveTarget(finding) {
    const original = /Original finding\W*:\s*(.+)/i.exec(finding.body)?.[1] || '';
    const avits = [...new Set((original.match(/AVIT\d{7,15}/gi) || finding.title.match(/AVIT\d{7,15}/gi) || finding.body.match(/AVIT\d{7,15}/gi) || []).map(item => item.toUpperCase()))];
    const location = finding.evidence?.[0] || '';
    const [path, line] = location.split(':');
    const rule = original.split(/[;,]/).map(part => part.replaceAll(/[`*]/g, '').trim()).find(part => /^[\w-]+(?:\.[\w-]+){2,}$/.test(part) && !/\.(?:js|ts|py|java|go|rb|cs|php|tsx|jsx)$/.test(part)) || '';
    return { avit: avits.length === 1 ? avits[0] : '', rule, path: path || '', line: /^\d+$/.test(line || '') ? line : '' };
  }
  function fpStatus(id, text, tone = '') { const node = $(id); node.textContent = text; node.className = `field-note small ${tone ? `fp-status-${tone}` : ''}`; }
  function fpTarget() {
    return { rule: $('fp-semgrep-rule').value.trim(), repo: $('fp-semgrep-repo').value.trim(), path: $('fp-semgrep-path').value.trim(),
      line: $('fp-semgrep-line').value.trim() || null, deployment: $('fp-semgrep-deployment').value.trim() || undefined };
  }
  function openFalsePositiveActions(finding) {
    const target = falsePositiveTarget(finding);
    state.fpAction = { finding, avit: target.avit, matches: [], deployment: null };
    $('fp-action-title').textContent = `${finding.id} · ${finding.title}`;
    $('fp-action-summary').textContent = target.avit ? `ServiceNow ${target.avit} · FALSE POSITIVE · confidence ${finding.confidence}` : `FALSE POSITIVE · confidence ${finding.confidence} · no AVIT number found in this finding`;
    $('fp-snow-section').hidden = !target.avit;
    $('fp-close-avit').hidden = !target.avit; $('fp-close-avit').disabled = false;
    $('fp-attachment-name').textContent = target.avit ? `${target.avit}-threatlint-fp-review.md` : '';
    fpStatus('fp-snow-status', servicenowReady() ? '' : 'ServiceNow is not configured. Add the instance, client ID, and secret in Model & settings first.', servicenowReady() ? '' : 'warn');
    $('fp-semgrep-rule').value = target.rule; $('fp-semgrep-path').value = target.path; $('fp-semgrep-line').value = target.line;
    if (!$('fp-semgrep-repo').value && state.session?.repoPath) $('fp-semgrep-repo').value = state.session.provenance?.repository || repoName(state.session.repoPath);
    $('fp-semgrep-matches').replaceChildren(); fpStatus('fp-semgrep-status', ''); $('fp-action-error').textContent = '';
    $('fp-ignore-semgrep').disabled = true;
    $('fp-action-dialog').showModal();
  }
  async function closeAvitFalsePositive() {
    const action = state.fpAction; if (!action?.avit) return;
    if (!servicenowReady()) { fpStatus('fp-snow-status', 'Configure ServiceNow in Model & settings first.', 'warn'); return; }
    if (!window.confirm(`Close ${action.avit} in ServiceNow as Closed / False Positive and attach this report?`)) return;
    $('fp-close-avit').disabled = true; fpStatus('fp-snow-status', `Attaching the report and closing ${action.avit}…`);
    try {
      const result = await request('/api/servicenow/close-false-positive', { method: 'POST', body: JSON.stringify({ reportId: state.report.id, findingId: action.finding.id,
        servicenow: { instance: state.preferences.snowInstance, clientId: state.credentials.snowClientId, clientSecret: state.credentials.snowClientSecret } }) });
      const files = result.attachments.map(item => item.name).join(', ');
      if (result.closed) fpStatus('fp-snow-status', `${result.avit} closed as false positive. Attached ${files}.`, 'ok');
      else { fpStatus('fp-snow-status', `${result.avit}: report attached (${files}) and work note added, but ServiceNow kept state ${result.state} / ${result.substate} (likely pending approval).`, 'warn'); $('fp-close-avit').disabled = false; }
    } catch (error) { fpStatus('fp-snow-status', error.message, 'warn'); $('fp-close-avit').disabled = false; }
  }
  async function findSemgrepMatches() {
    const action = state.fpAction; if (!action) return;
    $('fp-action-error').textContent = ''; $('fp-semgrep-find').disabled = true; $('fp-ignore-semgrep').disabled = true;
    fpStatus('fp-semgrep-status', 'Reading the Semgrep token and searching open findings…'); $('fp-semgrep-matches').replaceChildren();
    try {
      const result = await request('/api/semgrep/false-positive/matches', { method: 'POST', body: JSON.stringify({ reportId: state.report.id, findingId: action.finding.id, target: fpTarget(),
        profile: $('snow-aws-profile').value.trim() || undefined }) });
      action.matches = result.matches; action.deployment = result.deployment.slug;
      for (const match of result.matches) {
        const label = el('label'); const box = el('input'); box.type = 'checkbox'; box.checked = true; box.value = String(match.id);
        label.append(box, document.createTextNode(`#${match.id} · ${match.rule} · ${match.path}:${match.line ?? '?'}${match.ref ? ` · ${match.ref}` : ''}`)); $('fp-semgrep-matches').append(label);
      }
      fpStatus('fp-semgrep-status', result.matches.length ? `${result.matches.length} open finding${result.matches.length > 1 ? 's' : ''} in ${result.deployment.name || result.deployment.slug} match this rule and file.` : 'No open Semgrep findings match this rule, project, and file. Check the rule ID and paths.', result.matches.length ? '' : 'warn');
      $('fp-ignore-semgrep').disabled = !result.matches.length;
    } catch (error) { fpStatus('fp-semgrep-status', error.message, 'warn'); }
    finally { $('fp-semgrep-find').disabled = false; }
  }
  async function ignoreSemgrepFalsePositive() {
    const action = state.fpAction; if (!action?.matches.length) return;
    const issueIds = [...$('fp-semgrep-matches').querySelectorAll('input:checked')].map(box => Number(box.value));
    if (!issueIds.length) { fpStatus('fp-semgrep-status', 'Select at least one finding to ignore.', 'warn'); return; }
    if (!window.confirm(`Ignore ${issueIds.length} Semgrep finding${issueIds.length > 1 ? 's' : ''} as false positive?`)) return;
    $('fp-ignore-semgrep').disabled = true; fpStatus('fp-semgrep-status', 'Updating Semgrep triage…');
    try {
      const result = await request('/api/semgrep/false-positive/ignore', { method: 'POST', body: JSON.stringify({ reportId: state.report.id, findingId: action.finding.id, target: { ...fpTarget(), deployment: action.deployment },
        issueIds, profile: $('snow-aws-profile').value.trim() || undefined }) });
      fpStatus('fp-semgrep-status', `Semgrep ignored ${result.triaged} finding${result.triaged === 1 ? '' : 's'} as false positive (including the same fingerprint on other branches).`, 'ok');
    } catch (error) { fpStatus('fp-semgrep-status', error.message, 'warn'); $('fp-ignore-semgrep').disabled = false; }
  }

  async function chooseRepository() {
    if (state.running) return;
    if (desktop) {
      try { const repoPath = await desktop.selectRepository(); if (repoPath) await connectRepository(repoPath); } catch (error) { toast(error.message, true); }
    } else { $('repository-error').textContent = ''; $('repo-path').value = state.session?.repoPath || ''; $('directory-browser').classList.add('hidden'); $('repository-dialog').showModal(); }
  }
  async function connectRepository(repoPath) {
    const data = await request('/api/session/local', { method: 'POST', body: JSON.stringify({ repoPath }) });
    await refreshSessions(); await openSession({ id: data.sessionId });
    if ($('repository-dialog').open) $('repository-dialog').close();
    toast(`${repoName(data.repoPath)} is ready for review.`);
  }
  async function browseDirectory(repoPath = '') {
    const query = repoPath ? `?path=${encodeURIComponent(repoPath)}` : '';
    const data = await request(`/api/fs/browse${query}`);
    $('repo-path').value = data.path;
    const container = $('directory-browser'); container.classList.remove('hidden'); container.replaceChildren();
    container.append(el('p', 'small subtle', data.path));
    if (data.parent) container.append(button('↑ Parent directory', 'directory-row', () => browseDirectory(data.parent).catch(error => { $('repository-error').textContent = error.message; })));
    for (const entry of data.entries) container.append(button(`${entry.isRepo ? '◇' : '▱'} ${entry.name}${entry.isRepo ? ' · Git repository' : ''}`, 'directory-row', () => browseDirectory(`${data.path}/${entry.name}`).catch(error => { $('repository-error').textContent = error.message; })));
  }
  function setAttachment(attachment) {
    if (!attachment) return;
    if (!/\.(sarif|json|md|txt)$/i.test(attachment.name) || new TextEncoder().encode(attachment.content).length > 5 * 1024 * 1024 || !attachment.content.trim()) { toast('Choose a nonempty SARIF, JSON, Markdown, or text file up to 5 MB.', true); return; }
    state.attachment = attachment;
    $('attachment-name').textContent = attachment.name; $('attachment-name').title = attachment.name;
    $('remove-attachment').classList.remove('hidden'); toast('Findings attached for this session. Source evidence will still be verified.');
  }
  async function chooseFindings() {
    if (state.running) return;
    if (desktop) { try { setAttachment(await desktop.selectFindings()); } catch (error) { toast(error.message, true); } }
    else $('findings-file').click();
  }

  function providerKeys(provider) {
    return { apiKey: provider === 'claude' ? state.credentials.claude || undefined : undefined, openaiApiKey: provider === 'openai' ? state.credentials.openai || undefined : undefined,
      copilotToken: provider === 'copilot' ? state.credentials.copilot || undefined : undefined };
  }
  function updateProviderDisplay() {
    $('stat-provider').textContent = { lmstudio: cloudProvider() ? 'Remote' : 'Local', claude: 'Claude', openai: 'OpenAI', copilot: 'Copilot' }[state.preferences.provider] || 'Local';
    updateRunControls();
  }
  function showSettings() { showView('settings'); }
  // Organization-specific help (SSO portal, Parameter Store names) comes from /api/config; nothing is built in.
  function renderAccessNotes() {
    const access = state.config.servicenow || {}, note = $('snow-access-note');
    note.replaceChildren('To triage ServiceNow application vulnerable items (AVITs), enter your instance URL and OAuth client ID and secret.');
    if (access.clientIdParameter && access.clientSecretParameter) {
      const code = value => Object.assign(document.createElement('code'), { textContent: value });
      const link = (href, label) => Object.assign(document.createElement('a'), { href, textContent: label, target: '_blank', rel: 'noopener noreferrer' });
      note.append(` They are stored in AWS Parameter Store (${access.region}): `);
      if (access.ssoUrl) note.append('sign in through ', link(access.ssoUrl, 'single sign-on'), ' and request access if you do not have it, then ');
      note.append('copy ', code(access.clientIdParameter), ' and ', code(access.clientSecretParameter), ' from ', link(access.parameterStoreUrl, 'Parameter Store'), ', or read them with your signed-in AWS CLI.');
    }
    $('snow-read-parameters').disabled = !(access.clientIdParameter && access.clientSecretParameter);
    $('semgrep-parameter-note').textContent = access.semgrepTokenParameter ? `, which can read it from Parameter Store ${access.semgrepTokenParameter}` : '';
  }
  function loadSettingsForm() {
    const provider = state.preferences.provider;
    document.querySelector(`input[name=provider][value="${provider}"]`).checked = true;
    $('model-url').value = state.preferences.lmstudioUrl;
    $('model-id').value = selectedModel(); state.modelListProvider = null;
    $('api-key').value = state.credentials[provider] || '';
    $('settings-error').textContent = '';
    $('cloud-consent').checked = state.consent.has(consentKey());
    renderAccessNotes(); fillServiceNowForm(); void loadSemgrepSettings(); void loadAdoSettings();
    updateSettingsFields(provider);
  }
  // Callers that need a specific section (e.g. ServiceNow before an AVIT run) scroll to it.
  function showSettingsSection(section) {
    showSettings();
    const target = $(`settings-${['servicenow', 'semgrep', 'ado'].includes(section) ? section : 'model'}`);
    target?.scrollIntoView({ behavior: 'instant', block: 'start' });
    for (const link of document.querySelectorAll('.settings-nav a')) link.classList.toggle('active', link.getAttribute('href') === `#${target?.id}`);
  }
  // The saved connection lives in the Threatlint config (shared with the CLI); the secret never reaches the page.
  const MASK = '••••••••••••';
  function fillServiceNowForm() {
    const saved = state.snowSaved || {};
    $('snow-instance').value = state.preferences.snowInstance || saved.instance || state.config.servicenow?.instance || '';
    $('snow-client-id').value = state.credentials.snowClientId || saved.clientId || '';
    $('snow-client-secret').value = state.credentials.snowClientSecret ? state.credentials.snowClientSecret : saved.hasSecret ? MASK : '';
    updateSnowStatus();
  }
  async function loadSemgrepSettings() {
    try { state.semgrepSaved = await request('/api/semgrep/settings'); } catch { state.semgrepSaved = null; }
    const saved = state.semgrepSaved || {};
    $('semgrep-token').value = saved.hasToken ? MASK : '';
    $('semgrep-status').textContent = saved.inKeyring ? 'Saved by `threatlint semgrep login` in the OS credential store (CLI only). Enter it here to use it in the Workbench too.'
      : saved.hasToken ? `Saved in ${saved.path}${saved.deployment ? ` · deployment ${saved.deployment}` : ''}. The token is never shown.` : 'Not configured.';
  }
  async function saveSemgrep(event) {
    event.preventDefault(); $('semgrep-error').textContent = '';
    const typed = $('semgrep-token').value.trim();
    if (!typed || typed === MASK) { toast('The saved Semgrep token is unchanged.'); return; }
    try { state.semgrepSaved = await request('/api/semgrep/settings', { method: 'POST', body: JSON.stringify({ token: typed }) }); }
    catch (error) { $('semgrep-error').textContent = error.message; return; }
    await loadSemgrepSettings(); toast('Semgrep token validated and saved. It is never shown again.');
  }
  // One PAT per Azure DevOps organization: list them (sources only), add or replace one, remove one.
  async function loadAdoSettings() {
    try { state.adoSaved = await request('/api/ado/settings'); } catch { state.adoSaved = null; }
    const orgs = state.adoSaved?.organizations || [];
    const list = $('ado-organizations'); list.replaceChildren();
    for (const org of orgs) {
      const row = el('div', 'ado-org-row');
      row.append(el('strong', '', org.name), el('span', 'small subtle', ` · ${org.source} · PAT ••••••••`),
        button('Remove', 'button secondary small-button', async () => {
          if (!confirm(`Remove the saved PAT for ${org.name}?`)) return;
          try { state.adoSaved = await request(`/api/ado/settings/${encodeURIComponent(org.name)}`, { method: 'DELETE' }); } catch (error) { $('ado-error').textContent = error.message; return; }
          await loadAdoSettings(); toast(`Removed the PAT for ${org.name}.`);
        }));
      list.append(row);
    }
    $('ado-pat').value = '';
    $('ado-status').textContent = orgs.length ? `${orgs.length} organization${orgs.length > 1 ? 's' : ''} configured. Each clone uses its own organization's PAT. PATs are never shown.`
      : state.adoSaved?.hasPat ? `Saved in ${state.adoSaved.source}. The PAT is never shown.` : 'Not configured. Required to review AVITs.';
  }
  async function saveAdo(event) {
    event.preventDefault(); $('ado-error').textContent = '';
    const pat = $('ado-pat').value.trim(), organization = $('ado-organization').value.trim();
    if (!organization) { $('ado-error').textContent = 'Enter the organization this PAT is for.'; return; }
    if (!pat) { $('ado-error').textContent = 'Enter the PAT for this organization.'; return; }
    try { await request('/api/ado/settings', { method: 'POST', body: JSON.stringify({ organization, pat }) }); }
    catch (error) { $('ado-error').textContent = error.message; return; }
    $('ado-organization').value = ''; await loadAdoSettings(); toast(`PAT for ${organization} validated and saved. It is never shown again.`);
  }
  async function loadSavedServiceNow() {
    try { state.snowSaved = await request('/api/servicenow/settings'); } catch { state.snowSaved = null; }
    if (state.snowSaved?.instance && !state.preferences.snowInstance) state.preferences.snowInstance = state.snowSaved.instance;
  }
  function servicenowReady() {
    const saved = state.snowSaved || {};
    return !!((state.preferences.snowInstance || saved.instance) && (state.credentials.snowClientId || saved.clientId) && (state.credentials.snowClientSecret || saved.hasSecret));
  }
  function updateSnowStatus(message) {
    $('snow-status').textContent = message || (state.snowSaved?.hasSecret
      ? `Saved in ${state.snowSaved.path}. The secret is never shown and is sent only to your ServiceNow instance.`
      : servicenowReady() ? 'Configured for this session only. Save to keep it in the Threatlint config.'
        : 'Not configured. Enter the instance URL, client ID, and secret once; they are saved in the Threatlint config.');
  }
  /** The instance must be HTTPS without credentials or a path; the server also restricts it to ServiceNow hosts. */
  function snowInstanceUrl(value) {
    if (!value) return '';
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || !['', '/'].includes(url.pathname)) throw new Error('Invalid instance');
    return url.origin;
  }
  async function readSnowParameters() {
    $('snow-read-parameters').disabled = true; updateSnowStatus('Reading Parameter Store with your AWS CLI session…');
    try {
      const values = await request('/api/servicenow/parameter-store', { method: 'POST', body: JSON.stringify({ profile: $('snow-aws-profile').value.trim() || undefined }) });
      $('snow-client-id').value = values.clientId; $('snow-client-secret').value = values.clientSecret;
      updateSnowStatus('Loaded from Parameter Store. Click Save ServiceNow settings to keep them.');
    } catch (error) { updateSnowStatus(error.message); }
    finally { $('snow-read-parameters').disabled = false; }
  }
  function updateSettingsFields(provider) {
    const local = provider === 'lmstudio';
    $('local-settings').classList.toggle('hidden', !local); $('cloud-settings').classList.toggle('hidden', local);
    $('api-key-label').firstChild.textContent = provider === 'copilot' ? 'GitHub token ' : 'API key ';
    const source = state.config.providers[provider], where = { claude: 'ANTHROPIC_API_KEY or ~/.claude/settings.json', openai: 'OPENAI_API_KEY', copilot: 'GH_TOKEN/GITHUB_TOKEN or `gh auth login`' }[provider];
    $('environment-key-note').textContent = local ? '' : source ? `Using ${source}. Leave this empty, or enter a key for this session only.` : `No key found in ${where}. Enter one for this session.`;
    if (state.modelListProvider !== provider) { state.modelListProvider = provider; fillModelSelect([], $('model-id').value.trim() || state.preferences.models[provider] || ''); $('model-source').textContent = ''; }
    // Load even without a known key so the server can explain where to sign in (e.g. a ChatGPT-only Codex login).
    if (!local && !$('model-select').dataset.loaded) void discoverModels();
    // Remote LM Studio-compatible servers also require explicit data-sharing consent.
    let remote = !local;
    if (local) { try { remote = !['localhost', '127.0.0.1', '[::1]'].includes(new URL($('model-url').value).hostname); } catch { remote = true; } }
    $('cloud-consent-label').classList.toggle('hidden', !remote);
  }
  function saveSettings(event) {
    event.preventDefault();
    const provider = document.querySelector('input[name=provider]:checked').value;
    const model = $('model-id').value.trim();
    if (!model) { $('settings-error').textContent = 'Load models and choose one, or enter a model ID.'; return; }
    let url;
    try {
      url = new URL($('model-url').value || DEFAULTS.lmstudioUrl);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error('Invalid model-server URL');
      if (url.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) throw new Error('Remote servers require HTTPS');
    } catch { $('settings-error').textContent = 'Use an HTTP(S) model-server URL without credentials. Remote servers require HTTPS.'; return; }
    $('settings-error').textContent = '';
    state.preferences.provider = provider;
    state.preferences.models[provider] = model;
    state.preferences.model = model;
    state.preferences.lmstudioUrl = url.toString().replace(/\/$/, '');
    if (provider !== 'lmstudio') state.credentials[provider] = $('api-key').value.trim();
    if ($('cloud-consent').checked) state.consent.add(consentKey()); else state.consent.delete(consentKey());
    savePreferences();
    updateProviderDisplay(); toast('Model settings saved. Credentials remain in memory only.');
  }
  function savePreferences() {
    const { provider, models, lmstudioUrl, snowInstance } = state.preferences;
    try { localStorage.setItem('threatlint.preferences.v2', JSON.stringify({ provider, models, lmstudioUrl, snowInstance })); } catch { /* in-memory operation remains available */ }
  }
  async function saveServiceNow(event) {
    event.preventDefault();
    $('servicenow-error').textContent = '';
    let snowInstance;
    try { snowInstance = snowInstanceUrl($('snow-instance').value.trim()); } catch { $('servicenow-error').textContent = 'Use the HTTPS ServiceNow instance URL, e.g. https://<instance>.service-now.com'; return; }
    const snowClientId = $('snow-client-id').value.trim(), typed = $('snow-client-secret').value.trim();
    // The masked placeholder means "keep the saved secret".
    const snowClientSecret = typed === MASK ? '' : typed;
    const hasSecret = !!snowClientSecret || (typed === MASK && state.snowSaved?.hasSecret);
    if ((snowClientId || hasSecret) && !(snowInstance && snowClientId && hasSecret)) { $('servicenow-error').textContent = 'ServiceNow needs the instance URL, client ID, and client secret together.'; return; }
    try {
      state.snowSaved = await request('/api/servicenow/settings', { method: 'POST', body: JSON.stringify({ instance: snowInstance, clientId: snowClientId, clientSecret: snowClientSecret || undefined }) });
    } catch (error) { $('servicenow-error').textContent = error.message; return; }
    state.preferences.snowInstance = snowInstance;
    // The server now holds the credentials; requests send blanks and it fills them in.
    state.credentials.snowClientId = ''; state.credentials.snowClientSecret = '';
    savePreferences(); fillServiceNowForm(); toast('ServiceNow settings saved to the Threatlint config. The secret is never shown again.');
  }
  // The dropdown is the normal path; the manual field remains for IDs a list omits. Selecting one fills the other.
  function fillModelSelect(models, selected) {
    const select = $('model-select');
    const options = models.map(model => { const option = el('option', '', model.name && model.name !== model.id ? `${model.name} · ${model.id}` : model.id); option.value = model.id; return option; });
    if (selected && !models.some(model => model.id === selected)) { const option = el('option', '', `${selected} (current)`); option.value = selected; options.unshift(option); }
    if (!options.length) { const option = el('option', '', 'Load models to choose'); option.value = ''; options.push(option); }
    select.replaceChildren(...options); select.value = selected || options[0].value; select.dataset.loaded = models.length ? '1' : '';
    $('model-id').value = select.value;
  }
  async function discoverModels() {
    const provider = document.querySelector('input[name=provider]:checked').value;
    $('discover-models').disabled = true; $('settings-error').textContent = ''; $('model-source').textContent = 'Loading models…';
    try {
      let models, source;
      if (provider === 'lmstudio') {
        models = (await request(`/api/lmstudio/models?baseUrl=${encodeURIComponent($('model-url').value || DEFAULTS.lmstudioUrl)}`)).models.map(id => ({ id, name: id }));
        source = 'your model server';
        if (!models.length) throw new Error('The server is reachable but no model is loaded. Load a model in LM Studio.');
      } else {
        ({ models, source } = await request('/api/models', { method: 'POST', body: JSON.stringify({ provider, key: $('api-key').value.trim() || state.credentials[provider] || undefined }) }));
        if (!models.length) throw new Error('No models are available for this key. Check the account or plan.');
      }
      const current = $('model-id').value.trim() || state.preferences.models[provider];
      fillModelSelect(models, models.some(model => model.id === current) ? current : models[0].id);
      $('model-source').textContent = `${models.length} model${models.length > 1 ? 's' : ''} available · listed with ${source === 'session' ? 'the key entered here' : source}`;
    } catch (error) { $('model-source').textContent = ''; $('settings-error').textContent = error.message; }
    finally { $('discover-models').disabled = false; }
  }

  function log(message, kind = '') {
    $('activity-empty').classList.add('hidden'); $('activity-log').classList.remove('hidden');
    const container = $('activity-log');
    const follow = container.scrollHeight - container.scrollTop - container.clientHeight < 100;
    const node = el('div', `log-event ${kind}`, message); container.append(node);
    if (++state.activityCount > 1500) container.firstChild?.remove();
    if (follow) container.scrollTop = container.scrollHeight;
  }
  function logText(text) {
    const container = $('activity-log'); const follow = container.scrollHeight - container.scrollTop - container.clientHeight < 100;
    let node = container.lastElementChild;
    if (!node?.classList.contains('log-text')) { node = el('div', 'log-text'); container.append(node); }
    node.append(document.createTextNode(text));
    if (node.textContent.length > 100_000) node.textContent = '[Earlier streaming output omitted from this activity view]\n' + node.textContent.slice(-80_000);
    if (follow) container.scrollTop = container.scrollHeight;
  }
  function finishRun(result) {
    state.running = false;
    for (const id of state.pipeline) if (state.statuses[id] === 'running' || state.statuses[id] === 'ready') state.statuses[id] = result === 'complete' ? state.statuses[id] : result;
    $('activity-badge').classList.remove('running');
    const label = { complete: 'Review complete', cancelled: 'Review stopped', error: 'Review needs attention', interrupted: 'Connection interrupted' }[result] || result;
    $('activity-badge').replaceChildren(el('span', 'status-dot'), document.createTextNode(label));
    $('activity-detail').textContent = result === 'complete' ? 'Completed reports are available in your report library.' : 'Completed reports remain available. Incomplete reviews are not saved as final reports.';
    const logKind = { complete: 'success', error: 'error' }[result] || '';
    log(label, logKind);
    renderPipeline(); renderPresets(); renderAgents();
    refreshReports().catch(error => toast(error.message, true)); refreshSessions().catch(() => {});
  }
  // ── False positive review (AVIT batch) ──
  const STAGES = { fetching: 'Fetching', checkout: 'Cloning', triage: 'Triaging', reported: 'Reported', resolving: 'Updating ServiceNow',
    done: 'Done', error: 'Error', 'out-of-scope': 'Out of scope', cancelled: 'Cancelled', queued: 'Queued' };
  function avitCard(avit) {
    let card = document.getElementById(`avit-${avit}`);
    if (card) return card;
    card = el('article', 'avit-card'); card.id = `avit-${avit}`;
    const header = el('header'); header.append(el('span', 'avit-id', avit), el('span', 'avit-stage stage-queued', 'Queued'), el('span', 'avit-disposition'));
    card.append(header, el('div', 'avit-detail'), el('ul', 'avit-outcome'), el('div', 'avit-actions'));
    $('fpreview-results').append(card);
    return card;
  }
  function renderAvitItem(event) {
    const card = avitCard(event.avit);
    const stage = card.querySelector('.avit-stage');
    if (event.stage && STAGES[event.stage]) { stage.textContent = STAGES[event.stage]; stage.className = `avit-stage stage-${event.stage}`; }
    if (event.tool) { state.avitTools[event.avit] = (state.avitTools[event.avit] || 0) + 1; card.querySelector('.avit-detail').textContent = `Inspecting the repository (${state.avitTools[event.avit]} tool calls)…`; }
    else if (event.detail !== undefined) card.querySelector('.avit-detail').textContent = event.detail;
    if (event.disposition) { const badge = card.querySelector('.avit-disposition'); badge.className = 'avit-disposition disposition-badge'; badge.textContent = event.disposition; }
    if (event.outcome) {
      const list = card.querySelector('.avit-outcome'); list.replaceChildren();
      const o = event.outcome;
      if (o.attached) list.append(el('li', '', 'Word report attached to the AVIT'));
      if (o.closed === true) list.append(el('li', '', 'Closed as false positive with the Threatlint work note'));
      if (o.closed === 'state not applied') list.append(el('li', '', 'ServiceNow did not keep the closed state/substate (check its business rules)'));
      if (o.leftOpen) list.append(el('li', '', 'Left open with “True positive, see attached report.”'));
      for (const line of o.semgrep || []) list.append(el('li', '', line.replace(/^[✓!]\s*/, 'Semgrep: ')));
    }
    if (event.report && !card.querySelector('.avit-actions button')) {
      card.querySelector('.avit-actions').append(button('Read report ↗', 'button secondary small-button', () => openReportUrl(event.report.previewUrl).catch(error => toast(error.message, true))));
      if (event.report.docxUrl) { const word = el('a', 'button secondary small-button', '↓ Word'); word.href = event.report.docxUrl; word.download = ''; card.querySelector('.avit-actions').append(word); }
    }
  }
  function renderSctaskItem(event) {
    let card = document.getElementById(`sctask-${event.sctask}`);
    if (!card) {
      card = el('article', 'avit-card sctask-card'); card.id = `sctask-${event.sctask}`;
      const header = el('header'); header.append(el('span', 'avit-id', event.sctask), el('span', 'avit-stage stage-queued', 'Catalog task'));
      card.append(header, el('div', 'avit-detail')); $('fpreview-results').prepend(card);
    }
    const stage = card.querySelector('.avit-stage');
    const label = { reviewing: 'Reviewing its AVITs', resolving: 'Updating the task', done: 'Done', error: 'Error' }[event.stage];
    if (label) { stage.textContent = label; stage.className = `avit-stage stage-${event.stage === 'reviewing' ? 'triage' : event.stage}`; }
    card.querySelector('.avit-detail').textContent = event.avits ? `${event.detail}: ${event.avits.join(', ')}` : event.detail || '';
  }
  function fpreviewRunning(running) {
    state.fpreviewRunning = running;
    $('fpreview-start').disabled = running; $('fpreview-avits').disabled = running; $('fpreview-cancel').classList.toggle('hidden', !running);
  }
  // Required setup, as `threatlint setup --check` sees it; ServiceNow values typed this session also count.
  const SETUP_SECTIONS = { 'ServiceNow OAuth client': 'servicenow', 'Azure DevOps PAT': 'ado', 'Semgrep API token': 'semgrep' };
  async function updateFpreviewSetup() {
    let items = [];
    try { items = (await request('/api/setup/status')).items || []; } catch { /* shown as unknown below */ }
    state.setupMissing = items.filter(item => !item.configured && !(SETUP_SECTIONS[item.name] === 'servicenow' && servicenowReady())).map(item => item.name);
    const box = $('fpreview-setup'); box.replaceChildren();
    const heading = document.createElement('strong'); heading.textContent = state.setupMissing.length ? 'Required setup is incomplete' : 'Required setup complete';
    const list = document.createElement('ul'); list.className = 'setup-checklist';
    for (const item of items) {
      const done = !state.setupMissing.includes(item.name), row = document.createElement('li');
      row.textContent = `${done ? '✓' : '✗'} ${item.name}${done ? (item.source ? ` · ${item.source}` : '') : ' · '}`;
      if (!done) { const link = document.createElement('a'); link.href = '#'; link.textContent = 'Set up in Settings'; link.addEventListener('click', event => { event.preventDefault(); showSettingsSection(SETUP_SECTIONS[item.name]); }); row.append(link, document.createTextNode(` or run \`${item.fix.split('  ')[0]}\``)); }
      list.append(row);
    }
    box.append(heading, list);
    box.className = `field-note small ${state.setupMissing.length ? 'fp-status-warn' : 'subtle'}`;
    $('fpreview-model').textContent = selectedModel() ? `Model: ${selectedModel()} (${state.preferences.provider}).` : 'Choose a model in Settings first.';
  }
  async function startAvitBatch(event) {
    event.preventDefault(); $('fpreview-error').textContent = '';
    let avits;
    const sctasks = [...new Set(($('fpreview-avits').value.toUpperCase().match(/\bSCTASK\d{7,10}\b/g) || []))];
    try { avits = parseAvits($('fpreview-avits').value.replace(/\bSCTASK\d{7,10}\b/gi, ' ')); } catch (error) { $('fpreview-error').textContent = error.message; return; }
    if (!avits.length && !sctasks.length) { $('fpreview-error').textContent = 'Enter at least one AVIT or SCTASK number.'; return; }
    if (avits.length > 50) { $('fpreview-error').textContent = 'Review at most 50 AVITs at a time.'; return; }
    if (!selectedModel()) { showSettings(); toast('Choose a model before starting a review.', true); return; }
    if (cloudProvider() && !state.consent.has(consentKey())) { showSettings(); toast('Authorize remote context sharing in model settings first.', true); return; }
    if (!servicenowReady()) { showSettingsSection('servicenow'); toast('Configure ServiceNow before reviewing AVITs.', true); return; }
    if (!state.connected || state.running || state.fpreviewRunning) { toast('Another review is running, or the Workbench is not connected.', true); return; }
    if (!await requireSemgrep()) return;
    await updateFpreviewSetup();
    if (state.setupMissing.length) { $('fpreview-error').textContent = `Finish the required setup first: ${state.setupMissing.join(', ')}.`; return; }
    state.avitTools = {}; $('fpreview-results').replaceChildren(); for (const avit of avits) avitCard(avit);
    fpreviewRunning(true);
    const provider = state.preferences.provider;
    state.ws.send(JSON.stringify({ action: 'run_avit_batch', avits: [...avits, ...sctasks].join(' '), provider, model: selectedModel(), lmstudioUrl: state.preferences.lmstudioUrl, lmstudioModel: state.preferences.models.lmstudio,
      ...providerKeys(provider), awsProfile: $('snow-aws-profile').value.trim() || undefined,
      servicenow: { instance: state.preferences.snowInstance, clientId: state.credentials.snowClientId || undefined, clientSecret: state.credentials.snowClientSecret || undefined } }));
  }

  function handleEvent(event) {
    switch (event.type) {
      case 'avit_batch_start': for (const avit of event.avits) avitCard(avit); break;
      case 'sctask_item': renderSctaskItem(event); break;
      case 'avit_item': renderAvitItem(event); break;
      case 'avit_batch_complete': fpreviewRunning(false); toast(event.cancelled ? 'AVIT review stopped.' : 'AVIT review complete.'); break;
      case 'avit_batch_error': fpreviewRunning(false); $('fpreview-error').textContent = event.message; break;
      case 'avit_fetch': log(`Fetching ${event.count} AVIT${event.count > 1 ? 's' : ''} from ${event.instance}…`); break;
      case 'avit_loaded': log(`ServiceNow returned ${event.retrieved} CodeSecurity AVIT${event.retrieved === 1 ? '' : 's'}${event.missing.length ? ` · not found: ${event.missing.join(', ')}` : ''}${event.excluded?.length ? ` · skipped (not CodeSecurity): ${event.excluded.join(', ')}` : ''}`, event.missing.length || event.excluded?.length ? 'error' : 'success'); break;
      case 'pipeline_start': log(`Review started · ${event.agentIds.length} specialist${event.agentIds.length > 1 ? 's' : ''} · ${selectedModel()}`); break;
      case 'agent_start': state.statuses[event.agentId] = 'running'; renderPipeline(); log(`${agentById(event.agentId)?.initials || '→'}  ${event.label} · ${event.skills?.length || agentById(event.agentId)?.skills.length || ''} skills loaded`, 'agent-start'); break;
      case 'iteration': $('activity-detail').textContent = `${agentById(event.agentId)?.label || 'Agent'} · inspection step ${event.n}`; break;
      case 'text_chunk': logText(event.text); break;
      case 'tool_executing': { const input = event.input || {}; const detail = input.file_path || input.pattern || input.command || ''; log(`↳ ${event.tool} ${String(detail).slice(0, 180)}`); break; }
      case 'tool_result': break;
      case 'agent_complete': state.statuses[event.agentId] = 'complete'; renderPipeline(); log(`${event.label} report saved locally${event.hasDocx ? ' · Word export ready' : ''}`, 'success'); refreshReports().catch(error => toast(error.message, true)); break;
      case 'agent_error': state.statuses[event.agentId] = 'error'; renderPipeline(); log(event.message, 'error'); toast(event.message, true); break;
      case 'pipeline_complete': finishRun(event.status || 'complete'); break;
      case 'cancelled': log('Cancellation acknowledged. No incomplete report will be marked complete.'); break;
      case 'chat_start': case 'chat_chunk': case 'chat_tool': case 'chat_complete': case 'chat_error':
        document.dispatchEvent(new CustomEvent('threatlint:chat-event', { detail: event })); break;
      case 'error': log(event.message, 'error'); toast(event.message, true); if (state.running) finishRun('error'); break;
      default: break;
    }
  }
  function connectSocket() {
    clearTimeout(state.reconnectTimer);
    const socket = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/`);
    state.ws = socket;
    socket.addEventListener('open', () => { state.connected = true; $('connection-status').textContent = 'Connected'; $('connection-status').className = 'connection online'; updateRunControls(); });
    socket.addEventListener('message', message => { try { handleEvent(JSON.parse(message.data)); } catch (error) { console.error('Invalid runner event', error.message); } });
    socket.addEventListener('close', () => {
      state.connected = false; $('connection-status').textContent = 'Disconnected'; $('connection-status').className = 'connection offline';
      if (state.running) finishRun('interrupted');
      updateRunControls();
      if (!state.intentionalClose) state.reconnectTimer = setTimeout(connectSocket, 3000);
    });
    socket.addEventListener('error', () => { $('connection-status').textContent = 'Reconnecting'; });
  }
  function parseAvits(text) {
    const tokens = text.toUpperCase().split(/[\s,;]+/).filter(Boolean);
    const invalid = tokens.filter(token => !/^AVIT\d{7,15}$/.test(token));
    if (invalid.length) throw new Error(`Not an AVIT number: ${invalid.slice(0, 5).join(', ')} (expected AVIT followed by 7 to 15 digits, e.g. AVIT000000095938462 or AVIT0042599)`);
    return [...new Set(tokens)];
  }
  /** Semgrep is checked live, so installing it and retrying works without restarting the Workbench. */
  async function requireSemgrep() {
    if (!state.pipeline.some(id => (state.config.semgrepAgents || []).includes(id))) return true;
    try { state.config = await request('/api/config'); } catch { return true; /* the runner enforces it */ }
    if (state.config.semgrep) return true;
    toast('Semgrep Community Edition is required for Findings triage. Install it with `python3 -m pip install semgrep` (or `brew install semgrep`), confirm `semgrep --version`, then run again.', true);
    return false;
  }
  async function startRun() {
    if (state.running || !state.session || !state.pipeline.length || !state.connected) return;
    let avits = [];
    if (state.pipeline.includes(FP_REVIEWER)) {
      try { avits = parseAvits($('avit-list').value); } catch (error) { toast(error.message, true); $('avit-list').focus(); return; }
      if (avits.length > (state.config.servicenow?.maxAvits || 50)) { toast(`Review at most ${state.config.servicenow?.maxAvits || 50} AVITs per report.`, true); return; }
      if (avits.length && state.attachment) { toast('Use either an attached findings file or ServiceNow AVITs for one review, not both.', true); return; }
      if (avits.length && !servicenowReady()) { showSettingsSection('servicenow'); toast('Authenticate through SSO and set the ServiceNow instance, client ID, and secret first.', true); return; }
    }
    if (!selectedModel()) { showSettings(); toast('Choose a model before starting a review.', true); return; }
    if (cloudProvider() && !state.consent.has(consentKey())) { showSettings(); toast('Authorize remote context sharing in model settings first.', true); return; }
    const provider = state.preferences.provider;
    if (provider !== 'lmstudio' && !state.credentials[provider] && !state.config.providers[provider]) { showSettings(); toast(provider === 'copilot' ? 'Sign in with the GitHub CLI (gh auth login) or enter a GitHub token for Copilot.' : 'A provider API key is required for this review.', true); return; }
    if (state.pipeline.includes(FP_REVIEWER) && !state.attachment && !avits.length && !$('target').value.trim() && state.pipeline[0] === FP_REVIEWER) { toast('Attach findings, enter ServiceNow AVITs, or specify the findings location in your review scope.', true); $('attach-findings').focus(); return; }
    if (!await requireSemgrep() || state.running || !state.connected) return;
    state.running = true; state.statuses = Object.fromEntries(state.pipeline.map(id => [id, 'ready']));
    $('activity-empty').classList.add('hidden'); $('activity-log').classList.remove('hidden'); $('activity-log').replaceChildren(); state.activityCount = 0;
    $('activity-badge').classList.add('running'); $('activity-badge').replaceChildren(el('span', 'status-dot'), document.createTextNode('Reviewing'));
    const payload = { action: 'run_pipeline', sessionId: state.session.id, agentIds: [...state.pipeline], target: $('target').value.trim(), provider,
      model: selectedModel(), lmstudioUrl: state.preferences.lmstudioUrl, lmstudioModel: state.preferences.models.lmstudio,
      ...providerKeys(provider),
      attachment: state.attachment || undefined, continueOnError: false,
      ...(avits.length ? { avits, servicenow: { instance: state.preferences.snowInstance, clientId: state.credentials.snowClientId, clientSecret: state.credentials.snowClientSecret } } : {}) };
    try { state.ws.send(JSON.stringify(payload)); } catch (error) { finishRun('error'); toast(error.message, true); }
    renderPipeline(); renderPresets(); renderAgents();
  }

  function wireEvents() {
    for (const item of document.querySelectorAll('[data-view]')) item.addEventListener('click', () => showView(item.dataset.view));
    for (const item of document.querySelectorAll('[data-go-view]')) item.addEventListener('click', () => showView(item.dataset.goView));
    for (const close of document.querySelectorAll('.close-dialog')) close.addEventListener('click', () => close.closest('dialog').close());
    for (const dialog of document.querySelectorAll('dialog')) dialog.addEventListener('click', event => { if (event.target === dialog) { const rect = dialog.getBoundingClientRect(); if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) dialog.close(); } });
    $('choose-repo').addEventListener('click', chooseRepository);
    $('repository-form').addEventListener('submit', async event => { event.preventDefault(); $('open-repository').disabled = true; $('repository-error').textContent = ''; try { await connectRepository($('repo-path').value.trim()); } catch (error) { $('repository-error').textContent = error.message; } finally { $('open-repository').disabled = false; } });
    $('browse-repository').addEventListener('click', () => browseDirectory($('repo-path').value.trim()).catch(error => { $('repository-error').textContent = error.message; }));
    $('refresh-sessions').addEventListener('click', () => refreshSessions().catch(error => toast(error.message, true)));
    $('refresh-reports').addEventListener('click', () => refreshReports().catch(error => toast(error.message, true)));
    $('configure-provider').addEventListener('click', showSettings);
    $('servicenow-form').addEventListener('submit', saveServiceNow);
    $('fpreview-form').addEventListener('submit', startAvitBatch); $('fpreview-cancel').addEventListener('click', () => { if (state.ws?.readyState === 1) state.ws.send(JSON.stringify({ action: 'cancel' })); });
    document.addEventListener('threatlint:view', event => { if (event.detail.view === 'fpreview') { void loadSemgrepSettings().then(updateFpreviewSetup); } }); $('semgrep-form').addEventListener('submit', saveSemgrep); $('ado-form').addEventListener('submit', saveAdo);
    for (const link of document.querySelectorAll('.settings-nav a')) link.addEventListener('click', event => { event.preventDefault(); showSettingsSection(link.getAttribute('href').replace('#settings-', '')); });
    $('settings-form').addEventListener('submit', saveSettings);
    $('model-select').addEventListener('change', () => { $('model-id').value = $('model-select').value; });
    $('model-id').addEventListener('change', () => fillModelSelect([...$('model-select').options].filter(option => option.value && !option.textContent.endsWith('(current)')).map(option => ({ id: option.value, name: option.textContent.split(' · ')[0] })), $('model-id').value.trim())); $('discover-models').addEventListener('click', discoverModels);
    let settingsProvider = state.preferences.provider;
    for (const radio of document.querySelectorAll('input[name=provider]')) radio.addEventListener('change', () => {
      if (settingsProvider !== 'lmstudio') state.credentials[settingsProvider] = $('api-key').value.trim();
      settingsProvider = radio.value; $('model-id').value = state.preferences.models[settingsProvider] || '';
      $('api-key').value = state.credentials[settingsProvider] || ''; $('cloud-consent').checked = false;
      updateSettingsFields(settingsProvider);
    });
    $('snow-read-parameters').addEventListener('click', readSnowParameters);
    $('fp-close-avit').addEventListener('click', closeAvitFalsePositive); $('fp-semgrep-find').addEventListener('click', findSemgrepMatches);
    $('fp-ignore-semgrep').addEventListener('click', ignoreSemgrepFalsePositive); $('fp-action-form').addEventListener('submit', event => event.preventDefault());
    for (const id of ['fp-semgrep-rule', 'fp-semgrep-repo', 'fp-semgrep-path', 'fp-semgrep-line', 'fp-semgrep-deployment']) $(id).addEventListener('input', () => { $('fp-ignore-semgrep').disabled = true; });
    $('model-url').addEventListener('input', () => { updateSettingsFields('lmstudio'); $('cloud-consent').checked = false; });
    $('attach-findings').addEventListener('click', chooseFindings);
    $('findings-file').addEventListener('change', async event => {
      const file = event.target.files[0];
      if (!file) return;
      try {
        if (file.size > 5 * 1024 * 1024) throw new Error('The attachment exceeds 5 MB.');
        setAttachment({ name: file.name, content: await file.text() });
      } catch (error) { toast(error.message, true); }
      event.target.value = '';
    });
    $('remove-attachment').addEventListener('click', () => { state.attachment = null; $('attachment-name').textContent = 'SARIF, JSON, Markdown, or text · up to 5 MB'; $('attachment-name').title = ''; $('remove-attachment').classList.add('hidden'); });
    $('browse-agents').addEventListener('click', () => showView('agents'));
    $('clear-pipeline').addEventListener('click', () => {
      if (state.running) return;
      state.pipeline = []; state.statuses = {}; state.preset = ''; renderPipeline(); renderPresets(); renderAgents();
    });
    $('agent-search').addEventListener('input', renderAgents); $('agent-category').addEventListener('change', renderAgents); $('skill-search').addEventListener('input', renderSkills);
    let starting = false;
    $('start-run').addEventListener('click', () => {
      if (starting) return;
      starting = true;
      startRun().catch(error => toast(error.message, true)).finally(() => { starting = false; });
    });
    $('cancel-run').addEventListener('click', () => { if (state.running && state.connected) { state.ws.send(JSON.stringify({ action: 'cancel' })); $('activity-detail').textContent = 'Stopping the current model request…'; } });
    $('clear-activity').addEventListener('click', () => { $('activity-log').replaceChildren(); state.activityCount = 0; if (!state.running) { $('activity-log').classList.add('hidden'); $('activity-empty').classList.remove('hidden'); } });
    $('preview-example').addEventListener('click', openExample); $('reports-example').addEventListener('click', openExample);
    $('report-tab-full').addEventListener('click', () => selectReportTab('full')); $('report-tab-findings').addEventListener('click', () => selectReportTab('findings'));
    $('report-ask').addEventListener('click', () => askAbout({ type: 'report', reportId: state.report.id, label: `${state.report.label} report` }, 'What should I fix first in this report, and why?'));
    $('onboarding-repo').addEventListener('click', chooseRepository);
    $('onboarding-model').addEventListener('click', showSettings);
    $('severity-filter').addEventListener('change', renderFindings); $('disposition-filter').addEventListener('change', renderFindings);
    desktop?.onChooseRepository?.(chooseRepository);
    // Handoffs from the Sources and Runtime views share the same workspace and pipeline.
    document.addEventListener('threatlint:workspace', event => {
      if (state.running) { toast('Stop the current review before changing workspace.', true); return; }
      refreshSessions().then(() => openSession({ id: event.detail.sessionId })).then(() => { showView('workbench'); toast(`${repoName(event.detail.repoPath)} checked out and ready for review.`); }).catch(error => toast(error.message, true));
    });
    document.addEventListener('threatlint:runtime-evidence', event => {
      if (state.running) return;
      setAttachment(event.detail);
      state.pipeline = ['appsec-runtime-reviewer']; state.statuses = {}; state.preset = 'runtime';
      renderPipeline(); renderPresets(); renderAgents(); showView('workbench');
      if (!state.session) toast('Runtime evidence attached. Open the repository that serves this app so the agent can correlate it with source.');
    });
    document.addEventListener('threatlint:navigate', event => showView(event.detail.view));
    document.addEventListener('threatlint:asked', () => { state.asked = true; try { localStorage.setItem('threatlint.asked', '1'); } catch { /* optional */ } publishContext(); });
    document.addEventListener('threatlint:request-context', publishContext);
    window.addEventListener('beforeunload', () => { state.intentionalClose = true; if (state.running && state.ws?.readyState === 1) state.ws.send(JSON.stringify({ action: 'cancel' })); });
    document.addEventListener('keydown', event => { if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'o' && !document.querySelector('dialog[open]')) { event.preventDefault(); void chooseRepository(); } });
  }

  async function initialize() {
    // Retire secret-bearing preferences used by the old UI; do not migrate stored credentials.
    for (const key of ['tl_apikey', 'tl_openai_apikey', 'tl-settings', 'threatlint-settings', 'apiKey', 'openaiApiKey', 'anthropicApiKey', 'tl_api_key', 'tl_openai_key', 'tlApiKey']) localStorage.removeItem(key);
    wireEvents(); renderPresets(); renderPipeline(); renderReports(); updateProviderDisplay();
    if (desktop) { $('runtime-badge').textContent = 'DESKTOP WORKBENCH'; $('app-version').textContent = desktop.version; }
    try {
      [state.agents, state.skills, state.config] = await Promise.all([request('/api/agents'), request('/api/skills'), request('/api/config')]);
      await loadSavedServiceNow();
      const build = state.config.build;
      if (build) {
        const label = build.fingerprint === 'source' ? 'live' : build.commit;
        const builtAt = build.builtAt ? ` · ${build.builtAt}` : '';
        $('app-version').textContent = `${build.version} · ${label}`;
        $('app-version').title = `Build ${build.fingerprint}${builtAt}`;
      }
      $('stat-agents').textContent = state.agents.length; $('agent-nav-count').textContent = state.agents.length;
      $('stat-skills').textContent = state.skills.length; $('skill-nav-count').textContent = state.skills.length;
      for (const category of [...new Set(state.agents.map(agent => agent.category))].sort((a, b) => a.localeCompare(b))) { const option = el('option', '', category); option.value = category; $('agent-category').append(option); }
      renderPipeline(); renderAgents(); renderSkills();
      await refreshSessions();
      const last = localStorage.getItem('threatlint.last-session.v2');
      if (last && state.sessions.some(session => session.id === last)) await openSession({ id: last });
      connectSocket();
    } catch (error) { toast(`Workbench could not initialize: ${error.message}`, true); $('connection-status').textContent = 'Unavailable'; }
    showView(location.hash.slice(1) || 'workbench');
  }
  initialize().catch(error => toast(`Workbench initialization failed: ${error.message}`, true));
})();