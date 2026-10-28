'use strict';

/**
 * Sidekick pages: portfolio reporting and bulk operations. Independent of app.js; renders into the
 * #<view>-body containers when a Sidekick view is shown. CSP-safe: DOM nodes and textContent only.
 * Long-running work is a server job polled for progress (cancellable).
 */
(() => {
  const $ = id => document.getElementById(id);
  const Charts = () => window.ThreatlintCharts;
  const state = { loadouts: {}, powered: {}, orgs: [], defaultOrg: '', loaded: {}, findResults: [], avitRows: [], avitTotal: null, runsOffset: 0 };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = String(text);
    return node;
  }
  function button(label, className, action) { const node = el('button', className || 'button secondary', label); node.type = 'button'; node.addEventListener('click', action); return node; }
  function field(label, input) { const wrap = el('label', 'sk-field'); wrap.append(el('span', 'small subtle', label), input); return wrap; }
  function input(type, value = '', attrs = {}) { const node = el('input'); node.type = type; node.value = value; for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v); return node; }
  function select(options, value) { const node = el('select'); for (const [k, v] of options) { const o = el('option', '', v); o.value = k; node.append(o); } if (value != null) node.value = value; return node; }
  function card(...children) { const node = el('div', 'settings-card sk-card'); node.append(...children); return node; }
  function note(text, warn) { return el('p', `field-note small ${warn ? 'fp-status-warn' : 'subtle'}`, text); }
  function toast(message, error) { document.dispatchEvent(new CustomEvent('threatlint:toast', { detail: { message, error } })); if (error) console.warn(message); }
  async function api(url, options = {}) {
    const response = await fetch(url, { cache: 'no-store', ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
    const payload = response.status === 204 ? null : await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload?.error || `Request failed (${response.status})`);
    return payload;
  }
  const post = (url, body) => api(url, { method: 'POST', body: JSON.stringify(body) });
  const fmt = value => (value == null ? '—' : Number(value).toLocaleString());
  function table(headers, rows, cells) {
    const wrap = el('div', 'sk-table-wrap'); const t = el('table', 'sk-table');
    const head = el('tr'); for (const h of headers) head.append(el('th', '', h));
    const thead = el('thead'); thead.append(head); const tbody = el('tbody');
    for (const row of rows) { const tr = el('tr'); for (const value of cells(row)) { const td = el('td'); if (value instanceof Node) td.append(value); else td.textContent = value ?? ''; tr.append(td); } tbody.append(tr); }
    t.append(thead, tbody); wrap.append(t); return wrap;
  }
  function link(href, text) { const a = el('a', '', text || href); a.href = href; a.target = '_blank'; a.rel = 'noopener noreferrer'; return a; }

  /** A job panel: progress bar, log tail, Stop, and a completion callback. */
  async function runJob(container, body, onDone) {
    container.replaceChildren();
    const bar = el('progress', 'sk-progress'); bar.max = 1; bar.value = 0;
    const status = note('Starting…'); const log = el('pre', 'sk-log');
    const stop = button('Stop', 'button secondary', async () => { stop.disabled = true; try { await post(`/api/sidekick/jobs/${id}/cancel`, {}); } catch (e) { toast(e.message, true); } });
    container.append(bar, status, log, stop);
    let id;
    try { ({ jobId: id } = await post('/api/sidekick/jobs', body)); } catch (error) { status.textContent = error.message; status.className = 'field-note small fp-status-warn'; stop.remove(); return; }
    for (;;) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      let job; try { job = await api(`/api/sidekick/jobs/${id}`); } catch (error) { status.textContent = error.message; break; }
      const p = job.progress || {};
      if (p.total) { bar.max = p.total; bar.value = p.current || 0; }
      status.textContent = job.state === 'running' ? (p.total ? `${p.phase ? `${p.phase} · ` : ''}${fmt(p.current)} of ${fmt(p.total)}` : p.triaged != null ? `${fmt(p.triaged)} findings triaged` : 'Working…') : job.state;
      log.textContent = (job.log || []).join('\n');
      if (job.state !== 'running' && job.state !== 'cancelling') {
        stop.remove();
        if (job.state === 'done') { status.textContent = 'Done'; onDone?.(job.result); }
        else { status.textContent = job.error || job.state; status.className = 'field-note small fp-status-warn'; }
        break;
      }
    }
  }

  async function loadLoadouts() {
    const data = await api('/api/sidekick/loadouts');
    state.loadouts = data.loadouts || {}; state.powered = data.powered || {};
    const orgs = await api('/api/sidekick/orgs'); state.orgs = orgs.organizations || []; state.defaultOrg = orgs.default || '';
  }
  function loadoutPicker(value) {
    const options = [...Object.keys(state.loadouts).sort().map(n => [n, n]), ...Object.entries(state.powered).map(([id, p]) => [id, `⚡ ${p.label}`])];
    return select(options.length ? options : [['', 'No loadouts yet']], value);
  }
  function orgPicker(value) { return state.orgs.length ? select(state.orgs.map(o => [o, o]), value || state.defaultOrg) : input('text', value || '', { placeholder: 'organization' }); }
  function setupNote() { return state.orgs.length ? null : note('No Azure DevOps organizations are configured. Add "adoOrganizations": ["org-a", "org-b"] to ~/.threatlint/org.json, or set THREATLINT_ADO_ORGANIZATIONS, and save a PAT for each in Settings → Azure DevOps.', true); }

  // ── Generate vReports ───────────────────────────────────────────────────
  async function renderVReports(body) {
    await loadLoadouts();
    const picker = loadoutPicker(); const stale = input('number', '90', { min: '1', max: '365' }); const result = el('div');
    const go = button('Generate vReport', 'button primary', () => runJob(result, { kind: 'report', loadout: picker.value, staleDays: Number(stale.value) || 90 }, done => {
      result.append(note(`${fmt(done.rows)} repositories · ${fmt(done.failed)} failed.`), button('Download workbook', 'button secondary', () => { window.location.href = `/api/sidekick/runs/${done.runId}/workbook`; }),
        ...(done.failed ? [button('Retry failed', 'button secondary', () => runJob(result, { kind: 'report', loadout: picker.value, onlyFailedFrom: done.runId }))] : []));
    }));
    body.replaceChildren(card(...[setupNote()].filter(Boolean), field('Loadout', picker), field('Stale after (days)', stale), go, result));
  }

  // ── Loadouts ────────────────────────────────────────────────────────────
  async function renderLoadouts(body) {
    await loadLoadouts();
    const list = el('div', 'sk-list');
    for (const [name, entries] of Object.entries(state.loadouts).sort()) {
      const row = el('div', 'sk-row');
      row.append(el('strong', '', name), el('span', 'small subtle', `${entries.length} repositories`),
        button('Edit', 'button secondary small-button', () => edit(name)),
        button('Export', 'button secondary small-button', () => download(`${name}.json`, JSON.stringify({ name, repos: entries }, null, 2), 'application/json')),
        button('Delete', 'button secondary small-button', async () => { if (!confirm(`Delete loadout ${name}?`)) return; await api(`/api/sidekick/loadouts/${encodeURIComponent(name)}`, { method: 'DELETE' }); renderLoadouts(body); }));
      list.append(row);
    }
    for (const [id, p] of Object.entries(state.powered)) {
      const row = el('div', 'sk-row'); const out = el('div');
      row.append(el('strong', '', `⚡ ${p.label}`), el('span', 'small subtle', p.refreshedAt ? `${(p.entries || []).length} repositories · refreshed ${p.refreshedAt.slice(0, 10)}${(p.unresolved || []).length ? ` · ${(p.unresolved || []).length} unresolved` : ''}` : 'not refreshed yet'),
        button('Refresh', 'button secondary small-button', () => runJob(out, { kind: 'powered', id }, () => renderLoadouts(body))), out);
      list.append(row);
    }
    const name = input('text', '', { placeholder: 'Loadout name' }); const org = orgPicker();
    const text = el('textarea', 'sk-textarea'); text.rows = 10; text.placeholder = 'repo, project[, organization]\n# org: another-org\nrepo, project';
    const fileInput = input('file', '', { accept: '.json,application/json' });
    fileInput.addEventListener('change', async () => {
      const file = fileInput.files[0]; if (!file) return;
      try { const data = JSON.parse(await file.text()); const repos = Array.isArray(data) ? data : data.repos || []; if (data.name) name.value = data.name; text.value = repos.map(r => [r.repo || r.repository, r.project, r.organization].filter(Boolean).join(', ')).join('\n'); }
      catch { toast('That file is not a loadout export', true); }
    });
    let editing = '';
    function edit(existing) { editing = existing; name.value = existing; text.value = state.loadouts[existing].map(e => `${e.repo}, ${e.project}, ${e.organization}`).join('\n'); name.focus(); }
    const status = el('div');
    const save = button('Save loadout', 'button primary', async () => {
      try { const r = await post('/api/sidekick/loadouts', { name: name.value, text: text.value, renameFrom: editing || undefined, organization: org.value || undefined });
        status.replaceChildren(note(`Saved ${r.entries} repositories (${r.added} added, ${r.removed} removed).`), ...r.warnings.map(w => note(w, true))); editing = ''; renderLoadouts(body); }
      catch (error) { status.replaceChildren(note(error.message, true)); }
    });
    body.replaceChildren(card(el('h2', '', 'Your loadouts'), list.childElementCount ? list : note('No loadouts yet.')),
      card(el('h2', '', 'Create or edit'), ...[setupNote()].filter(Boolean), field('Name', name), field('Default organization', org), field('Repositories', text), field('Import a loadout export (.json)', fileInput), save, status));
  }
  function download(name, content, type) { const a = el('a'); a.href = URL.createObjectURL(new Blob([content], { type })); a.download = name; document.body.append(a); a.click(); a.remove(); }

  // ── Find projects ───────────────────────────────────────────────────────
  async function renderFind(body) {
    await loadLoadouts();
    const names = el('textarea', 'sk-textarea'); names.rows = 8; names.placeholder = 'One repository name per line';
    const out = el('div'); const results = el('div');
    function show(found) {
      state.findResults = found.results || [];
      const missing = state.findResults.filter(r => r.status === 'missing');
      const target = loadoutPicker(); const newName = input('text', '', { placeholder: 'or a new loadout name' });
      results.replaceChildren(
        note(`${state.findResults.length - missing.length} found · ${missing.length} missing${(found.skipped || []).length ? ` · skipped ${found.skipped.map(s => s.organization).join(', ')}` : ''}`),
        table(['Repository', 'Project', 'Organization', 'Status'], state.findResults, r => [r.repo, r.project || '', r.organization || '', r.status]),
        field('Add the found repositories to', target), newName,
        button('Save to loadout', 'button primary', async () => {
          const destination = newName.value.trim() || target.value; const found = state.findResults.filter(r => r.status === 'found');
          const existing = state.loadouts[destination] || [];
          try { await post('/api/sidekick/loadouts', { name: destination, entries: [...existing, ...found.map(r => ({ repo: r.repo, project: r.project, organization: r.organization }))] }); toast(`Saved to ${destination}`); }
          catch (error) { toast(error.message, true); }
        }),
        ...(missing.length ? [button('Export missing (.csv)', 'button secondary', () => download('missing-repositories.csv', `repository\n${missing.map(r => csv(r.repo)).join('\n')}\n`, 'text/csv'))] : []));
    }
    body.replaceChildren(card(...[setupNote()].filter(Boolean), field('Repositories', names), button('Find', 'button primary', () => runJob(out, { kind: 'find', names: names.value }, show)), out, results));
  }
  function csv(value) { let v = String(value); if (/^[=+\-@\t]/.test(v)) v = `'${v}`; return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v; }

  // ── View vReports ───────────────────────────────────────────────────────
  async function renderReports(body) {
    await loadLoadouts();
    const filter = loadoutPicker(); filter.prepend(Object.assign(el('option', '', 'All loadouts'), { value: '' })); filter.value = '';
    const list = el('div'); const detail = el('div');
    async function refresh() {
      const { runs } = await api(`/api/sidekick/runs?limit=20&offset=${state.runsOffset}${filter.value ? `&loadout=${encodeURIComponent(filter.value)}` : ''}`);
      list.replaceChildren(runs.length ? table(['Date', 'Loadout', 'Repos', 'Critical', 'High', 'Secrets', 'Total', ''], runs, r => [r.created_at.slice(0, 16).replace('T', ' '), r.loadout || 'ad hoc', fmt(r.rows),
        fmt(r.total_critical), fmt(r.total_high), fmt(r.open_secrets), fmt(r.total_vulns), (() => { const w = el('span', 'sk-actions');
          w.append(button('Rows', 'button secondary small-button', () => rows(r.id)), button('Workbook', 'button secondary small-button', () => { window.location.href = `/api/sidekick/runs/${r.id}/workbook`; }),
            button('Delete', 'button secondary small-button', async () => { if (!confirm('Delete this run and its workbook?')) return; await api(`/api/sidekick/runs/${r.id}`, { method: 'DELETE' }); refresh(); })); return w; })()]) : note('No reports yet.'));
    }
    async function rows(id) {
      const repo = input('text', '', { placeholder: 'Filter repository' }); const out = el('div');
      async function load() { const { rows: data } = await api(`/api/sidekick/runs/${id}/rows?repository=${encodeURIComponent(repo.value)}&limit=200`);
        out.replaceChildren(table(['Repository', 'Project', 'Org', 'Status', 'Branches', 'Stale', 'Crit', 'Crit>60d', 'High', 'High>60d', 'Secrets', 'Total', 'Manager', 'Director'], data,
          r => [r.repository, r.project, r.organization, r.status, fmt(r.total_branches), fmt(r.stale_branches), fmt(r.total_critical), fmt(r.critical_over_60d), fmt(r.total_high), fmt(r.high_over_60d), fmt(r.open_secrets), fmt(r.total_vulns), r.repo_manager || '', r.director || ''])); }
      repo.addEventListener('change', load); detail.replaceChildren(card(el('h2', '', 'Rows'), repo, out)); load();
    }
    filter.addEventListener('change', () => { state.runsOffset = 0; refresh(); });
    const file = input('file', '', { accept: '.xlsx' }); const loadout = loadoutPicker(); const date = input('date', new Date().toISOString().slice(0, 10)); const upStatus = el('div');
    const upload = button('Upload report', 'button primary', async () => {
      const f = file.files[0]; if (!f) { toast('Choose an .xlsx file', true); return; }
      const bytes = new Uint8Array(await f.arrayBuffer()); let binary = ''; for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      try { const r = await post('/api/sidekick/import', { content: btoa(binary), loadout: loadout.value, date: date.value }); upStatus.replaceChildren(note(`Imported ${r.rows} rows.`)); refresh(); }
      catch (error) { upStatus.replaceChildren(note(error.message, true)); }
    });
    body.replaceChildren(card(field('Loadout', filter), list), detail, card(el('h2', '', 'Upload a report run by someone else'), field('Workbook', file), field('Loadout', loadout), field('Report date', date), upload, upStatus));
    refresh();
  }

  // ── Branch report ───────────────────────────────────────────────────────
  async function renderBranch(body) {
    await loadLoadouts();
    const org = orgPicker(); const project = input('text', '', { placeholder: 'Project' }); const repo = input('text', '', { placeholder: 'Repository' });
    const stale = input('number', '90', { min: '1', max: '365' }); const out = el('div');
    const go = button('Run branch report', 'button primary', async () => {
      out.replaceChildren(note('Working…'));
      try { const r = await post('/api/sidekick/branches', { organization: org.value, project: project.value, repository: repo.value, staleDays: Number(stale.value) || 90 });
        out.replaceChildren(note(`${r.stale} of ${r.total} branches are stale.`), table(['Branch', 'Last commit', 'Committer', 'Days stale'], r.rows, b => [b.branch, b.last_commit_date.slice(0, 10), b.last_committer, fmt(b.days_stale)])); }
      catch (error) { out.replaceChildren(note(error.message, true)); }
    });
    body.replaceChildren(card(...[setupNote()].filter(Boolean), field('Organization', org), field('Project', project), field('Repository', repo), field('Stale after (days)', stale), go, out));
  }

  // ── Trends ──────────────────────────────────────────────────────────────
  const MEASURE_LABELS = { totalVulns: 'Open vulnerabilities', totalCritical: 'Critical', totalHigh: 'High', criticalOver60d: 'Critical over 60 days', highOver60d: 'High over 60 days', totalOver60d: 'Over 60 days', openSecrets: 'Open secrets', staleBranches: 'Stale branches', repositories: 'Repositories' };
  async function renderTrends(body) {
    await loadLoadouts();
    const picker = loadoutPicker(); const months = select([['6', '6 months'], ['12', '12 months'], ['0', 'All history']], '12');
    const measure = select(Object.entries(MEASURE_LABELS), 'totalVulns'); const out = el('div', 'sk-trends');
    async function load() {
      out.replaceChildren(note('Loading…'));
      let t; try { t = await api(`/api/sidekick/trends?loadout=${encodeURIComponent(picker.value)}&months=${months.value}`); } catch (error) { out.replaceChildren(note(error.message, true)); return; }
      const h = t.headline; const tone = h.posture === 'Improving' ? 'good' : h.posture === 'Worsening' ? 'bad' : '';
      const headline = el('div', `sk-headline ${tone}`);
      headline.append(el('strong', '', `${h.posture}: open vulnerabilities ${h.delta <= 0 ? '▼' : '▲'} ${fmt(Math.abs(h.delta))}${h.percent == null ? '' : ` (${h.percent > 0 ? '+' : ''}${h.percent}%)`}`),
        el('span', 'small subtle', `${t.baseline.created_at.slice(0, 10)} → ${t.current.created_at.slice(0, 10)}${t.likeForLike ? ' · like-for-like over the repositories in both runs' : ''}`));
      const chart = el('div', 'sk-chart');
      Charts()?.render(chart, 'line', { rows: t.series.map(p => ({ key: p.date, label: p.date, value: p[measure.value] })) }, { metric: measure.value });
      const scope = t.likeForLike ? note(`Of the raw change of ${fmt(t.attribution.raw)}, ${fmt(t.attribution.fromScope)} came from repositories joining or leaving the loadout and ${fmt(t.attribution.fromExisting)} from the repositories in both runs.`) : null;
      out.replaceChildren(headline, ...[scope].filter(Boolean), chart, el('h2', '', 'Notable changes by repository'),
        t.movers.length ? table(['Repository', 'Measure', 'Before', 'After', 'Change'], t.movers, m => [m.repository, m.metric, fmt(m.before), fmt(m.after), `${m.delta > 0 ? '+' : ''}${m.delta}`]) : note('No repository changed.'),
        button('Export PDF', 'button secondary', () => exportPdf(picker.value)));
    }
    for (const control of [picker, months, measure]) control.addEventListener('change', load);
    body.replaceChildren(card(field('Loadout', picker), field('Window', months), field('Measure', measure)), out); load();
  }
  function exportPdf(loadout) {
    document.body.classList.add('sk-printing');
    const done = () => { document.body.classList.remove('sk-printing'); window.removeEventListener('afterprint', done); };
    window.addEventListener('afterprint', done);
    document.title = `executive-summary-${loadout}-${new Date().toISOString().slice(0, 10)}`;
    window.print();
  }

  // ── Ownership hub ───────────────────────────────────────────────────────
  async function renderOwnership(body) {
    await loadLoadouts();
    const email = input('email', '', { placeholder: 'name@your-domain' }); const repo = input('text', '', { placeholder: 'Repository' });
    const project = input('text', '', { placeholder: 'Project' }); const org = orgPicker(); const out = el('div');
    function show(r) {
      out.replaceChildren(note(`${r.cached ? 'From cache · ' : ''}Committer ${r.committerEmail || 'unknown'} · Manager ${r.repoManager || '—'} · Director ${r.director || '—'}`),
        table(['Name', 'Title', 'Email', 'Role'], r.chain || [], p => [p.name, p.title, p.email, p.role || '']));
    }
    const byEmail = button('Look up by email', 'button primary', async () => { try { show(await api(`/api/sidekick/owner?email=${encodeURIComponent(email.value)}`)); } catch (e) { out.replaceChildren(note(e.message, true)); } });
    const byRepo = button('Look up by repository', 'button primary', async () => { try { show(await api(`/api/sidekick/owner?repository=${encodeURIComponent(repo.value)}&project=${encodeURIComponent(project.value)}&organization=${encodeURIComponent(org.value)}`)); } catch (e) { out.replaceChildren(note(e.message, true)); } });
    const clear = button('Clear cache', 'button secondary', async () => { const r = await post('/api/sidekick/owner-cache/clear', {}); toast(`Cleared ${r.cleared} cached lookups`); });
    body.replaceChildren(card(field('Email', email), byEmail), card(field('Organization', org), field('Project', project), field('Repository', repo), byRepo), out, clear);
  }

  // ── AVIT closure ────────────────────────────────────────────────────────
  const FIELDS = [['state', 'State'], ['active', 'Active'], ['number', 'Number'], ['u_repository', 'Repository'], ['project_name', 'Project'], ['project_branch', 'Branch'],
    ['vulnerability', 'Vulnerability'], ['u_security_finding_source', 'Finding type'], ['risk_rating', 'Risk rating']];
  const OPERATORS = [['=', 'is'], ['!=', 'is not'], ['LIKE', 'contains'], ['NOT LIKE', 'does not contain'], ['STARTSWITH', 'starts with'], ['ENDSWITH', 'ends with'], ['ISEMPTY', 'is empty'], ['ISNOTEMPTY', 'is not empty']];
  async function renderAvit(body) {
    const rows = el('div', 'sk-conditions'); const results = el('div'); const job = el('div');
    function addCondition(c = {}) {
      const line = el('div', 'sk-condition'); const join = select([['AND', 'and'], ['OR', 'or']], c.join || 'AND');
      const f = select(FIELDS, c.field || 'state'); const op = select(OPERATORS, c.operator || '='); const v = input('text', c.value || '');
      line.append(join, f, op, v, button('✕', 'icon-button', () => line.remove())); line.read = () => ({ join: join.value, field: f.value, operator: op.value, value: v.value }); rows.append(line);
    }
    const conditions = () => [...rows.children].map(line => line.read());
    addCondition({ field: 'active', value: 'true' }); addCondition({ field: 'state', value: '1' });
    const reason = el('textarea', 'sk-textarea'); reason.rows = 2; reason.placeholder = 'Reason (written to each AVIT as a work note)';
    async function search() {
      try { const r = await post('/api/sidekick/avit/search', { conditions: conditions(), limit: 100 }); state.avitRows = r.rows; state.avitTotal = r.total;
        results.replaceChildren(note(`${r.total == null ? r.rows.length : fmt(r.total)} AVITs match.`), table(['', 'Number', 'Repository', 'Project', 'Vulnerability', 'Type', 'Risk', 'State'], r.rows, a => {
          const box = input('checkbox'); box.dataset.sysId = a.sys_id; box.dataset.state = a.state; box.dataset.active = a.active; return [box, a.number, a.u_repository, a.project_name, a.vulnerability, a.u_security_finding_source, a.risk_rating, a.state]; })); }
      catch (error) { results.replaceChildren(note(error.message, true)); }
    }
    const closeSelected = button('Close selected', 'button secondary', () => {
      const records = [...results.querySelectorAll('input[type=checkbox]:checked')].map(b => ({ sysId: b.dataset.sysId, state: b.dataset.state, active: b.dataset.active }));
      if (!records.length) { toast('Select AVITs first', true); return; }
      if (!reason.value.trim() || !confirm(`Close ${records.length} AVITs?`)) return;
      runJob(job, { kind: 'avit-close', reason: reason.value, records }, r => job.append(note(`${r.closed} closed, ${r.failed} failed. Reverse it from Actions history if needed.`)));
    });
    const closeAll = button('Close all matching', 'button primary', () => {
      if (!reason.value.trim()) { toast('A reason is required', true); return; }
      if (!confirm(`Close every AVIT matching these conditions${state.avitTotal != null ? ` (${state.avitTotal})` : ''}?`)) return;
      runJob(job, { kind: 'avit-close', reason: reason.value, conditions: conditions() }, r => job.append(note(`${r.closed} closed, ${r.failed} failed. Reverse it from Actions history if needed.`)));
    });
    body.replaceChildren(card(rows, button('Add condition', 'button secondary', () => addCondition()), button('Search', 'button primary', search)), results, card(field('Reason', reason), closeSelected, closeAll, job));
  }

  // ── Bulk triage ─────────────────────────────────────────────────────────
  async function renderTriage(body) {
    const project = input('text', '', { placeholder: 'Semgrep project, e.g. Project/repository' }); const mode = select([['sast', 'SAST rule'], ['secrets', 'Secret type']], 'sast');
    const rule = input('text', '', { placeholder: 'Rule ID or secret type' }); const noteText = input('text', '', { placeholder: 'Triage note' });
    const workers = input('number', '4', { min: '1', max: '16' }); const out = el('div');
    const go = button('Triage all matching findings', 'button primary', () => {
      if (!confirm(`Ignore every open ${mode.value === 'sast' ? 'finding of rule' : 'secret of type'} ${rule.value} in ${project.value} as a false positive?`)) return;
      runJob(out, { kind: 'triage', project: project.value, mode: mode.value, rule: rule.value, secretType: rule.value, note: noteText.value, workers: Number(workers.value) || 4 },
        r => out.append(note(`${fmt(r.triaged)} findings triaged from ${fmt(r.seeds)} seeds${r.complete ? '; none remain' : ''}.`)));
    });
    body.replaceChildren(card(note('Each call triages one finding, which Semgrep expands to its whole fingerprint cluster; workers repeat until nothing is left.'),
      field('Project', project), field('Match', mode), field('Rule / secret type', rule), field('Note', noteText), field('Workers', workers), go, out));
  }

  // ── Actions history ─────────────────────────────────────────────────────
  async function renderActions(body) {
    const out = el('div'); const days = select([['30', '30 days'], ['90', '90 days'], ['180', '180 days'], ['365', '365 days']], '90');
    async function load() {
      const { actions, stats } = await api('/api/sidekick/actions?limit=300');
      out.replaceChildren(note(`${fmt(stats.runs)} actions${stats.oldest ? ` since ${stats.oldest.slice(0, 10)}` : ''}.`), table(['When', 'Action', 'Reason', 'Succeeded', 'Failed', ''], actions, a => [a.created_at.slice(0, 16).replace('T', ' '),
        a.kind.replace(/_/g, ' '), a.reason || '', fmt(a.succeeded), fmt(a.failed), a.reversible ? button('Reverse', 'button secondary small-button', () => reverse(a)) : a.reversed_by ? 'reversed' : '']));
    }
    function reverse(action) {
      const reason = prompt(`Reopen the ${action.succeeded} AVITs this closure closed. Reason:`);
      if (!reason) return;
      const panel = el('div'); out.prepend(panel);
      runJob(panel, { kind: 'avit-reverse', actionId: action.id, reason }, r => { panel.append(note(`${r.reopened} reopened, ${r.failed} failed.`)); load(); });
    }
    const purge = button('Delete older entries', 'button secondary', async () => {
      if (!confirm(`Delete history older than ${days.value} days? Closures that can still be reversed are kept.`)) return;
      const r = await post('/api/sidekick/actions/purge', { days: Number(days.value) }); toast(`Removed ${r.removed} entries`); load();
    });
    body.replaceChildren(card(field('Keep', days), purge), out); load();
  }

  const RENDER = { 'sk-vreports': renderVReports, 'sk-loadouts': renderLoadouts, 'sk-find': renderFind, 'sk-reports': renderReports, 'sk-branch': renderBranch,
    'sk-trends': renderTrends, 'sk-ownership': renderOwnership, 'sk-avit': renderAvit, 'sk-triage': renderTriage, 'sk-actions': renderActions };
  document.addEventListener('threatlint:view', event => {
    const render = RENDER[event.detail.view]; const body = $(`${event.detail.view}-body`);
    if (render && body) render(body).catch(error => body.replaceChildren(note(error.message, true)));
  });
})();
