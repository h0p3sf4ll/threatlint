/* Repository evidence, explicit review attestations, and offline export/coaching previews. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  if (!$('view-intelligence')) return;
  const state = { session: null, data: null, selected: [], chainRows: [], linkRows: [], coachingRows: [], generation: 0 };
  function node(tag, content, className) {
    const result = document.createElement(tag);
    if (content !== undefined) result.textContent = content;
    if (className) result.className = className;
    return result;
  }
  function button(label, action) {
    const result = node('button', label, 'button secondary small-button'); result.type = 'button';
    result.addEventListener('click', action); return result;
  }
  function field(parent, label, kind = 'input', options = {}) {
    const wrapper = node('label', label), input = node(kind); Object.assign(input, options); input.setAttribute('aria-label', label.trim()); wrapper.append(input); parent.append(wrapper); return input;
  }
  function choices(select, values, placeholder) {
    const before = select.value; select.replaceChildren();
    if (placeholder !== undefined) { const option = node('option', placeholder); option.value = ''; select.append(option); }
    for (const [value, label] of values) { const option = node('option', label); option.value = value; select.append(option); }
    if (values.some(([value]) => value === before)) select.value = before;
  }
  const shortRevision = finding => `${finding.provenance.branch} · ${finding.provenance.commit.slice(0, 12)} · files ${finding.provenance.contentDigest.slice(0, 10)}`;
  const allFindings = () => state.data?.revisionFindings || state.data?.findings || [];
  const selectedFindings = () => state.selected.map(id => allFindings().find(item => item.id === id)).filter(Boolean);
  const evidenceLabel = item => `${item.kind}: ${item.path || item.reference}${item.line ? `:${item.line}` : ''} · ${item.quote.slice(0, 70) || 'reference only'}`;
  async function request(url, body, sessionId = state.session?.id) {
    if (!sessionId) throw new Error('Open a workspace first.');
    const response = await fetch(`/api/intelligence${url}${body === undefined ? `${url.includes('?') ? '&' : '?'}sessionId=${encodeURIComponent(sessionId)}` : ''}`,
      body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...body, sessionId }) });
    const result = await response.json(); if (!response.ok) throw new Error(result.error || 'Evidence request failed'); return result;
  }
  function clear() {
    state.data = null; state.selected = []; state.chainRows = []; state.linkRows = []; state.coachingRows = [];
    for (const id of ['intelligence-summary', 'intelligence-findings', 'intelligence-composites', 'intelligence-trends', 'coaching-findings', 'coaching-result']) $(id).replaceChildren();
    $('repository-progress').replaceChildren(node('p', 'Open a workspace to see its evidence history.', 'subtle'));
    $('intelligence-status').textContent = state.session ? 'Loading workspace evidence…' : 'Open a workspace to load its findings.';
    $('coaching-opt-in').checked = false; $('coaching-status').textContent = ''; $('chain-status').textContent = '';
    for (const id of ['intelligence-branch', 'intelligence-revision', 'intelligence-disposition']) $(id).value = '';
    renderChain();
  }
  async function refresh(sync = false) {
    if (!state.session) { clear(); return; }
    const generation = ++state.generation, sessionId = state.session.id;
    $('intelligence-status').textContent = sync ? 'Importing saved reports and refreshing evidence…' : 'Loading workspace evidence…';
    try {
      const result = await request(sync ? '/sync' : '/overview', sync ? {} : undefined, sessionId);
      if (generation !== state.generation || sessionId !== state.session?.id) return;
      state.data = sync ? result.overview : result;
      state.selected = state.selected.filter(id => allFindings().some(item => item.id === id));
      render();
      $('intelligence-status').textContent = `${state.data.summary.findings} current logical findings across ${state.data.repositories.reduce((sum, repo) => sum + repo.branches.length, 0)} observed branches.${result.errors?.length ? ` ${result.errors.length} saved report(s) need import review: ${result.errors.map(item => item.error).join('; ')}` : ''}`;
    } catch (error) { if (generation === state.generation) $('intelligence-status').textContent = error.message; }
  }
  function renderSummary() {
    const summary = state.data.summary; $('intelligence-summary').replaceChildren();
    for (const [label, value, note] of [['Open findings', summary.open, 'Current logical issues'], ['High / critical', summary.high + summary.critical, 'Reported severity'],
      ['Verified remediated', summary.verifiedRemediated, 'Evidence-backed decisions'], ['Open priority points', summary.openRiskPoints, summary.unknownSeverity ? `${summary.unknownSeverity} unknown severities unscored` : 'Severity rubric · not CVSS']]) {
      const card = node('div', undefined, 'stat-card'), inner = node('div'); inner.append(node('span', String(value), 'stat-value'), node('span', label, 'stat-label'));
      card.append(inner, node('span', note, 'stat-note')); $('intelligence-summary').append(card);
    }
    if (state.data.chainSummary?.current) {
      const chains = state.data.chainSummary, card = node('div', undefined, 'stat-card'), inner = node('div');
      inner.append(node('span', `${chains.maxContextualPriorityPoints}/10`, 'stat-value'), node('span', 'Highest chain priority', 'stat-label'));
      card.append(inner, node('span', `${chains.criticalImpact} critical / ${chains.highImpact} high impact · ${chains.provisional} provisional`, 'stat-note')); $('intelligence-summary').append(card);
    }
    choices($('intelligence-branch'), [...new Set(allFindings().map(item => item.provenance.branch))].map(value => [value, value]), 'All observed branches');
    choices($('intelligence-revision'), [...new Map(allFindings().map(item => [`${item.provenance.commit}|${item.provenance.contentDigest}`, shortRevision(item)])).entries()], 'Latest observation per issue');
  }
  function reviewForm(finding) {
    const details = node('details', undefined, 'platform-advanced'); details.append(node('summary', 'Review evidence and record a decision'));
    details.append(node('p', 'This records your explicit review. It does not run an exploit, validate a quote, or execute a test. Preserve unknowns in the decision rationale.', 'small subtle'));
    const form = node('form', undefined, 'intelligence-form');
    const decision = field(form, 'Decision', 'select'); choices(decision, ['TRUE POSITIVE', 'FALSE POSITIVE', 'REMEDIATED'].map(value => [value, value]));
    const kind = field(form, 'Evidence purpose', 'select'); choices(kind, [['source', 'Source / reachability'], ['impact', 'Observed terminal impact'], ['remediation', 'Verified remediation'], ['introduction', 'Verified introduction (private coaching)']]);
    const file = field(form, 'Evidence path or reference', 'input', { required: true, maxLength: 2000, value: finding.evidence[0]?.path || finding.evidence[0]?.reference || '' });
    const line = field(form, 'Line (when a source location)', 'input', { type: 'number', min: '1', value: finding.evidence[0]?.line || '' });
    const quote = field(form, 'New evidence quote / observed result', 'textarea', { required: true, rows: 3, maxLength: 12000 });
    const method = field(form, 'How you verified this evidence', 'textarea', { required: true, rows: 2, maxLength: 2000, placeholder: 'Name the inspected caller / control, or the actual test and result.' });
    const claim = field(form, 'Decision basis', 'textarea', { required: true, rows: 2, placeholder: 'The specific claim this evidence establishes.' });
    const reason = field(form, 'Decision rationale and limits', 'textarea', { required: true, rows: 2 });
    const safe = field(form, 'Verified safe behavior (required for false positive)', 'textarea', { rows: 2 });
    const refutes = field(form, 'Original decision basis refuted by this new evidence', 'select');
    choices(refutes, finding.reviewHistory.flatMap(event => event.basis.map(basis => [basis.id, `${event.disposition}: ${basis.claim}`])), 'None · required to reopen a closed decision');
    const attest = field(form, ' I independently reviewed this evidence and its relevance to this exact finding.', 'input', { type: 'checkbox', required: true });
    const submit = node('button', 'Record reviewed decision', 'button primary small-button'); submit.type = 'submit';
    const status = node('output', '', 'operations-status'); status.setAttribute('aria-live', 'polite'); form.append(submit, status); details.append(form);
    decision.addEventListener('change', () => { safe.required = decision.value === 'FALSE POSITIVE'; if (decision.value === 'REMEDIATED') kind.value = 'remediation'; });
    form.addEventListener('submit', async event => {
      event.preventDefault(); if (!attest.checked) return; submit.disabled = true;
      const sessionId = state.session?.id;
      try {
        const evidence = { path: file.value, ...(line.value ? { line: Number(line.value) } : {}), quote: quote.value, kind: kind.value,
          verification: 'verified', verificationMethod: method.value, refutes: refutes.value };
        await request(`/findings/${encodeURIComponent(finding.id)}/reviews`, { disposition: decision.value, reason: reason.value,
          newEvidence: [evidence], basis: [{ claim: claim.value, evidenceIds: [0] }], safeBehavior: safe.value }, sessionId);
        if (state.session?.id === sessionId) await refresh();
      } catch (error) { status.textContent = error.message; } finally { submit.disabled = false; }
    }); return details;
  }
  function renderFindings() {
    const revision = $('intelligence-revision').value;
    const findings = (revision ? allFindings() : state.data.findings).filter(item =>
      (!$('intelligence-branch').value || item.provenance.branch === $('intelligence-branch').value) &&
      (!revision || `${item.provenance.commit}|${item.provenance.contentDigest}` === revision) &&
      (!$('intelligence-disposition').value || item.disposition === $('intelligence-disposition').value));
    const container = $('intelligence-findings'); container.replaceChildren();
    if (!findings.length) container.append(node('p', 'No findings match this view. Refresh evidence to import saved reports, or run a security scan.', 'subtle'));
    for (const finding of findings) {
      const card = node('article', undefined, 'platform-finding panel');
      card.append(node('h3', finding.title), node('p', `${finding.severity} · ${finding.disposition} · ${shortRevision(finding)}`, 'small subtle'));
      if (finding.severityConflict) card.append(node('p', `Severity observations disagree: ${finding.observedSeverities.join(', ')}. The highest reported priority is retained.`, 'small subtle'));
      if (finding.reportedDisposition && finding.reportedDisposition !== 'OPEN') card.append(node('p', `Original reported decision: ${finding.reportedDisposition}. Reviewer decisions are recorded separately.`, 'small subtle'));
      const selectLabel = node('label', ' Include in reviewed chain', 'check-row advanced-only'), select = node('input'); select.type = 'checkbox'; select.checked = state.selected.includes(finding.id);
      select.addEventListener('change', () => { state.selected = select.checked ? [...state.selected, finding.id] : state.selected.filter(id => id !== finding.id); renderChain(); }); selectLabel.prepend(select); card.append(selectLabel);
      const evidence = node('details'); evidence.append(node('summary', `${finding.evidence.length} evidence record(s) · ${finding.reviewHistory.length} review decision(s)`));
      for (const item of finding.evidence) { evidence.append(node('p', `${item.verification.toUpperCase()} · ${evidenceLabel(item)}`, 'small')); if (item.quote) evidence.append(node('pre', item.quote)); }
      for (const event of finding.reviewHistory) evidence.append(node('p', `${new Date(event.at).toLocaleString()} · ${event.disposition}: ${event.reason}`, 'small'));
      if (!finding.evidence.length) evidence.append(node('p', 'No evidence location was recorded.', 'subtle'));
      card.append(evidence, reviewForm(finding)); container.append(card);
    }
  }
  function renderChain() {
    const findings = selectedFindings(); $('chain-members').replaceChildren(); $('chain-links').replaceChildren(); state.chainRows = []; state.linkRows = [];
    if (findings.length < 2) $('chain-members').append(node('p', 'Select at least two findings above after reviewing their evidence.', 'subtle'));
    findings.forEach((finding, index) => {
      const section = node('fieldset'); section.append(node('legend', `${index + 1}. ${finding.title}`));
      const role = field(section, 'Role in this path', 'select'); choices(role, [['vulnerability', 'Verified vulnerability'], ['context', 'Context / enabling condition']]);
      if (finding.disposition === 'FALSE POSITIVE') role.value = 'context';
      const rationale = field(section, 'Why this finding matters to the path', 'textarea', { required: true, rows: 2 });
      if (index) section.append(button('Move earlier', () => { [state.selected[index - 1], state.selected[index]] = [state.selected[index], state.selected[index - 1]]; renderChain(); }));
      state.chainRows.push({ findingId: finding.id, role, rationale }); $('chain-members').append(section);
      if (index < findings.length - 1) {
        const next = findings[index + 1], edge = node('fieldset'); edge.append(node('legend', `${index + 1} → ${index + 2}: prerequisite to effect`));
        const rationale = field(edge, 'How does the first effect enable the next step?', 'textarea', { required: true, rows: 2 });
        const evidence = field(edge, 'Verified supporting evidence', 'select', { required: true });
        choices(evidence, [...finding.evidence, ...next.evidence].filter(item => item.verification === 'verified').map(item => [item.id, evidenceLabel(item)]), 'Choose reviewed evidence');
        state.linkRows.push({ prerequisite: finding.id, effect: next.id, rationale, evidence }); $('chain-links').append(edge);
      }
    });
    choices($('chain-impact-evidence'), (findings.at(-1)?.evidence || []).filter(item => item.verification === 'verified' && item.kind === 'impact').map(item => [item.id, evidenceLabel(item)]), 'Choose verified impact evidence on the final finding');
    $('chain-submit').disabled = findings.length < 2;
  }
  async function saveChain(event) {
    event.preventDefault(); $('chain-submit').disabled = true; const sessionId = state.session?.id;
    try {
      await request('/composites', { title: $('chain-title').value,
        contributors: state.chainRows.map(row => ({ findingId: row.findingId, role: row.role.value, rationale: row.rationale.value })),
        links: state.linkRows.map(row => ({ prerequisite: row.prerequisite, effect: row.effect, rationale: row.rationale.value, evidenceIds: [row.evidence.value] })),
        impact: { severity: $('chain-impact-level').value, description: $('chain-impact').value, evidenceIds: [$('chain-impact-evidence').value] },
        complexity: { level: $('chain-complexity').value, rationale: $('chain-complexity-rationale').value }, riskRationale: $('chain-risk-rationale').value,
        coverage: $('chain-coverage').value, uncertainty: $('chain-uncertainty').value.split('\n').map(value => value.trim()).filter(Boolean) }, sessionId);
      if (sessionId === state.session?.id) { await refresh(); $('chain-status').textContent = 'Reviewed chain saved. Original findings and decisions are preserved.'; }
    } catch (error) { $('chain-status').textContent = error.message; } finally { $('chain-submit').disabled = state.selected.length < 2; }
  }
  function download(payload, name) {
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }));
    const link = node('a'); link.href = url; link.download = name; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function renderComposites() {
    const container = $('intelligence-composites'); container.replaceChildren();
    if (!state.data.composites.length) container.append(node('p', 'No reviewed exploit chains yet. Component count alone never creates a composite finding.', 'subtle'));
    for (const composite of state.data.composites) {
      const card = node('article', undefined, 'platform-finding panel');
      card.append(node('h3', composite.title), node('p', `${composite.severity} impact · ${composite.confidence} · ${composite.assessmentStatus}`, 'small subtle'), node('p', composite.impact.description),
        node('p', composite.riskRationale), node('p', `Complexity: ${composite.complexity.level} — ${composite.complexity.rationale}`, 'small'), node('p', `Coverage: ${composite.coverage}`, 'small'));
      if (composite.riskAssessment) card.append(node('p', `${composite.riskAssessment.priority} contextual priority · ${composite.riskAssessment.points}/10${composite.riskAssessment.provisional ? ' · provisional' : ''}`, 'small'),
        node('p', composite.riskAssessment.rationale, 'small'), node('p', composite.riskAssessment.calibration, 'small subtle'));
      const list = node('ol');
      for (const contributor of composite.contributors) list.append(node('li', `${allFindings().find(item => item.id === contributor.findingId)?.title || contributor.findingId}: ${contributor.relevance}; standalone ${contributor.standaloneDisposition}. ${contributor.rationale}`));
      card.append(list, node('p', `Uncertainty: ${composite.uncertainty.join('; ') || 'None recorded by reviewer'}`, 'small subtle'), node('p', composite.scoring, 'small subtle'));
      const status = node('output', '', 'operations-status'); status.setAttribute('aria-live', 'polite');
      const preview = button('Download ServiceNow preview', async () => {
        preview.disabled = true; const sessionId = state.session?.id;
        try { const payload = await request(`/composites/${encodeURIComponent(composite.id)}/servicenow-preview`, {}, sessionId); if (sessionId !== state.session?.id) return; download(payload, `${composite.id}-servicenow-preview.json`); status.textContent = 'Preview downloaded. No ServiceNow records were written.'; }
        catch (error) { status.textContent = error.message; } finally { preview.disabled = false; }
      }); card.append(preview, status); container.append(card);
    }
  }
  function trendTable() {
    const table = node('table', undefined, 'intelligence-table'), caption = node('caption', 'Recorded findings and verified improvement'); table.append(caption);
    const head = node('thead'), row = node('tr'); for (const label of ['Observed', 'Open', 'Priority points', 'Verified fixed', 'Coverage']) { const cell = node('th', label); cell.scope = 'col'; row.append(cell); } head.append(row); table.append(head);
    const body = node('tbody');
    for (const point of (state.data?.trends || []).slice(-30)) { const row = node('tr'); for (const value of [new Date(point.at).toLocaleString(), point.open, point.openRiskPoints, point.verifiedRemediated, point.coverage]) row.append(node('td', String(value))); body.append(row); }
    table.append(body); return table;
  }
  function renderTrends() {
    for (const id of ['intelligence-trends', 'repository-progress']) {
      $(id).replaceChildren();
      if (!state.data.trends.length) $(id).append(node('p', 'No observation history yet. Run a scan or refresh saved reports.', 'subtle'));
      else $(id).append(trendTable());
      for (const repo of state.data.repositories) for (const branch of repo.branches) $(id).append(node('p', `${repo.repo.name} / ${branch.branch}: ${branch.open} unresolved; ${branch.notReobserved} not reobserved in the latest scan. Coverage: ${branch.coverage.status} (${branch.coverage.scope}). ${branch.coverage.limitations.join(' ')}`, 'small subtle'));
    }
  }
  function renderCoaching() {
    const container = $('coaching-findings'); container.replaceChildren(); state.coachingRows = [];
    const eligible = state.data.findings.filter(item => ['TRUE POSITIVE', 'REMEDIATED'].includes(item.disposition) && item.evidence.some(evidence => evidence.kind === 'introduction' && evidence.verification === 'verified'));
    if (!eligible.length) container.append(node('p', 'No eligible introduced issues. In Repository risk, review a finding and add independently verified introduction evidence. A commit author is not sufficient.', 'subtle'));
    for (const finding of eligible) {
      const group = node('fieldset'), include = field(group, ` Include my verified introduced issue: ${finding.title}`, 'input', { type: 'checkbox' });
      const exposure = field(group, 'Observed exposure', 'select'); choices(exposure, [['unknown', 'Unknown'], ['internet', 'Internet'], ['internal', 'Internal'], ['local', 'Local']]);
      const evidence = field(group, 'Evidence for known exposure', 'select'); choices(evidence, finding.evidence.filter(item => item.verification === 'verified').map(item => [item.id, evidenceLabel(item)]), 'Required when exposure is known');
      state.coachingRows.push({ finding, include, exposure, evidence }); container.append(group);
    }
  }
  async function previewCoaching(event) {
    event.preventDefault(); if (!$('coaching-opt-in').checked) return;
    const sessionId = state.session?.id;
    try {
      const result = await request('/developer-risk-preview', { optIn: true, subject: 'My private coaching preview', observedChangeCount: Number($('coaching-sample').value),
        observations: state.coachingRows.filter(row => row.include.checked).map(row => ({ findingId: row.finding.id, introduced: true,
          introductionEvidenceIds: row.finding.evidence.filter(item => item.kind === 'introduction' && item.verification === 'verified').map(item => item.id), exposure: row.exposure.value,
          exposureEvidenceIds: row.evidence.value ? [row.evidence.value] : [] })) }, sessionId);
      if (sessionId !== state.session?.id || !$('coaching-opt-in').checked) return;
      $('coaching-status').textContent = result.score === null ? 'Insufficient verified observations for an index.' : `Private coaching priority: ${result.score}/100 · ${result.confidence} confidence.`;
      $('coaching-result').replaceChildren(node('p', `${result.includedIssues} verified issues / ${result.observedChangeCount} reviewed changes. ${result.excluded.length} records excluded. This preview is not persisted.`, 'small'), node('p', result.formula, 'small subtle'));
      const list = node('ul'); for (const step of result.improvementSteps) list.append(node('li', step)); $('coaching-result').append(list);
      for (const limit of result.limitations) $('coaching-result').append(node('p', limit, 'small subtle'));
    } catch (error) { $('coaching-status').textContent = error.message; }
  }
  function render() { renderSummary(); renderFindings(); renderChain(); renderComposites(); renderTrends(); renderCoaching(); }
  function wire() {
    $('intelligence-refresh').addEventListener('click', () => { void refresh(true); });
    $('repository-progress-refresh').addEventListener('click', () => { void refresh(true); });
    for (const id of ['intelligence-branch', 'intelligence-revision', 'intelligence-disposition']) $(id).addEventListener('change', () => { if (state.data) renderFindings(); });
    $('chain-form').addEventListener('submit', saveChain); $('coaching-form').addEventListener('submit', previewCoaching);
    $('coaching-opt-in').addEventListener('change', () => { if (!$('coaching-opt-in').checked) { $('coaching-result').replaceChildren(); $('coaching-status').textContent = ''; } });
    document.addEventListener('threatlint:context', event => {
      const changed = state.session?.id !== event.detail.session?.id; state.session = event.detail.session;
      if (changed) { state.generation++; clear(); if (state.session && (!$('view-intelligence').hidden || !$('view-metrics').hidden)) void refresh(true); }
    });
    document.addEventListener('threatlint:view', event => { if (['intelligence', 'metrics'].includes(event.detail.view)) void refresh(true); });
    document.addEventListener('threatlint:intelligence-updated', () => { if (state.session && (!$('view-intelligence').hidden || !$('view-metrics').hidden)) void refresh(); });
    document.dispatchEvent(new CustomEvent('threatlint:request-context'));
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire, { once: true }); else wire();
})();
