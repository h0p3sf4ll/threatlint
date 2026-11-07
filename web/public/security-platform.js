'use strict';

/** Scanner UI: server-owned proposals, explicit mutation, then visible rescan evidence. */
(() => {
  const $ = id => document.getElementById(id);
  const state = { session: null, scan: null, busy: false, reviewRunning: false, generation: 0, activeScan: null, cancelling: false };
  const rank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, UNSPECIFIED: 5 };
  const autoRules = ['TL-DEBUG-ENABLED', 'TL-PY-YAML', 'TL-TLS-VERIFY-OFF'];
  function node(tag, text, className) {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    return element;
  }
  async function request(url, body) {
    const response = await fetch(url, body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'The request could not be completed.');
    return result;
  }
  function status(message, error = false) { $('security-status').textContent = message; $('security-status').classList.toggle('error', error); }
  function controls() {
    $('security-scan-start').disabled = !state.session || state.busy || state.reviewRunning;
    $('security-scan-options').disabled = state.busy;
    $('security-scan-start').textContent = state.busy ? 'Working…' : 'Scan my code →';
    $('security-scan-cancel').hidden = !state.activeScan;
    $('security-scan-cancel').disabled = !state.activeScan || state.cancelling;
    for (const button of $('security-findings').querySelectorAll('button')) button.disabled = state.busy || state.reviewRunning;
  }
  function button(label, action) {
    const element = node('button', label, 'button secondary small-button'); element.type = 'button'; element.addEventListener('click', action); return element;
  }
  function detail(label, content) {
    const block = node('div', undefined, 'platform-detail'); block.append(node('strong', label), node('p', content || 'Not supplied by this engine.')); return block;
  }
  function notifyEvidence() { document.dispatchEvent(new CustomEvent('threatlint:intelligence-updated')); }
  function render(scan) {
    state.scan = scan;
    const coverage = $('security-coverage'); coverage.replaceChildren();
    for (const engine of scan.engines || []) {
      const card = node('div', undefined, 'platform-coverage-card');
      card.append(node('strong', `${engine.id} · ${engine.status}`), node('p', engine.detail, 'small subtle'));
      if (engine.provenance) {
        card.append(node('p', `Engine ${engine.provenance.engineVersion || 'unrecorded'} · rules: ${engine.provenance.rulePack?.source || 'unrecorded'} · immutable rule revision ${engine.provenance.rulePack?.revision || 'unrecorded'}`, 'micro subtle'));
        for (const [database, metadata] of Object.entries(engine.provenance.databases || {})) card.append(node('p', `${database} · updated ${metadata.updatedAt || 'unrecorded'} · downloaded ${metadata.downloadedAt || 'unrecorded'}`, 'micro subtle'));
      }
      coverage.append(card);
    }
    const limits = node('details', undefined, 'platform-coverage-limits');
    limits.append(node('summary', `Coverage: ${scan.coverage?.status || 'unknown'} · ${scan.coverage?.files ?? 'unknown'} files`));
    for (const limitation of scan.coverage?.limitations || []) limits.append(node('p', limitation, 'small subtle'));
    if (scan.binding) limits.append(node('p', `${scan.binding.branch || 'Unknown branch'} · ${scan.binding.commit || 'Unknown revision'} · snapshot ${scan.binding.contentDigest || 'not recorded'}`, 'micro subtle'));
    if (scan.policy?.localApplySupported === false) limits.append(node('p', scan.policy.localApplyReason, 'small subtle'));
    coverage.append(limits);
    const findings = $('security-findings'); findings.replaceChildren();
    const sorted = [...(scan.findings || [])].sort((a, b) => (rank[a.severity] ?? 5) - (rank[b.severity] ?? 5));
    if (!sorted.length) findings.append(node('p', 'No findings in the checks that ran. Review coverage before drawing conclusions.', 'subtle'));
    for (const finding of sorted) {
      const article = node('article', undefined, 'platform-finding'); article.dataset.findingId = finding.id;
      const heading = node('div', undefined, 'platform-finding-heading');
      const badge = node('span', finding.severity, 'platform-severity'); badge.dataset.severity = finding.severity;
      heading.append(badge, node('h3', finding.title)); article.append(heading);
      article.append(node('p', `${finding.path}:${finding.line} · ${finding.engine || finding.source || 'baseline'} · ${finding.category || 'analysis'}`, 'micro subtle'));
      article.append(detail('Impact', finding.impact));
      const code = node('pre'); code.append(node('code', finding.snippet || 'No code excerpt supplied.')); article.append(code);
      article.append(detail('Suggested fix', finding.recommendation));
      const proposal = node('div', undefined, 'platform-fix-proposal');
      if (finding.fixAvailable) article.append(button('Review suggested change', () => showProposal(finding, proposal)));
      else article.append(node('p', 'Advisory fix · review and change this code in your editor, then scan again.', 'small subtle'));
      article.append(proposal); findings.append(article);
    }
    controls();
  }
  async function showProposal(finding, container) {
    const generation = state.generation;
    state.busy = true; controls();
    try {
      const plan = await request(`/api/security-scanner/scans/${encodeURIComponent(state.scan.id)}/fixes`, { findingId: finding.id });
      if (generation !== state.generation) return;
      container.replaceChildren(node('p', plan.description, 'small'));
      const before = node('pre', undefined, 'platform-diff-before'); before.append(node('code', `− ${plan.before}`));
      const after = node('pre', undefined, 'platform-diff-after'); after.append(node('code', `+ ${plan.after}`));
      container.append(before, after);
      if (plan.canApply === false) container.append(node('p', plan.applyUnavailableReason, 'small subtle'));
      else container.append(node('p', 'This changes the selected workspace. The server verifies the original snapshot and rescans. Application tests remain your responsibility.', 'small subtle'),
        button('Apply this change & rescan', () => { void applyPlan(plan, generation).catch(() => {}); }));
    } catch (error) { if (generation === state.generation) status(error.message, true); }
    finally { if (generation === state.generation) { state.busy = false; controls(); } }
  }
  async function applyPlan(plan, generation, automatic = false) {
    if (generation !== state.generation) return;
    state.busy = true; controls(); status('Checking the snapshot, applying the supported change and rescanning…');
    try {
      const result = await request(`/api/security-scanner/fixes/${encodeURIComponent(plan.id)}/apply`, automatic
        ? { policy: { autoApply: true, rules: autoRules } } : { confirm: true });
      if (generation !== state.generation) return;
      render(result.scan); notifyEvidence();
      status('Change applied and rescanned. Syntax validation passed; application tests have not run. Review the result before committing.');
      await loadHistory(generation);
      return result.scan;
    } catch (error) { if (generation === state.generation) status(error.message, true); throw error; }
    finally { if (generation === state.generation) { state.busy = false; controls(); } }
  }
  async function loadHistory(generation = state.generation) {
    if (!state.session) return;
    const scans = await request(`/api/security-scanner/scans?sessionId=${encodeURIComponent(state.session.id)}`);
    if (generation !== state.generation) return;
    $('security-history').replaceChildren();
    for (const scan of scans) $('security-history').append(button(`${new Date(scan.startedAt).toLocaleString()} · ${scan.status} · ${scan.findings?.length || 0} findings`, () => {
      if (!state.busy) { render(scan); status(`Previous scan · ${scan.status}. This result describes its recorded snapshot.`); }
    }));
  }
  async function poll(id, generation) {
    while (generation === state.generation) {
      const scan = await request(`/api/security-scanner/scans/${encodeURIComponent(id)}`);
      if (scan.status !== 'running') return scan;
      await new Promise(resolve => setTimeout(resolve, 750));
    }
    return null;
  }
  $('security-scan-form').addEventListener('submit', async event => {
    event.preventDefault(); if (!state.session || state.busy) return;
    const generation = state.generation;
    const automatic = $('experience-mode').value === 'advanced' && $('security-auto-fix').checked;
    $('security-auto-fix').checked = false;
    state.busy = true; controls(); status('Scanning the selected workspace. Coverage and engine status will appear with the results…');
    try {
      const engines = ['semgrep', 'trivy'].filter(id => $(`security-${id}`).checked);
      const started = await request('/api/security-scanner/scans', { sessionId: state.session.id, engines });
      if (generation !== state.generation) return;
      state.activeScan = started.id; controls();
      let scan = await poll(started.id, generation);
      if (!scan || generation !== state.generation) return;
      state.activeScan = null; state.cancelling = false; controls();
      if (['failed', 'cancelled'].includes(scan.status)) throw new Error(scan.error || `Scan ${scan.status}. No clean result is claimed.`);
      render(scan); notifyEvidence();
      status(`Scan finished · ${scan.findings.length} findings · ${scan.coverage?.status || 'unknown'} coverage. Start with the highest severity and check its evidence.`);
      if (automatic && scan.policy?.localApplySupported === false) status(scan.policy.localApplyReason);
      if (automatic && scan.policy?.localApplySupported !== false) {
        let count = 0;
        while (count < 12 && generation === state.generation) {
          const eligible = scan.findings.find(item => item.fixAvailable && autoRules.includes(item.ruleId));
          if (!eligible) break;
          const plan = await request(`/api/security-scanner/scans/${encodeURIComponent(scan.id)}/fixes`, { findingId: eligible.id });
          const rescanned = await applyPlan(plan, generation, true);
          if (generation !== state.generation || !rescanned) return;
          scan = rescanned; count++;
          state.busy = true; controls();
        }
        if (generation === state.generation) status(count ? `${count} supported source change(s) applied and rescanned. Application tests have not run; review before committing.${count === 12 ? ' The 12-change limit was reached.' : ''}` : 'Scan finished. No changes qualified for the automatic fix policy.');
      }
      await loadHistory(generation);
    } catch (error) { if (generation === state.generation) status(error.message, true); }
    finally { if (generation === state.generation) { state.busy = false; state.activeScan = null; state.cancelling = false; controls(); } }
  });
  $('security-scan-cancel').addEventListener('click', async () => {
    const id = state.activeScan, generation = state.generation;
    if (!id || state.cancelling) return;
    state.cancelling = true; controls(); status('Cancellation requested. Waiting for scanner processes to stop…');
    try { await request(`/api/security-scanner/scans/${encodeURIComponent(id)}/cancel`, {}); }
    catch (error) { if (generation === state.generation) { state.cancelling = false; controls(); status(error.message, true); } }
  });
  document.addEventListener('threatlint:context', event => {
    state.reviewRunning = !!event.detail.running;
    if (event.detail.session?.id !== state.session?.id) {
      state.generation++; state.session = event.detail.session; state.scan = null; state.busy = false; state.activeScan = null; state.cancelling = false;
      $('security-auto-fix').checked = false;
      $('security-findings').replaceChildren(node('p', 'Run a scan to see findings for this workspace.', 'subtle'));
      $('security-coverage').replaceChildren(); $('security-history').replaceChildren();
      status('No scan selected in this workspace.');
      $('security-source').textContent = state.session ? `${state.session.repoPath}${state.session.provenance?.branch ? ` · ${state.session.provenance.branch}` : ''}` : 'Open a local repository or connect a branch.';
      const generation = state.generation;
      if (state.session) void loadHistory(generation).catch(error => { if (generation === state.generation) status(error.message, true); });
    }
    controls();
  });
  document.addEventListener('threatlint:view', event => {
    const generation = state.generation;
    if (event.detail.view === 'security' && state.session) void loadHistory(generation).catch(error => { if (generation === state.generation) status(error.message, true); });
  });
  document.dispatchEvent(new CustomEvent('threatlint:request-context'));
})();
