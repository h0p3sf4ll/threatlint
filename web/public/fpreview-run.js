/**
 * False positive review: run status, progress, and per-item history.
 *
 * Every runner event (avit_batch_start, sctask_item, avit_item, avit_batch_complete, avit_batch_error) is applied
 * to the cards and appended to two chronological logs: one per AVIT / SCTASK card and one for the whole run.
 * Entries are only ever appended; the current stage stays at the top of each card. All values are set as text.
 *
 * Reloads and reconnects: the server keeps no run state. A batch belongs to the WebSocket that started it and is
 * cancelled when that connection closes. So the history is kept for this browser session only (sessionStorage):
 * a reload shows the run exactly as far as it got, marked interrupted when it had not finished.
 */
(() => {
  'use strict';
  const STORE_KEY = 'threatlint.fpreview.run.v1';
  const MAX_STORED = 4000;
  const MAX_LOG = 3000;
  const AVIT_STAGES = { queued: 'Queued', fetching: 'Fetching', checkout: 'Cloning', triage: 'Reviewing', reported: 'Report saved', resolving: 'Updating ServiceNow',
    done: 'Done', error: 'Error', 'out-of-scope': 'Out of scope', cancelled: 'Cancelled', skipped: 'Skipped' };
  const TASK_STAGES = { queued: 'Queued', expanding: 'Reading task', reviewing: 'Reviewing its AVITs', resolving: 'Updating the task', done: 'Done', error: 'Error', cancelled: 'Cancelled' };
  const ACTIONS = { attached: 'Attached', closed: 'Closed', noted: 'Note added', 'semgrep-ignored': 'Semgrep ignored', tuned: 'Rule tuned', semgrep: 'Semgrep', warning: 'Warning' };
  const RESULTS = ['closed', 'noted', 'error', 'skipped'];
  const RUN_STATUS = { expanding: 'Reading SCTASKs', running: 'Reviewing', complete: 'Complete', cancelled: 'Stopped', error: 'Did not start', interrupted: 'Interrupted' };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = String(text);
    return node;
  }
  const clock = at => { const date = new Date(at); return Number.isNaN(date.getTime()) ? '' : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); };
  const plural = (count, word) => `${count} ${word}${count === 1 ? '' : 's'}`;
  /** The bucket for a final event when an older runner sent no `result`. */
  function resultOf(event) {
    if (event.result && RESULTS.includes(event.result)) return event.result;
    if (event.stage === 'error') return 'error';
    if (['out-of-scope', 'cancelled', 'skipped'].includes(event.stage)) return 'skipped';
    return event.disposition === 'REPO REMOVED' || event.outcome?.closed === true ? 'closed' : 'noted';
  }

  function create(root) {
    let run, persist = true, saveTimer = null, stored = [];

    // ── Layout ──
    const section = el('section', 'fp-run hidden'); section.id = 'fpreview-run'; section.setAttribute('aria-labelledby', 'fpreview-run-title');
    const header = el('header', 'fp-run-header');
    const spinner = el('span', 'fp-spinner'); spinner.setAttribute('aria-hidden', 'true');
    const title = el('h2', '', 'Review run'); title.id = 'fpreview-run-title';
    const status = el('span', 'avit-stage'); status.id = 'fpreview-run-status';
    const started = el('time', 'fp-run-time small subtle');
    header.append(spinner, title, status, started);
    const bar = el('div', 'fp-progress'); bar.id = 'fpreview-progress'; bar.setAttribute('role', 'progressbar'); bar.setAttribute('aria-label', 'AVITs reviewed'); bar.setAttribute('aria-valuemin', '0');
    const segments = Object.fromEntries(RESULTS.map(result => { const segment = el('span', `fp-progress-seg seg-${result}`); bar.append(segment); return [result, segment]; }));
    const counts = el('p', 'fp-run-counts'); counts.id = 'fpreview-counts'; counts.setAttribute('aria-live', 'polite');
    const tasksLine = el('p', 'fp-run-tasks small subtle'); tasksLine.id = 'fpreview-task-counts';
    const note = el('p', 'fp-run-note small'); note.id = 'fpreview-run-note';
    const logBox = el('details', 'fp-history fp-run-log'); logBox.open = true;
    const logSummary = el('summary', '', 'Activity log');
    const log = el('ol', 'fp-history-list'); log.id = 'fpreview-run-log';
    logBox.append(logSummary, log);
    section.append(header, bar, counts, tasksLine, note, logBox);
    const tasks = el('div', 'fpreview-cards fp-task-cards'); tasks.id = 'fpreview-tasks';
    const avits = el('div', 'fpreview-cards fp-avit-cards'); avits.id = 'fpreview-avit-cards';
    root.replaceChildren(section, tasks, avits);
    const userToggled = details => details.querySelector('summary').addEventListener('click', () => { details.dataset.userToggled = '1'; });
    userToggled(logBox);

    function reset() {
      run = { status: 'idle', total: 0, avits: new Map(), tasks: new Map(), avitTasks: new Map(), events: 0, startedAt: null, truncated: null, error: '' };
      tasks.replaceChildren(); avits.replaceChildren(); log.replaceChildren(); note.textContent = ''; logBox.open = true; delete logBox.dataset.userToggled;
      section.classList.add('hidden');
    }

    // ── History entries ──
    function entry(list, at, label, detail, kind = '') {
      const item = el('li', `fp-history-entry ${kind}`.trim());
      const time = el('time', 'fp-history-time', clock(at)); time.dateTime = at;
      item.append(time, el('span', 'fp-history-stage', label), el('span', 'fp-history-detail', detail || ''));
      list.append(item);
      return item;
    }
    function runLog(at, subject, label, detail, kind) {
      const follow = log.scrollHeight - log.scrollTop - log.clientHeight < 60;
      const item = entry(log, at, label, detail, kind);
      item.prepend(el('span', 'fp-history-subject', subject || 'Run'));
      if (log.children.length > MAX_LOG) { log.firstElementChild.remove(); log.dataset.trimmed = '1'; }
      run.events++;
      logSummary.textContent = `Activity log · ${plural(run.events, 'event')}${log.dataset.trimmed ? ' (oldest hidden)' : ''}`;
      if (follow) log.scrollTop = log.scrollHeight;
      return item;
    }
    /**
     * Consecutive model tool calls on one AVIT are counted in one entry (with the time of the first and the
     * name of the latest tool) so a long investigation does not bury the stage changes around it.
     */
    function toolEntry(list, card, at, tool, count) {
      const last = list.lastElementChild;
      const total = (last?.dataset.tools ? Number(last.dataset.tools) : 0) + count;
      const detail = `Inspecting the repository · ${plural(total, 'tool call')} (latest: ${tool})`;
      if (last?.dataset.tools) { last.dataset.tools = String(total); last.querySelector('.fp-history-detail').textContent = detail; return { item: last, detail, fresh: false }; }
      const item = entry(list, at, 'Reviewing', detail, 'tool'); item.dataset.tools = String(total);
      card?.querySelector('.fp-history summary')?.replaceChildren(document.createTextNode(`History · ${plural(list.children.length, 'event')}`));
      return { item, detail, fresh: true };
    }

    // ── Cards ──
    function card(kind, id) {
      const map = kind === 'avit' ? run.avits : run.tasks;
      if (map.has(id)) return map.get(id);
      const node = el('article', kind === 'avit' ? 'avit-card' : 'avit-card sctask-card'); node.id = `${kind}-${id}`;
      const head = el('header');
      const spin = el('span', 'fp-spinner'); spin.setAttribute('aria-hidden', 'true');
      head.append(spin, el('span', 'avit-id', id), el('span', 'avit-stage stage-queued', 'Queued'));
      if (kind === 'avit') head.append(el('span', 'avit-disposition'));
      head.append(el('time', 'avit-updated small subtle'));
      const history = el('details', 'fp-history'); history.open = true;
      history.append(el('summary', '', 'History'), el('ol', 'fp-history-list'));
      userToggled(history);
      node.append(head, el('div', 'avit-detail'));
      if (kind === 'avit') node.append(el('ul', 'avit-outcome'), el('div', 'avit-tasks small subtle'));
      else node.append(el('div', 'fp-task-progress small subtle'), el('ul', 'fp-task-avits'));
      node.append(history);
      (kind === 'avit' ? avits : tasks).append(node);
      const item = { node, stage: 'queued', result: null, active: false, tools: 0 };
      map.set(id, item);
      return item;
    }
    function addHistory(item, at, label, detail, kind) {
      const list = item.node.querySelector('.fp-history-list');
      entry(list, at, label, detail, kind);
      item.node.querySelector('.fp-history summary').textContent = `History · ${plural(list.children.length, 'event')}`;
    }
    function setStage(item, stageKey, labels, at) {
      const stage = item.node.querySelector('.avit-stage');
      if (labels[stageKey]) { stage.textContent = labels[stageKey]; stage.className = `avit-stage stage-${stageKey === 'expanding' || stageKey === 'reviewing' ? 'triage' : stageKey}`; }
      item.stage = stageKey;
      const time = item.node.querySelector('.avit-updated'); time.textContent = clock(at); time.dateTime = at;
    }
    function finish(item, result) {
      item.result = result; item.active = false;
      item.node.classList.remove('active'); item.node.dataset.result = result;
      const history = item.node.querySelector('.fp-history');
      if (!history.dataset.userToggled && result !== 'error') history.open = false;
    }
    function activate(item) { if (!item.result) { item.active = true; item.node.classList.add('active'); } }

    function queueAvit(avit, at) {
      const item = card('avit', avit);
      if (!item.node.querySelector('.fp-history-list').children.length) addHistory(item, at, 'Queued', 'Waiting for its turn in the batch');
      return item;
    }
    function refreshTaskChips(task) {
      const info = run.tasks.get(task);
      if (!info?.avits) return;
      const list = info.node.querySelector('.fp-task-avits'); list.replaceChildren();
      for (const avit of info.avits) {
        const result = run.avits.get(avit)?.result;
        const chip = el('li', `fp-chip ${result ? `chip-${result}` : run.avits.get(avit)?.active ? 'chip-active' : ''}`.trim(), avit);
        chip.title = result ? `${avit}: ${result}` : `${avit}: ${run.avits.get(avit)?.active ? 'in progress' : 'queued'}`;
        list.append(chip);
      }
      const done = info.avits.filter(avit => run.avits.get(avit)?.result).length;
      info.node.querySelector('.fp-task-progress').textContent = `${done} / ${info.avits.length} AVITs reviewed${info.shared?.length ? ` · ${info.shared.length} shared with an earlier entry, reviewed once` : ''}${info.skipped?.length ? ` · ${info.skipped.length} over the limit` : ''}`;
    }

    // ── Summary ──
    function summarize() {
      section.classList.remove('hidden');
      const tally = Object.fromEntries(RESULTS.map(result => [result, 0]));
      for (const item of run.avits.values()) if (item.result) tally[item.result]++;
      const total = Math.max(run.total, run.avits.size);
      const done = RESULTS.reduce((sum, result) => sum + tally[result], 0);
      const running = run.status === 'running' || run.status === 'expanding';
      const indeterminate = running && (run.status === 'expanding' || !total);
      bar.classList.toggle('indeterminate', indeterminate);
      bar.setAttribute('aria-valuemax', String(total));
      if (indeterminate) { bar.removeAttribute('aria-valuenow'); bar.setAttribute('aria-valuetext', 'Reading the SCTASK descriptions'); }
      else { bar.setAttribute('aria-valuenow', String(done)); bar.setAttribute('aria-valuetext', `${done} of ${plural(total, 'AVIT')} done`); }
      for (const result of RESULTS) segments[result].style.width = total ? `${(tally[result] / total) * 100}%` : '0%';
      counts.replaceChildren(el('strong', 'fp-count-done', `${done} / ${total}`),
        document.createTextNode(` · ${tally.closed} closed · ${tally.noted} noted · ${plural(tally.error, 'error')}${tally.skipped ? ` · ${tally.skipped} skipped` : ''}`));
      const taskTally = Object.fromEntries(RESULTS.map(result => [result, 0]));
      for (const item of run.tasks.values()) if (item.result) taskTally[item.result]++;
      tasksLine.textContent = run.tasks.size ? `${plural(run.tasks.size, 'SCTASK')} · ${taskTally.closed} closed · ${taskTally.noted} left open · ${plural(taskTally.error, 'error')}${taskTally.skipped ? ` · ${taskTally.skipped} not updated` : ''}` : '';
      status.textContent = run.status === 'running' && total ? `${RUN_STATUS.running} ${Math.min(done + 1, total)} of ${total}` : RUN_STATUS[run.status] || '';
      status.className = `avit-stage stage-${{ running: 'triage', expanding: 'triage', complete: 'done', cancelled: 'cancelled', error: 'error', interrupted: 'cancelled' }[run.status] || 'queued'}`;
      section.classList.toggle('active', running);
      section.setAttribute('aria-busy', String(running));
      if (run.startedAt) { started.textContent = `Started ${clock(run.startedAt)}`; started.dateTime = run.startedAt; }
      const notes = [];
      if (run.truncated) notes.push(`Limited to ${run.truncated.reviewed} of ${run.truncated.total} AVITs (the maximum per run): ${run.truncated.skipped.length} not reviewed and listed as skipped. Run them again in another batch.`);
      if (run.status === 'interrupted') notes.push('The page reloaded or lost its connection before the run finished. The Workbench stops a run when its connection closes (no run state is kept on the server), so items still in progress were not finished; a ServiceNow update already under way still completes. The history up to that point is kept for this browser session.');
      if (run.error) notes.push(run.error);
      note.textContent = notes.join(' ');
      note.className = `fp-run-note small ${notes.length ? 'fp-status-warn' : ''}`.trim();
      if (!running && !logBox.dataset.userToggled && run.status !== 'idle') logBox.open = run.status !== 'complete' || run.events <= 40;
    }

    // ── Events ──
    function apply(event) {
      const at = event.at || new Date().toISOString();
      switch (event.type) {
        case 'fp_run_start': {
          reset(); run.status = event.sctasks?.length ? 'expanding' : 'running'; run.startedAt = at; run.total = event.avits.length;
          for (const avit of event.avits) queueAvit(avit, at);
          runLog(at, '', 'Started', `${plural(event.avits.length, 'AVIT')}${event.sctasks?.length ? ` and ${plural(event.sctasks.length, 'SCTASK')}` : ''} submitted${event.model ? ` · ${event.model}` : ''}`);
          break;
        }
        case 'sctask_item': {
          const item = card('sctask', event.sctask);
          setStage(item, event.stage, TASK_STAGES, at);
          if (event.avits) {
            item.avits = event.avits; item.shared = event.shared || []; item.skipped = event.skipped || [];
            for (const avit of event.avits) { if (!run.avitTasks.has(avit)) run.avitTasks.set(avit, []); if (!run.avitTasks.get(avit).includes(event.sctask)) run.avitTasks.get(avit).push(event.sctask); }
          }
          item.node.querySelector('.avit-detail').textContent = event.detail || '';
          const label = TASK_STAGES[event.stage] || event.stage;
          addHistory(item, at, label, event.detail, event.stage === 'error' ? 'error' : '');
          runLog(at, event.sctask, label, event.detail, event.stage === 'error' ? 'error' : event.done && event.stage === 'done' ? 'success' : '');
          if (event.done) finish(item, resultOf(event)); else if (event.stage !== 'queued') activate(item);
          refreshTaskChips(event.sctask);
          break;
        }
        case 'avit_batch_start': {
          run.status = 'running'; run.total = event.avits.length; run.truncated = event.truncated || null;
          for (const avit of event.avits) { const item = queueAvit(avit, at); avits.append(item.node); }
          for (const [avit, owners] of run.avitTasks) { const item = run.avits.get(avit); if (item) item.node.querySelector('.avit-tasks').textContent = `From ${owners.join(', ')}`; }
          runLog(at, '', 'Queued', `${plural(event.avits.length, 'AVIT')} to review${event.sctasks?.length ? ` (including the AVITs of ${plural(event.sctasks.length, 'SCTASK')})` : ''}`);
          if (event.truncated) runLog(at, '', 'Limit', `Only the first ${event.truncated.reviewed} of ${event.truncated.total} AVITs are reviewed (maximum ${event.max || event.truncated.reviewed} per run); ${event.truncated.skipped.length} skipped: ${event.truncated.skipped.join(', ')}`, 'warning');
          for (const task of run.tasks.keys()) refreshTaskChips(task);
          break;
        }
        case 'avit_item': {
          const item = card('avit', event.avit);
          const list = item.node.querySelector('.fp-history-list');
          if (event.tool) {
            activate(item);
            const { detail, fresh } = toolEntry(list, item.node, at, event.tool, event.repeat || 1);
            item.node.querySelector('.avit-detail').textContent = `${detail}…`;
            if (fresh) runLog(at, event.avit, 'Reviewing', 'Model inspecting the repository', 'tool');
            break;
          }
          setStage(item, event.stage, AVIT_STAGES, at);
          if (event.detail !== undefined && !event.action) item.node.querySelector('.avit-detail').textContent = event.detail;
          if (event.disposition) { const badge = item.node.querySelector('.avit-disposition'); badge.className = 'avit-disposition disposition-badge'; badge.textContent = event.disposition; }
          const label = event.action ? ACTIONS[event.action] || 'Updated' : AVIT_STAGES[event.stage] || event.stage;
          const kind = event.stage === 'error' ? 'error' : event.action === 'warning' ? 'warning' : event.action || (event.done && event.stage === 'done') ? 'success' : '';
          const detail = `${event.detail || ''}${event.disposition && event.stage === 'reported' ? ` · ${event.disposition}` : ''}`;
          addHistory(item, at, label, detail, kind);
          runLog(at, event.avit, label, detail, kind);
          if (event.outcome) renderOutcome(item, event);
          if (event.done) finish(item, resultOf(event)); else activate(item);
          for (const task of run.avitTasks.get(event.avit) || []) refreshTaskChips(task);
          break;
        }
        case 'avit_batch_complete':
          run.status = event.cancelled ? 'cancelled' : 'complete';
          runLog(at, '', event.cancelled ? 'Stopped' : 'Complete', event.cancelled ? 'The run was stopped; finished items keep their results' : 'Every item has reached a final state', event.cancelled ? 'warning' : 'success');
          settle();
          break;
        case 'avit_batch_error':
          run.status = run.events > 1 ? 'interrupted' : 'error'; run.error = event.message || 'The run could not start';
          runLog(at, '', 'Error', run.error, 'error');
          settle();
          break;
        case 'fp_interrupted':
          if (run.status !== 'running' && run.status !== 'expanding') return;
          run.status = 'interrupted';
          runLog(at, '', 'Interrupted', event.detail || 'The connection closed before the run finished', 'error');
          settle();
          break;
        default: return;
      }
      summarize();
    }
    /** Nothing is still in progress once the run ends: stop every spinner. */
    function settle() {
      for (const item of [...run.avits.values(), ...run.tasks.values()]) { item.active = false; item.node.classList.remove('active'); }
    }
    function renderOutcome(item, event) {
      const list = item.node.querySelector('.avit-outcome'); list.replaceChildren();
      const o = event.outcome;
      if (o.attached) list.append(el('li', '', 'Word report attached to the AVIT'));
      if (o.closed === true) list.append(el('li', '', 'Closed as false positive with the Threatlint work note'));
      if (event.disposition === 'FALSE POSITIVE' && o.closed && !o.tuned && (o.semgrep || []).some(line => /Rule not tuned/.test(line))) list.append(el('li', 'fp-status-warn', 'The rule was not tuned, so this false positive can recur. Re-run this AVIT, or run `threatlint avit semgrep <AVIT> --report <report> --checkout <dir>`.'));
      if (o.closed === 'state not applied') list.append(el('li', '', 'ServiceNow did not keep the closed state/substate (check its business rules)'));
      if (o.leftOpen) list.append(el('li', '', 'Left open with the Threatlint work note and the report attached.'));
      for (const line of o.semgrep || []) list.append(el('li', '', line.replace(/^[✓!]\s*/, 'Semgrep: ')));
    }

    // ── Session persistence ──
    function remember(event) {
      if (!persist) return;
      if (event.type === 'fp_run_start') stored = [];
      const last = stored[stored.length - 1];
      // Consecutive tool calls on one AVIT are stored as one event with a repeat count.
      if (event.tool && last?.tool && last.avit === event.avit) last.repeat = (last.repeat || 1) + 1;
      else if (stored.length < MAX_STORED || event.done || event.type !== 'avit_item') stored.push(event);
      clearTimeout(saveTimer);
      saveTimer = setTimeout(save, 200);
    }
    function save() { try { sessionStorage.setItem(STORE_KEY, JSON.stringify(stored)); } catch { /* the history stays on the page */ } }

    function handle(event) {
      const stamped = event.at ? event : { ...event, at: new Date().toISOString() };
      if (stamped.type !== 'fp_run_start' && !run.startedAt && stamped.type !== 'avit_batch_error') apply({ type: 'fp_run_start', at: stamped.at, avits: [], sctasks: [] });
      remember(stamped);
      apply(stamped);
    }
    /** Replays this session's last run after a reload. Returns true when one was shown. */
    function restore() {
      let events = [];
      try { events = JSON.parse(sessionStorage.getItem(STORE_KEY) || '[]'); } catch { events = []; }
      if (!Array.isArray(events) || !events.length || events[0]?.type !== 'fp_run_start') return false;
      stored = events; persist = false;
      try { for (const event of events) apply(event); } finally { persist = true; }
      if (run.status === 'running' || run.status === 'expanding') handle({ type: 'fp_interrupted', detail: 'The page was reloaded during the run' });
      return true;
    }

    reset();
    return {
      start(plan) { handle({ type: 'fp_run_start', avits: plan.avits, sctasks: plan.sctasks, model: plan.model }); },
      handle,
      restore,
      interrupt(detail) { handle({ type: 'fp_interrupted', detail }); },
      get running() { return run.status === 'running' || run.status === 'expanding'; },
    };
  }

  /** Mirrors the server's parseBatchInput: AVIT and SCTASK numbers in any mix, in input order, deduplicated. */
  function parseInput(text) {
    const tokens = [...new Set(String(text || '').toUpperCase().split(/[\s,;]+/).filter(Boolean))];
    const invalid = tokens.filter(token => !/^AVIT\d{7,15}$/.test(token) && !/^SCTASK\d{7,10}$/.test(token));
    if (invalid.length) throw new Error(`Not an AVIT or SCTASK number: ${invalid.slice(0, 5).join(', ')} (expected AVIT plus 7 to 15 digits, e.g. AVIT000000095938462, or SCTASK plus 7 to 10 digits, e.g. SCTASK14120565)`);
    return { order: tokens, avits: tokens.filter(token => token.startsWith('AVIT')), sctasks: tokens.filter(token => token.startsWith('SCTASK')) };
  }

  window.ThreatlintFpRun = { create, parseInput };
})();
