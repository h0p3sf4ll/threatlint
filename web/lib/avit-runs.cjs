'use strict';

/**
 * Finding-triage runs that outlive the page that started them.
 *
 * A run belongs to the Workbench, not to a WebSocket: leaving the page, reloading it, or losing the connection
 * does not stop it. Each run keeps a compact, append-only event log; a page that connects later attaches, gets the
 * log replayed (`avit_batch_replay`), then follows live events. One run is active at a time because every AVIT
 * review shares the ServiceNow, Git, and Semgrep credentials and updates ServiceNow records. The most recent run's
 * log is kept after it finishes so a returning page can still show the outcome. Quitting the Workbench stops it.
 *
 * Events hold only what the page already receives (stages, details, outcomes); the start message's provider and
 * ServiceNow credentials are never recorded, and the message is released when the run ends.
 */

const { randomUUID } = require('node:crypto');
const { HttpError } = require('./http.cjs');
const { parseBatchInput } = require('./avit-batch.cjs');

// A run has no AVIT limit, so the log is bounded instead: past this many events, intermediate AVIT stages are
// dropped while every final outcome and every task/run event is still kept.
const MAX_EVENTS = 200_000;

function createAvitRuns(avitBatch) {
  let current = null;

  function record(run, event) {
    const last = run.events[run.events.length - 1];
    // Consecutive tool calls on one AVIT collapse into one entry with a repeat count, as the page stores them.
    if (event.tool && last?.tool && last.avit === event.avit) last.repeat = (last.repeat || 1) + 1;
    else if (run.events.length < MAX_EVENTS || event.done || event.type !== 'avit_item') run.events.push({ ...event });
    for (const subscriber of run.subscribers) {
      try { subscriber(event); } catch { /* one closed page never affects the run or the other pages */ }
    }
  }

  /** Starts a run and subscribes the starting page. Invalid input throws before any run exists. */
  function start(message, subscriber) {
    if (current?.active) throw Object.assign(new HttpError('A finding triage run is already in progress. It is shown on this page; stop it or wait for it to finish.', 409), { code: 'run_active' });
    const { avits, sctasks, issts } = parseBatchInput(message?.avits);
    const run = { id: randomUUID(), active: true, events: [], controller: new AbortController(), subscribers: new Set(subscriber ? [subscriber] : []) };
    current = run;
    const label = typeof message.modelLabel === 'string' ? message.modelLabel.slice(0, 200) : '';
    record(run, { type: 'fp_run_start', at: new Date().toISOString(), runId: run.id, avits, sctasks, issts, model: label });
    (async () => {
      try { await avitBatch.run(message, event => record(run, event), run.controller); }
      catch (error) { record(run, { type: 'avit_batch_error', at: new Date().toISOString(), message: error.message }); }
      finally { run.active = false; run.subscribers.clear(); }
    })();
    return run.id;
  }

  /** The current (or last) run's log, and live events while it is active. Synchronous, so no event falls between. */
  function attach(subscriber) {
    if (!current) return { runId: null, active: false, events: [] };
    if (current.active) current.subscribers.add(subscriber);
    return { runId: current.id, active: current.active, events: current.events.slice() };
  }

  function detach(subscriber) { current?.subscribers.delete(subscriber); }

  /** Stops the active run from any page; the runner reports the remaining AVITs as cancelled. */
  function cancel() {
    if (!current?.active) return false;
    current.controller.abort();
    return true;
  }

  return { start, attach, detach, cancel, close: cancel, get active() { return !!current?.active; } };
}

module.exports = { createAvitRuns, MAX_EVENTS };
