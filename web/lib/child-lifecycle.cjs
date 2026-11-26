'use strict';

/** Supervise one native CLI. Termination is a request; only close confirms its resources are released. */
/**
 * Calls onExpire after `ms` of time the computer was awake. Time asleep is not counted: on wake, a gap between ticks
 * far longer than the tick is treated as sleep, so a laptop waking from sleep does not instantly expire every limit.
 * Returns a function that cancels it.
 */
function awakeTimer(ms, onExpire, { now = Date.now } = {}) {
  const tick = Math.max(10, Math.min(5000, Math.floor(ms / 10)));
  let elapsed = 0, last = now();
  const interval = setInterval(() => {
    const current = now();
    const gap = current - last;
    last = current;
    elapsed += gap > tick * 6 ? tick : gap;  // A long gap is sleep: count one tick, not the time asleep.
    if (elapsed >= ms) { clearInterval(interval); onExpire(); }
  }, tick);
  interval.unref?.();
  return () => clearInterval(interval);
}

function superviseChild(child, { signal, timeoutMs, timeoutMessage, startMessage, onClose, resolve, reject, killGraceMs = 5000 }) {
  let settled = false, closed = false, stopping = null, killTimer = null;
  // timeoutMessage may be a function, so the message can include output gathered while the child ran.
  const cancelLimit = awakeTimer(timeoutMs, () => stop(new Error(typeof timeoutMessage === 'function' ? timeoutMessage() : timeoutMessage)));
  const timer = { clear: cancelLimit };
  const abort = () => stop(Object.assign(new Error('Run cancelled'), { name: 'AbortError' }));

  function finish(error, value) {
    if (settled) return;
    settled = true;
    timer.clear(); clearTimeout(killTimer);
    signal?.removeEventListener('abort', abort);
    if (error) reject(error); else resolve(value);
  }

  function stop(error) {
    if (settled || stopping) return;
    stopping = error;
    timer.clear();
    if (closed) { finish(error); return; }
    try { child.kill('SIGTERM'); } catch { /* Still wait for exit and attempt the bounded escalation below. */ }
    if (settled) return; // Test doubles and some hosts can emit close synchronously from kill.
    killTimer = setTimeout(() => {
      if (!closed) { try { child.kill('SIGKILL'); } catch { /* A failed signal is not proof of exit. */ } }
    }, killGraceMs);
  }

  child.once('error', () => {
    const error = new Error(startMessage);
    if (!child.pid) finish(error); // spawn failed, so there is no process to drain
    else stop(error);
  });
  child.once('close', code => {
    closed = true;
    if (settled) return;
    if (stopping) { finish(stopping); return; }
    try { onClose(code, finish); } catch { finish(new Error('Native model provider returned an invalid final response')); }
  });
  signal?.addEventListener('abort', abort, { once: true });
  // Callers check before spawning. This catches an abort during a custom spawn implementation.
  if (signal?.aborted) queueMicrotask(abort);
  return { stop, get settled() { return settled; }, get stopping() { return !!stopping; } };
}

module.exports = { superviseChild, awakeTimer };
