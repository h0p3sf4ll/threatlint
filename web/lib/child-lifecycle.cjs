'use strict';

/** Supervise one native CLI. Termination is a request; only close confirms its resources are released. */
function superviseChild(child, { signal, timeoutMs, timeoutMessage, startMessage, onClose, resolve, reject, killGraceMs = 5000 }) {
  let settled = false, closed = false, stopping = null, killTimer = null;
  const timer = setTimeout(() => stop(new Error(timeoutMessage)), timeoutMs);
  const abort = () => stop(Object.assign(new Error('Run cancelled'), { name: 'AbortError' }));

  function finish(error, value) {
    if (settled) return;
    settled = true;
    clearTimeout(timer); clearTimeout(killTimer);
    signal?.removeEventListener('abort', abort);
    if (error) reject(error); else resolve(value);
  }

  function stop(error) {
    if (settled || stopping) return;
    stopping = error;
    clearTimeout(timer);
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

module.exports = { superviseChild };
