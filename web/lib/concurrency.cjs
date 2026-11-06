'use strict';

/** Small structured-concurrency primitives. Never leave work running after the caller settles. */
function checkAbort(signal) {
  if (signal?.aborted) throw Object.assign(new Error('Cancelled'), { name: 'AbortError' });
}

function positiveLimit(value, fallback, maximum = 16) {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < 1 || value > maximum) throw new Error(`Concurrency must be an integer from 1 to ${maximum}`);
  return value;
}

function environmentLimit(name, fallback, maximum = 16) {
  const value = process.env[name];
  return value === undefined ? fallback : positiveLimit(Number(value), fallback, maximum);
}

/** Stable output order, bounded admission, stop-on-error and cancellation with in-flight draining. */
async function mapBounded(items, mapper, { concurrency = 4, signal } = {}) {
  positiveLimit(concurrency, 4, 64);
  checkAbort(signal);
  const results = new Array(items.length);
  let cursor = 0, failure = null;
  async function worker() {
    while (cursor < items.length && !failure) {
      try {
        checkAbort(signal);
        const index = cursor++;
        results[index] = await mapper(items[index], index);
      } catch (error) { failure ||= error; }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  checkAbort(signal);
  if (failure) throw failure;
  return results;
}

/** FIFO, process-local admission for whole model runs across sockets and workflow types. */
function createLimiter(limit, maxQueue = 128) {
  positiveLimit(limit, 4, 64);
  const queue = [];
  let active = 0;
  function drain() {
    while (active < limit && queue.length) {
      const entry = queue.shift();
      entry.signal?.removeEventListener('abort', entry.abort);
      if (entry.signal?.aborted) { entry.reject(Object.assign(new Error('Cancelled'), { name: 'AbortError' })); continue; }
      active++;
      Promise.resolve().then(() => { checkAbort(entry.signal); return entry.work(); })
        .then(entry.resolve, entry.reject).finally(() => { active--; drain(); });
    }
  }
  return (work, { signal } = {}) => new Promise((resolve, reject) => {
    try { checkAbort(signal); } catch (error) { reject(error); return; }
    if (queue.length >= maxQueue) { reject(new Error('Model request queue is full; retry after active reviews finish')); return; }
    const entry = { work, signal, resolve, reject, abort: null };
    entry.abort = () => {
      const index = queue.indexOf(entry);
      if (index >= 0) queue.splice(index, 1);
      signal.removeEventListener('abort', entry.abort);
      reject(Object.assign(new Error('Cancelled'), { name: 'AbortError' }));
    };
    signal?.addEventListener('abort', entry.abort, { once: true });
    queue.push(entry);
    drain();
  });
}

module.exports = { checkAbort, positiveLimit, environmentLimit, mapBounded, createLimiter };
