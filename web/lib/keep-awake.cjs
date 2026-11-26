'use strict';

/**
 * Keeps a Mac from idle-sleeping while Threatlint works through a queue. Idle sleep freezes reviews and ServiceNow or
 * Semgrep writes mid-flight. `caffeinate -i` blocks only idle sleep (closing the lid still sleeps the Mac), and
 * `-w <pid>` ends it automatically if Threatlint quits or crashes. Concurrent queues share one caffeinate process.
 *
 * Off when THREATLINT_KEEP_AWAKE=0, on other platforms, and inside the Node test runner.
 */
const fs = require('node:fs');
const { spawn } = require('node:child_process');

const CAFFEINATE = '/usr/bin/caffeinate';
let holders = 0;
let child = null;

function keepAwake({ platform = process.platform, env = process.env, spawnImpl = spawn, exists = fs.existsSync, pid = process.pid } = {}) {
  if (platform !== 'darwin' || env.THREATLINT_KEEP_AWAKE === '0' || env.NODE_TEST_CONTEXT || !exists(CAFFEINATE)) return () => {};
  holders += 1;
  if (!child) {
    try {
      child = spawnImpl(CAFFEINATE, ['-i', '-w', String(pid)], { stdio: 'ignore' });
      child.on?.('error', () => { child = null; });
      child.unref?.();
    } catch { child = null; }
  }
  let released = false;
  return () => {
    if (released) return;
    released = true;
    holders = Math.max(0, holders - 1);
    if (!holders && child) {
      try { child.kill(); } catch { /* caffeinate also exits with Threatlint (-w). */ }
      child = null;
    }
  };
}

module.exports = { keepAwake };
