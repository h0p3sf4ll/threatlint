'use strict';
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const path = require('node:path');
const { python, pythonPath } = require('./avit-batch.cjs');
const { semgrepToken } = require('./semgrep-cloud.cjs');
const execute = promisify(execFile);
let cached, pending;
async function status() {
  if (cached && Date.now() - cached.time < 60000) return cached.value;
  if (pending) return pending;
  pending = (async () => {
    const env = { ...process.env, PYTHONPATH: [pythonPath(), process.env.PYTHONPATH].filter(Boolean).join(path.delimiter) };
    try {
      const local = await execute(python(), ['-c', 'import json; from threatlint.semgrep_engine import engine_status; from threatlint.tls import tool_env; print(json.dumps(engine_status(environment=tool_env)))'], { env, timeout: 45000, maxBuffer: 64000, windowsHide: true });
      const installed = JSON.parse(local.stdout);
      if (!installed.cli_version) {
        const value = { ...installed, engine: null, pro_enabled: null, descriptor: 'Semgrep is not installed on this runner' };
        cached = { time: Date.now(), value }; return value;
      }
      try { env.SEMGREP_APP_TOKEN = await semgrepToken(); } catch { /* Native login may still work. */ }
      const { stdout } = await execute(python(), ['-c', 'import json; from threatlint.semgrep_engine import scanner_status; from threatlint.tls import tool_env; print(json.dumps(scanner_status(environment=tool_env)))'], { env, timeout: 115000, maxBuffer: 64000, windowsHide: true });
      const value = JSON.parse(stdout); cached = { time: Date.now(), value }; return value;
    } catch { return { engine: null, pro_enabled: null, descriptor: 'Semgrep engine verification unavailable on this runner' }; }
  })().finally(() => { pending = null; });
  return pending;
}
module.exports = { status };
