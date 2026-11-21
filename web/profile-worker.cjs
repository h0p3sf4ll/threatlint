'use strict';

// Internal entry point. This port is never the public web app.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

async function main() {
  if (process.env.THREATLINT_WORKER_STDIN === '1') {
    const readline = require('node:readline').createInterface({ input: process.stdin });
    const config = await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Worker configuration missing')), 10_000);
      readline.once('line', line => { clearTimeout(timeout); readline.close(); try { resolve(JSON.parse(line)); } catch { reject(new Error('Invalid worker configuration')); } });
    });
    process.env.THREATLINT_WORKER_TOKEN = config.token;
  }
  if (!/^[a-f0-9]{64}$/.test(process.env.THREATLINT_WORKER_TOKEN || '')) throw new Error('Worker gateway token required');
  // Repository checkouts must survive container restarts along with their session records.
  const temporary = path.join(os.homedir(), 'tmp');
  fs.mkdirSync(temporary, { recursive: true, mode: 0o700 });
  process.env.TMPDIR = temporary; process.env.TEMP = temporary; process.env.TMP = temporary;
  const workspace = path.join(os.homedir(), 'workspace');
  fs.mkdirSync(workspace, { recursive: true, mode: 0o700 });
  process.chdir(workspace);
  const workbench = require('./server.js');
  await new Promise(resolve => workbench.server.listen(Number(process.env.PORT || 0), process.env.THREATLINT_WORKER_HOST || '127.0.0.1', resolve));
  process.send?.({ type: 'ready', port: workbench.server.address().port });
  let closing = false;
  async function close() { if (closing) return; closing = true; await workbench.close(); process.exit(0); }
  process.on('message', message => { if (message.action === 'close') close(); });
  process.once('SIGINT', close); process.once('SIGTERM', close);
}
main().catch(() => { process.send?.({ type: 'error' }); process.exit(1); });
