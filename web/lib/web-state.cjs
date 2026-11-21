'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function stateDirectory() { return path.resolve(process.env.THREATLINT_WEB_STATE_DIR || path.join(__dirname, '../.web-state')); }
function acquireStateLock(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const file = path.join(directory, 'gateway.lock');
  const owner = { pid: process.pid, token: crypto.randomUUID() };
  try { fs.writeFileSync(file, JSON.stringify(owner), { flag: 'wx', mode: 0o600 }); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    let prior;
    try { prior = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { throw new Error('Profile state is locked; inspect gateway.lock before removing it'); }
    let alive = true;
    try { process.kill(prior.pid, 0); } catch (probe) { if (probe.code === 'ESRCH') alive = false; }
    if (alive) throw new Error('Profile state is in use. Stop the gateway before starting another gateway or migrating profile state.');
    fs.unlinkSync(file);
    return acquireStateLock(directory);
  }
  return () => {
    try { if (JSON.parse(fs.readFileSync(file, 'utf8')).token === owner.token) fs.unlinkSync(file); } catch { /* already released */ }
  };
}
module.exports = { stateDirectory, acquireStateLock };
