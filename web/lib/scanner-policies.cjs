'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

/** Approved exceptions are bound to the reviewed repository and exact file bytes. */
function createScannerPolicies(directory) {
  const file = directory && path.join(directory, 'reviewed-scanner-policies.json');
  let entries = [];
  try { if (file) entries = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { /* No approved policies yet. */ }
  if (!Array.isArray(entries)) entries = [];
  function save(session, target, expires, reportId, findingId) {
    if (!session || session.provenance?.kind === 'scan-import' || !directory) return false;
    const root = fs.realpathSync(session.repoPath);
    const relative = target.path.replaceAll('\\', '/');
    if (path.isAbsolute(relative) || relative.split('/').some(part => ['..', '.'].includes(part))) return false;
    const candidate = path.resolve(root, relative);
    let stat;
    try { stat = fs.lstatSync(candidate); } catch { return false; }
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024 * 1024 || !fs.realpathSync(candidate).startsWith(root + path.sep)) return false;
    const record = { repository: root, path: relative, kind: target.kind, id: target.rule, purl: target.purl || null,
      fileHash: crypto.createHash('sha256').update(fs.readFileSync(candidate)).digest('hex'), expires, reportId, findingId };
    const next = entries.filter(item => !(item.repository === root && item.path === relative && item.kind === record.kind && item.id === record.id && item.purl === record.purl));
    next.push(record);
    if (next.length > 2000) throw new Error('Reviewed scanner policy limit reached');
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const temporary = `${file}.${crypto.randomUUID()}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify(next), { mode: 0o600 }); fs.renameSync(temporary, file);
    entries = next; return true;
  }
  return { save, forSession(session) {
    if (!session) return [];
    const root = fs.realpathSync(session.repoPath);
    const today = new Date().toISOString().slice(0, 10);
    return entries.filter(item => item.repository === root && item.expires >= today).map(({ repository, ...entry }) => entry);
  } };
}
module.exports = { createScannerPolicies };
