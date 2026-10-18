'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function createStore(directory) {
  const sessions = new Map();
  const index = directory ? path.join(directory, 'sessions.json') : null;
  if (index) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    if (fs.existsSync(index)) {
      try {
        for (const record of JSON.parse(fs.readFileSync(index, 'utf8'))) {
          if (record.id && record.repoPath && Array.isArray(record.reports)) sessions.set(record.id, record);
        }
      } catch (error) {
        throw new Error(`Session history could not be read; original data was preserved: ${error.message}`);
      }
    }
  }
  function save() {
    if (!index) return;
    // Explicit allowlist: API keys, attachments, prompts, and tool traces are never persisted.
    const records = [...sessions.values()].map(session => ({ id: session.id, repoPath: session.repoPath,
      isTempRepo: session.isTempRepo, tempDir: session.tempDir || null, provenance: session.provenance || null,
      createdAt: session.createdAt, updatedAt: session.updatedAt, reports: session.reports }));
    const temporary = `${index}.${crypto.randomUUID()}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify(records, null, 2), { mode: 0o600 });
    fs.renameSync(temporary, index);
  }
  function create(repoPath, isTempRepo = false, tempDir = null) {
    const id = crypto.randomUUID();
    sessions.set(id, { id, repoPath, isTempRepo, tempDir, createdAt: Date.now(), updatedAt: Date.now(), reports: [] });
    save();
    return id;
  }
  return { sessions, save, create, directory };
}

module.exports = { createStore };