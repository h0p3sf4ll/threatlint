'use strict';

/** Shared workspace operations for HTTP and MCP; neither requires a browser session. */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { HttpError } = require('./http.cjs');
const { createRepositoryDirectory } = require('./repo-store.cjs');
const execFileAsync = promisify(execFile);

function createWorkspaces({ store, integrations = {} }) {
  function get(sessionId) {
    const session = store.sessions.get(sessionId);
    if (!session) throw new HttpError('Session not found', 404);
    return { id: session.id, repoPath: session.repoPath, reportCount: session.reports.length, provenance: session.provenance || null };
  }
  return {
    get,
    list: () => [...store.sessions.values()].map(session => ({ ...get(session.id), createdAt: session.createdAt, updatedAt: session.updatedAt }))
      .sort((a, b) => b.updatedAt - a.updatedAt),
    open({ repoPath } = {}) {
      if (typeof repoPath !== 'string' || !repoPath.trim()) throw new HttpError('repoPath required');
      let resolved;
      try { resolved = fs.realpathSync(path.resolve(repoPath.replace(/^~(?=[\\/]|$)/, os.homedir()))); }
      catch { throw new HttpError('That folder does not exist'); }
      if (!fs.statSync(resolved).isDirectory()) throw new HttpError('Choose a repository directory, not a file');
      const existing = [...store.sessions.values()].find(session => session.repoPath === resolved && !session.isTempRepo);
      return { sessionId: existing?.id || store.create(resolved), repoPath: resolved };
    },
    async clone({ url: raw, branch } = {}) {
      let url;
      try { url = new URL(raw); } catch { throw new HttpError('Use an HTTPS repository URL without embedded credentials'); }
      if (url.protocol !== 'https:' || url.username || url.password) throw new HttpError('Use an HTTPS repository URL without embedded credentials');
      if (branch && (typeof branch !== 'string' || branch.startsWith('-') || !/^[\w./-]{1,200}$/.test(branch))) throw new HttpError('Invalid branch name');
      let tempDir;
      try { tempDir = (integrations.createRepositoryDirectory || createRepositoryDirectory)('threatlint-'); }
      catch { throw new HttpError('Repository storage is unavailable. Check local disk space and folder permissions.', 503); }
      const repoPath = path.join(tempDir, 'repo');
      try {
        await (integrations.execFile || execFileAsync)('git', ['-c', 'core.hooksPath=', 'clone', '--depth=20', ...(branch ? ['--branch', branch] : []), '--', url.toString(), repoPath], {
          timeout: 300_000, maxBuffer: 1024 * 1024, env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: '', SSH_ASKPASS: '' }, windowsHide: true });
      } catch {
        try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch { /* Preserve clone failure. */ }
        throw new HttpError('Clone failed. Verify the HTTPS URL, network access, and existing Git credentials.');
      }
      return { sessionId: store.create(repoPath, true, tempDir), repoPath };
    },
  };
}

module.exports = { createWorkspaces };
