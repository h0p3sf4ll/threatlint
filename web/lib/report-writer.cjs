'use strict';

/** Persists agent output as Markdown (and Word when python-docx is available) inside the workbench store. */

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { AGENTS, DATA_DIR } = require('./agents.cjs');
const { parseReport } = require('./reports.cjs');
const { normalizeReviewMarkdown } = require('./finding-disposition.cjs');

const execFileAsync = promisify(execFile);
const CONVERSION_TIMEOUT_MS = 60_000;
const WORD_UNAVAILABLE = 'Word export unavailable. Install python-docx in the configured Python environment; Markdown remains available.';

async function convertMarkdownToWord(mdPath, docxPath) {
  await execFileAsync(require('./avit-batch.cjs').python(), [path.join(DATA_DIR, 'scripts/md_to_docx.py'), mdPath, docxPath], { timeout: CONVERSION_TIMEOUT_MS, windowsHide: true });
}

function createReportWriter(store, { convertToWord = convertMarkdownToWord } = {}) {
  const reservedTimestamps = new Map();
  function directoryFor(sessionId) {
    return store.directory ? path.join(store.directory, 'reports', sessionId) : path.join(os.tmpdir(), `threatlint-reports-${sessionId}`);
  }

  async function writeWord(mdPath, docxPath) {
    try {
      await convertToWord(mdPath, docxPath);
      if (!fs.existsSync(docxPath)) return false;
      fs.chmodSync(docxPath, 0o600);
      return true;
    } catch { return false; }
  }

  /** options.title: a descriptive report title (e.g. for an imported scan); options.source: where the findings came from. */
  async function save(agentId, markdown, sessionId, { title = null, source = null } = {}) {
    if (!markdown.trim()) throw new Error('The model returned no final report');
    if (agentId === 'appsec-fp-reviewer') markdown = normalizeReviewMarkdown(markdown);
    const session = store.sessions.get(sessionId);
    const directory = directoryFor(sessionId);
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    // Reserve before Word conversion yields: parallel imports can save the same agent/session in one millisecond.
    const previous = session.reports.reduce((maximum, report) => Math.max(maximum, report.timestamp), reservedTimestamps.get(sessionId) || 0);
    const timestamp = Math.max(Date.now(), previous + 1);
    reservedTimestamps.set(sessionId, timestamp);
    const mdPath = path.join(directory, `${agentId}-${timestamp}.md`);
    const docxPath = path.join(directory, `${agentId}-${timestamp}.docx`);
    fs.writeFileSync(mdPath, markdown, { mode: 0o600 });
    const hasDocx = await writeWord(mdPath, docxPath);
    const parsed = parseReport(markdown, agentId);
    const report = { id: crypto.randomUUID(), agentId, label: agentId === 'appsec-fp-reviewer' ? 'Finding Review' : AGENTS[agentId].label, timestamp, mdPath, docxPath: hasDocx ? docxPath : null,
      sessionId, summary: parsed.summary, findings: parsed.findings, quality: parsed.quality, conversionNote: hasDocx ? null : WORD_UNAVAILABLE,
      ...(title ? { title: String(title).slice(0, 300) } : {}), ...(source ? { source } : {}) };
    session.reports.push(report);
    session.reports.sort((a, b) => a.timestamp - b.timestamp);
    session.updatedAt = Date.now();
    store.save();
    return report;
  }

  function metadata(report) {
    const base = `/api/report/${report.sessionId}/${report.agentId}/${report.timestamp}`;
    return { id: report.id, agentId: report.agentId, label: report.label, title: report.title || null, source: report.source || null, sessionId: report.sessionId, timestamp: report.timestamp,
      hasDocx: !!report.docxPath, mdUrl: `${base}/md`, docxUrl: report.docxPath ? `${base}/docx` : null,
      previewUrl: `${base}/json`, summary: report.summary, findings: report.findings, quality: report.quality,
      conversionNote: report.conversionNote || null };
  }

  /** Finds a report by its stable id across all sessions. */
  function find(reportId) {
    for (const session of store.sessions.values()) {
      const report = session.reports.find(item => item.id === reportId);
      if (report) return { session, report };
    }
    return null;
  }

  function read(report) { return parseReport(fs.readFileSync(report.mdPath, 'utf8'), report.agentId); }

  /** Deletes one saved report. A failed history write restores its files and entry. */
  function remove(report) {
    const session = store.sessions.get(report.sessionId);
    const saved = session?.reports.find(item => item.id === report.id);
    if (!saved) return false;
    const previous = session.reports;
    const updatedAt = session.updatedAt;
    const remaining = previous.filter(item => item.id !== saved.id);
    const artifacts = item => [[item.mdPath, 'md'], [item.docxPath, 'docx']];
    const referenced = new Set(remaining.flatMap(artifacts).map(([file]) => typeof file === 'string' && path.resolve(file)));
    const directory = directoryFor(session.id);
    const moved = [];
    try {
      // Never delete a path supplied by stored metadata outside its managed report directory.
      if (Object.hasOwn(AGENTS, saved.agentId) && Number.isSafeInteger(saved.timestamp) && /^[\w-]+$/.test(session.id) && fs.existsSync(directory)) {
        const expectedParent = store.directory ? path.join(fs.realpathSync(store.directory), 'reports', session.id)
          : path.join(fs.realpathSync(os.tmpdir()), `threatlint-reports-${session.id}`);
        if (fs.realpathSync(directory) === expectedParent) {
          for (const [file, format] of artifacts(saved)) {
            const artifact = path.resolve(directory, `${saved.agentId}-${saved.timestamp}.${format}`);
            if (typeof file !== 'string' || path.resolve(file) !== artifact || referenced.has(artifact)) continue;
            const stat = fs.lstatSync(artifact, { throwIfNoEntry: false });
            if (!stat || (!stat.isFile() && !stat.isSymbolicLink())) continue;
            const staged = path.join(directory, `.deleted-${crypto.randomUUID()}`);
            try { fs.renameSync(artifact, staged); } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
            moved.push({ artifact, staged });
          }
        }
      }
      session.reports = remaining;
      session.updatedAt = Date.now();
      store.save();
    } catch (error) {
      session.reports = previous;
      session.updatedAt = updatedAt;
      for (const { artifact, staged } of moved.reverse()) fs.renameSync(staged, artifact);
      throw error;
    }
    for (const { staged } of moved) fs.rmSync(staged, { force: true });
    return true;
  }

  return { save, metadata, find, read, remove };
}

module.exports = { createReportWriter };
