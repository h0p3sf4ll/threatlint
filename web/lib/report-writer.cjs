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

const execFileAsync = promisify(execFile);
const CONVERSION_TIMEOUT_MS = 60_000;
const WORD_UNAVAILABLE = 'Word export unavailable. Install python-docx in the configured Python environment; Markdown remains available.';

function createReportWriter(store) {
  function directoryFor(sessionId) {
    return store.directory ? path.join(store.directory, 'reports', sessionId) : path.join(os.tmpdir(), `threatlint-reports-${sessionId}`);
  }

  async function convertToWord(mdPath, docxPath) {
    try {
      await execFileAsync(process.env.THREATLINT_PYTHON || 'python3', [path.join(DATA_DIR, 'scripts/md_to_docx.py'), mdPath, docxPath], { timeout: CONVERSION_TIMEOUT_MS, windowsHide: true });
      if (!fs.existsSync(docxPath)) return false;
      fs.chmodSync(docxPath, 0o600);
      return true;
    } catch { return false; }
  }

  async function save(agentId, markdown, sessionId) {
    if (!markdown.trim()) throw new Error('The model returned no final report');
    const session = store.sessions.get(sessionId);
    const directory = directoryFor(sessionId);
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const timestamp = Math.max(Date.now(), (session.reports.at(-1)?.timestamp || 0) + 1);
    const mdPath = path.join(directory, `${agentId}-${timestamp}.md`);
    const docxPath = path.join(directory, `${agentId}-${timestamp}.docx`);
    fs.writeFileSync(mdPath, markdown, { mode: 0o600 });
    const hasDocx = await convertToWord(mdPath, docxPath);
    const parsed = parseReport(markdown, agentId);
    const report = { id: crypto.randomUUID(), agentId, label: AGENTS[agentId].label, timestamp, mdPath, docxPath: hasDocx ? docxPath : null,
      sessionId, summary: parsed.summary, findings: parsed.findings, quality: parsed.quality, conversionNote: hasDocx ? null : WORD_UNAVAILABLE };
    session.reports.push(report);
    session.updatedAt = Date.now();
    store.save();
    return report;
  }

  function metadata(report) {
    const base = `/api/report/${report.sessionId}/${report.agentId}/${report.timestamp}`;
    return { id: report.id, agentId: report.agentId, label: report.label, timestamp: report.timestamp,
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

  return { save, metadata, find, read };
}

module.exports = { createReportWriter };
