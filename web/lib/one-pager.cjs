'use strict';

/**
 * The one-page PDF summary that accompanies every Finding Review Word report sent to a tracker.
 * The Python package renders it (threatlint/one_pager.py), so the CLI, headless runs, and the Workbench share one layout.
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { HttpError } = require('./http.cjs');

const PREFIX = '[ONE PAGER SUMMARY] ';
const PDF_TYPE = 'application/pdf';
const FINDING_ID = /^[A-Z][A-Z0-9]*-\d+$/;

/** `[ONE PAGER SUMMARY] <Word report name>.pdf`, so the pair sorts and reads together. */
function attachmentName(wordName) {
  return `${PREFIX}${path.basename(wordName).replace(/\.docx$/i, '')}.pdf`;
}

/**
 * Renders the summary of one finding in a saved Markdown report. options: { avit, findingId, signal, runCli }.
 * Throws an HttpError when the PDF cannot be produced, so callers attach nothing rather than a Word report alone.
 */
async function render(mdPath, { avit = '', findingId = '', signal, runCli = require('./avit-batch.cjs').runCli } = {}) {
  if (!mdPath || !fs.existsSync(mdPath)) throw new HttpError('The Markdown report for the one-page summary is unavailable', 409);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-one-pager-'));
  const out = path.join(directory, 'summary.pdf');
  try {
    const args = ['one-pager', mdPath, out];
    if (avit) args.push('--avit', String(avit));
    if (findingId && FINDING_ID.test(findingId)) args.push('--finding', findingId);
    const result = await runCli(args, { signal });
    const content = result.code === 0 && fs.existsSync(out) ? fs.readFileSync(out) : null;
    if (!content || content.subarray(0, 5).toString() !== '%PDF-') {
      const reason = String(result.stderr || result.stdout || '').trim().split(/\r?\n/).filter(Boolean).pop() || 'no output';
      // Exit 3: the report has no structured finding, so there is nothing to summarize.
      throw Object.assign(new HttpError(`The one-page summary could not be generated, so nothing was posted: ${reason.replace(/^ERROR:\s*/, '').slice(0, 300)}`,
        result.code === 3 ? 409 : 500), result.code === 3 ? { code: 'one_pager_no_findings' } : {});
    }
    return content;
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

/** The attachment object ({ name, content, type }) for a Word report attachment name. */
async function attachment(mdPath, wordName, options = {}) {
  return { name: attachmentName(wordName), content: await render(mdPath, options), type: PDF_TYPE };
}

/** As attachment(), but null for a narrative-only report that has no finding to summarize. */
async function optionalAttachment(mdPath, wordName, options = {}) {
  try { return await attachment(mdPath, wordName, options); }
  catch (error) { if (error.code === 'one_pager_no_findings') return null; throw error; }
}

module.exports = { PREFIX, PDF_TYPE, attachmentName, render, attachment, optionalAttachment };
