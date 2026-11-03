'use strict';

/**
 * Positioned text lines from an uploaded PDF scan report, using pdf.js (pdfjs-dist, pinned).
 *
 * Each line is { page, y, size, text, parts: [{ x, size, text }] }: `text` serves layout-free parsing (Invicti),
 * while `x`/`y`/`size` let table parsers rebuild columns and rows (MobSF) and tell headings from cells.
 *
 * The PDF is untrusted: pdf.js runs with eval disabled, no font loading, no network/range fetching, and no
 * annotation scripting; only the text layer is read. Text items are regrouped into lines by their baseline so
 * table rows and headings come out in reading order. Page count and output size are capped.
 */

const MAX_PAGES = 1000;
const MAX_CHARS = 8 * 1024 * 1024;
const LINE_TOLERANCE = 2; // points: items whose baselines differ by less than this share a line

let pdfjs;
/**
 * pdf.js is an ES module; load it once on first use (the legacy build supports Node without a DOM).
 * Its optional canvas package is intentionally not installed (rendering is never used), so the load-time
 * "Cannot load @napi-rs/canvas / Cannot polyfill …" warnings are expected and filtered out here only.
 */
async function loadPdfjs() {
  if (!pdfjs) {
    const warn = console.warn;
    console.warn = (...args) => { if (!/^Warning: Cannot (load "@napi-rs\/canvas"|polyfill)/.test(String(args[0]))) warn(...args); };
    try { pdfjs = await import('pdfjs-dist/legacy/build/pdf.mjs'); } finally { console.warn = warn; }
  }
  return pdfjs;
}

/** Text items of one page joined into lines, top to bottom, left to right. */
function pageLines(items, page = 1) {
  const rows = [];
  for (const item of items) {
    if (typeof item.str !== 'string' || !item.str.trim()) continue;
    const [, , , height, x, y] = item.transform;
    let row = rows.find(candidate => Math.abs(candidate.y - y) < LINE_TOLERANCE);
    if (!row) { row = { page, y, parts: [] }; rows.push(row); }
    row.parts.push({ x, size: Math.abs(height), text: item.str.replace(/\s+/g, ' ').trim() });
  }
  return rows
    .sort((a, b) => b.y - a.y) // PDF y grows upward
    .map(row => {
      const parts = row.parts.sort((a, b) => a.x - b.x);
      return { ...row, parts, size: Math.max(...parts.map(part => part.size)), text: parts.map(part => part.text).join(' ').trim() };
    })
    .filter(row => row.text);
}

/** Positioned lines from every page, in reading order. */
async function pdfLines(buffer, { maxPages = MAX_PAGES } = {}) {
  const { getDocument } = await loadPdfjs();
  const task = getDocument({
    data: new Uint8Array(buffer), isEvalSupported: false, disableFontFace: true, useSystemFonts: false,
    disableRange: true, disableStream: true, disableAutoFetch: true, enableXfa: false, verbosity: 0,
  });
  let document;
  try {
    document = await task.promise;
  } catch (error) {
    throw new Error(error?.name === 'PasswordException' ? 'The PDF is password-protected; export it without a password' : 'The PDF could not be read');
  }
  try {
    if (document.numPages > maxPages) throw new Error(`The PDF has ${document.numPages} pages; at most ${maxPages} can be imported`);
    const lines = [];
    let chars = 0;
    for (let number = 1; number <= document.numPages; number += 1) {
      const page = await document.getPage(number);
      const { items } = await page.getTextContent();
      page.cleanup();
      for (const line of pageLines(items, number)) {
        chars += line.text.length + 1;
        if (chars > MAX_CHARS) throw new Error('The PDF contains more text than can be imported');
        lines.push(line);
      }
    }
    return lines;
  } finally {
    await task.destroy();
  }
}

module.exports = { pdfLines, pageLines };
