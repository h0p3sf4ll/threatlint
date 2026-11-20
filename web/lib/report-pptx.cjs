'use strict';

const PptxGenJS = require('pptxgenjs');
const JSZip = require('jszip');
const { redactText } = require('./scan-import.cjs');

const PALETTE = {
  white: 'FFFFFF', ink: '182E2D', muted: '465957', before: '273433', after: '153D36',
  text: 'F2F7F6', caption: 'C7D8D4', accent: '246052',
};
const TEXT_BUDGET = 12_000;
const CODE_COLS = 43;
const CODE_LINES = 6;

/** Bound untrusted text before redaction and keep only valid XML characters. */
function safeText(value) {
  if (typeof value !== 'string') return '';
  const text = value.slice(0, TEXT_BUDGET).replace(/\r\n?/g, '\n');
  const masked = text
    .replace(/(\b[\w.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)[\w.-]*\b["']?[ \t]*[:=][ \t]*)(["'])(?:\\.|(?!\2)[^\n\\])*(?:\2|(?=\n|$))/gi, '$1$2[REDACTED]$2')
    .replace(/^([ \t]*(?:(?:proxy-)?authorization|cookie|set-cookie|x-api-key|x-auth-token)[ \t]*:[ \t]*).*$/gim, '$1[REDACTED]');
  return redactText(masked)
    .replace(/[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD\u{10000}-\u{10FFFF}]/gu, '');
}

/** Small display budgets keep arbitrary findings readable on a one-page slide. */
function prose(value, limit) {
  const glyphs = Array.from(safeText(value).replace(/\s+/g, ' ').trim());
  if (glyphs.length <= limit) return glyphs.join('');
  const clipped = glyphs.slice(0, limit - 1);
  const end = clipped.lastIndexOf(' ');
  return `${(end >= limit - 16 ? clipped.slice(0, end) : clipped).join('').trimEnd()}…`;
}

function codeExcerpt(value) {
  const lines = safeText(value).replace(/^\n+|\s+$/g, '').replaceAll('\t', '    ').split('\n');
  if (!lines.some(line => line.trim())) return null;
  let shortened = lines.length > CODE_LINES || value.length > TEXT_BUDGET;
  const excerpt = lines.slice(0, CODE_LINES).map(line => {
    let used = 0;
    let visible = '';
    for (const glyph of line) {
      const width = glyph.codePointAt(0) >= 0x2e80 ? 2 : 1;
      if (used + width > CODE_COLS - 1) {
        shortened = true;
        return `${visible}…`;
      }
      used += width;
      visible += glyph;
    }
    return visible;
  });
  return { text: excerpt.join('\n'), shortened };
}

function addCodePanel(slide, { x, color, label, excerpt, fallback, citation }) {
  const y = 2.40;
  const width = 5.89;
  slide.addShape('roundRect', {
    x, y, w: width, h: 2.97, rectRadius: 0.16,
    fill: { color }, line: { color, transparency: 100 }, objectName: `${label} panel`,
  });
  slide.addText(label, {
    x: x + 0.25, y: y + 0.19, w: width - 0.5, h: 0.40, fontSize: 20, bold: true,
    color: PALETTE.text, margin: 0, isTextBox: true, objectName: `${label} heading`,
  });
  slide.addText(excerpt?.text || fallback, {
    x: x + 0.25, y: y + 0.77, w: width - 0.5, h: 1.78,
    fontFace: excerpt ? 'Courier New' : 'Arial', fontSize: 14, color: PALETTE.text,
    margin: 0, valign: 'top', isTextBox: true, fit: 'shrink', objectName: `${label} content`,
  });
  const captions = [citation && prose(citation, excerpt?.shortened ? 52 : 68), excerpt?.shortened && 'Excerpt shortened'].filter(Boolean);
  if (captions.length) slide.addText(captions.join(' · '), {
    x: x + 0.25, y: y + 2.62, w: width - 0.5, h: 0.22, fontSize: 10.5,
    color: PALETTE.caption, isTextBox: true, margin: 0, fit: 'shrink', objectName: `${label} citation`,
  });
}

/** Create an editable slide in memory. Only use evidence and remediation supplied by the saved report. */
async function createFindingPptx({ title, id, severity, location, originalCode, originalCodeSource, fixedCode, impact, remediation, status } = {}) {
  const presentation = new PptxGenJS();
  presentation.layout = 'LAYOUT_WIDE';
  presentation.author = 'Threatlint';
  presentation.title = prose(title, 100) || 'Finding review';
  presentation.subject = 'Finding review one-pager';
  presentation.theme = { headFontFace: 'Arial', bodyFontFace: 'Arial', lang: 'en-US' };
  presentation.defineSlideMaster({ title: 'Finding review', background: { color: PALETTE.white } });
  presentation.addSection({ title: 'Finding review' });
  const slide = presentation.addSlide({ masterName: 'Finding review', sectionTitle: 'Finding review' });

  const reviewStatus = prose(status, 80) || 'Status not supplied';
  const summary = [prose(id, 28), prose(severity, 22), reviewStatus].filter(Boolean).join('  ·  ');
  slide.addText(summary, {
    x: 0.60, y: 0.53, w: 12.12, h: 0.28, fontSize: 12, bold: true,
    color: PALETTE.accent, margin: 0, isTextBox: true, objectName: 'Finding status',
  });
  slide.addText(presentation.title, {
    x: 0.60, y: 0.94, w: 12.12, h: 1.04, fontSize: 36, bold: true, valign: 'mid',
    color: PALETTE.ink, margin: 0, isTextBox: true, fit: 'shrink', objectName: 'Finding title',
  });
  slide.addText(prose(location, 150) || 'Location not recorded', {
    x: 0.60, y: 2.00, w: 12.12, h: 0.26, fontSize: 12,
    color: PALETTE.muted, margin: 0, isTextBox: true, fit: 'shrink', objectName: 'Finding location',
  });

  const before = codeExcerpt(originalCode);
  const after = codeExcerpt(fixedCode);
  const proposedFix = prose(remediation, 330);
  const verified = /\bTRUE POSITIVE\b/i.test(reviewStatus) && /\bCONFIRMED\b/i.test(reviewStatus)
    && !/\b(?:UNVERIFIED|NOT CONFIRMED)\b/i.test(reviewStatus);
  addCodePanel(slide, {
    x: 0.60, color: PALETTE.before, label: verified && before ? 'Vulnerable code' : 'Code under review', excerpt: before,
    fallback: 'The saved report does not include a source excerpt for this finding.', citation: before && originalCodeSource,
  });
  addCodePanel(slide, {
    x: 6.81, color: PALETTE.after, label: after ? 'Proposed fixed code' : 'Proposed fix', excerpt: after,
    fallback: proposedFix || 'The saved report does not include a proposed fix for this finding.',
    citation: after && !after.shortened ? 'Proposed change' : '',
  });

  slide.addText('Impact', {
    x: 0.60, y: 5.70, w: 12.12, h: 0.33, fontSize: 20, bold: true,
    color: PALETTE.ink, margin: 0, isTextBox: true, objectName: 'Impact heading',
  });
  slide.addText(prose(impact, 300) || 'Impact not described in the saved report.', {
    x: 0.60, y: 6.13, w: 12.12, h: 0.84, fontSize: 16, valign: 'top',
    color: PALETTE.ink, margin: 0, isTextBox: true, fit: 'shrink', objectName: 'Impact explanation',
  });
  const file = await presentation.write({ outputType: 'nodebuffer', compression: true });
  const archive = await JSZip.loadAsync(file);
  // Extra directory records are redundant in OOXML and can prevent opening or co-editing online.
  for (const [name, entry] of Object.entries(archive.files)) if (entry.dir) delete archive.files[name];
  return archive.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
}

module.exports = { createFindingPptx };
