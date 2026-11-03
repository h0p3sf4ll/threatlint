'use strict';

/**
 * Builds a small, valid PDF from positioned text so PDF-import tests are self-describing (no binary fixtures and
 * no real scan reports). pages: [[{ x, y, size, text }, ...], ...]; x/y in points from the bottom-left (US Letter).
 * One text item per entry, Helvetica, ASCII only.
 */

const escape = text => String(text).replace(/[\\()]/g, match => `\\${match}`);

function makePdf(pages) {
  const objects = [];
  const add = body => { objects.push(body); return objects.length; };
  const catalog = add(null), pagesId = add(null), font = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
  const kids = pages.map(items => {
    const stream = items.map(({ x, y, size = 9, text }) => `BT /F1 ${size} Tf 1 0 0 1 ${x} ${y} Tm (${escape(text)}) Tj ET`).join('\n');
    const content = add(`<< /Length ${Buffer.byteLength(stream, 'latin1')} >>\nstream\n${stream}\nendstream`);
    return add(`<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 ${font} 0 R >> >> /Contents ${content} 0 R >>`);
  });
  objects[catalog - 1] = `<< /Type /Catalog /Pages ${pagesId} 0 R >>`;
  objects[pagesId - 1] = `<< /Type /Pages /Kids [${kids.map(id => `${id} 0 R`).join(' ')}] /Count ${kids.length} >>`;
  let pdf = '%PDF-1.4\n';
  const offsets = objects.map((body, index) => { const offset = Buffer.byteLength(pdf, 'latin1'); pdf += `${index + 1} 0 obj\n${body}\nendobj\n`; return offset; });
  const xref = Buffer.byteLength(pdf, 'latin1');
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.map(offset => `${String(offset).padStart(10, '0')} 00000 n \n`).join('')}`;
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root ${catalog} 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(pdf, 'latin1');
}

/** Lines laid out top-down: [[x, size, text, gapBefore = size * 1.5], ...] on one page. */
function page(rows, top = 760) {
  let y = top;
  return rows.flatMap(([x, size, text, gap]) => {
    y -= gap ?? size * 1.5;
    return (Array.isArray(text) ? text : [[x, text]]).map(([column, value]) => ({ x: column, y, size, text: value }));
  });
}

module.exports = { makePdf, page };
