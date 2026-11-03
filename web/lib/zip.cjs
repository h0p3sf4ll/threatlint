'use strict';

/**
 * Minimal, read-only ZIP reader for Office documents (.docx, .pptx, .vsdx): lists entries and inflates the ones asked
 * for. Untrusted input, so: stored and deflate entries only, no paths are written anywhere, and every entry and the
 * total inflated size are capped (zip-bomb guard).
 */

const zlib = require('node:zlib');

const EOCD = 0x06054b50, CENTRAL = 0x02014b50, LOCAL = 0x04034b50;
const MAX_ENTRY = 32 * 1024 * 1024;
const MAX_ENTRIES = 5000;

class ZipError extends Error {}

function endOfCentralDirectory(buffer) {
  for (let offset = buffer.length - 22; offset >= Math.max(0, buffer.length - 22 - 0xffff); offset -= 1) {
    if (buffer.readUInt32LE(offset) === EOCD) return offset;
  }
  throw new ZipError('not a ZIP archive');
}

/** [{ name, method, compressedSize, size, localOffset }] from the central directory. */
function entries(buffer) {
  const end = endOfCentralDirectory(buffer);
  const count = buffer.readUInt16LE(end + 10);
  if (count > MAX_ENTRIES) throw new ZipError('too many entries');
  let offset = buffer.readUInt32LE(end + 16);
  const found = [];
  for (let index = 0; index < count; index += 1) {
    if (offset + 46 > buffer.length || buffer.readUInt32LE(offset) !== CENTRAL) throw new ZipError('corrupt central directory');
    const nameLength = buffer.readUInt16LE(offset + 28), extra = buffer.readUInt16LE(offset + 30), comment = buffer.readUInt16LE(offset + 32);
    found.push({ name: buffer.toString('utf8', offset + 46, offset + 46 + nameLength), method: buffer.readUInt16LE(offset + 10),
      compressedSize: buffer.readUInt32LE(offset + 20), size: buffer.readUInt32LE(offset + 24), localOffset: buffer.readUInt32LE(offset + 42) });
    offset += 46 + nameLength + extra + comment;
  }
  return found;
}

/** The inflated bytes of one entry. */
function read(buffer, entry) {
  if (entry.size > MAX_ENTRY) throw new ZipError(`${entry.name} is too large`);
  const at = entry.localOffset;
  if (at + 30 > buffer.length || buffer.readUInt32LE(at) !== LOCAL) throw new ZipError('corrupt local header');
  const start = at + 30 + buffer.readUInt16LE(at + 26) + buffer.readUInt16LE(at + 28);
  const data = buffer.subarray(start, start + entry.compressedSize);
  if (entry.method === 0) return data;
  if (entry.method === 8) return zlib.inflateRawSync(data, { maxOutputLength: MAX_ENTRY });
  throw new ZipError(`${entry.name} uses an unsupported compression method`);
}

/** Text of every entry whose name matches `pattern`, in archive order, within a total budget. */
function readMatching(buffer, pattern, { maxTotal = 64 * 1024 * 1024 } = {}) {
  let total = 0;
  return entries(buffer).filter(entry => pattern.test(entry.name)).map(entry => {
    total += entry.size;
    if (total > maxTotal) throw new ZipError('the archive inflates beyond the size limit');
    return { name: entry.name, text: read(buffer, entry).toString('utf8') };
  });
}

module.exports = { entries, read, readMatching, ZipError };
