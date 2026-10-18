'use strict';
/** Generate reproducible PNG/ICNS/ICO build assets without network access or native tools. */
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const target = path.join(__dirname, '../build-assets');
fs.mkdirSync(target, { recursive: true });

function crc32(buffer) {
  let value = 0xffffffff;
  for (const byte of buffer) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit++) value = (value >>> 1) ^ ((value & 1) ? 0xedb88320 : 0);
  }
  return (value ^ 0xffffffff) >>> 0;
}
function chunk(name, data) {
  const type = Buffer.from(name), length = Buffer.alloc(4), crc = Buffer.alloc(4);
  length.writeUInt32BE(data.length); crc.writeUInt32BE(crc32(Buffer.concat([type, data])));
  return Buffer.concat([length, type, data, crc]);
}
function polygon(x, y, points) {
  let inside = false;
  for (let i = 0, previous = points.length - 1; i < points.length; previous = i++) {
    const [ax, ay] = points[i], [bx, by] = points[previous];
    if ((ay > y) !== (by > y) && x < (bx - ax) * (y - ay) / (by - ay) + ax) inside = !inside;
  }
  return inside;
}
function segmentDistance(x, y, a, b) {
  const dx = b[0] - a[0], dy = b[1] - a[1];
  const t = Math.max(0, Math.min(1, ((x - a[0]) * dx + (y - a[1]) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(x - a[0] - t * dx, y - a[1] - t * dy);
}
const shield = [[.5, .16], [.77, .26], [.77, .48], [.73, .62], [.64, .73], [.5, .84], [.36, .73], [.27, .62], [.23, .48], [.23, .26]];
const lines = [[[.34, .36], [.66, .36]], [[.5, .36], [.5, .65]], [[.4, .53], [.5, .65]], [[.5, .65], [.65, .44]]];
function color(x, y) {
  const radius = .18, qx = Math.max(Math.abs(x - .5) - (.45 - radius), 0), qy = Math.max(Math.abs(y - .5) - (.45 - radius), 0);
  if (Math.hypot(qx, qy) > radius) return [0, 0, 0, 0];
  let rgb = [17 + 12 * (1 - y), 29 + 16 * (1 - y), 26 + 11 * (1 - y)];
  if (polygon(x, y, shield)) rgb = [30, 62, 49];
  const edges = shield.map((point, index) => [point, shield[(index + 1) % shield.length]]);
  if (edges.some(([a, b]) => segmentDistance(x, y, a, b) < .008) || lines.some(([a, b]) => segmentDistance(x, y, a, b) < .014)) rgb = [145, 231, 195];
  return [...rgb, 255];
}
function png(size) {
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    const samples = [[.25, .25], [.75, .25], [.25, .75], [.75, .75]].map(([dx, dy]) => color((x + dx) / size, (y + dy) / size));
    for (let channel = 0; channel < 4; channel++) raw[y * (size * 4 + 1) + 1 + x * 4 + channel] = Math.round(samples.reduce((sum, sample) => sum + sample[channel], 0) / 4);
  }
  const header = Buffer.alloc(13); header.writeUInt32BE(size); header.writeUInt32BE(size, 4); header[8] = 8; header[9] = 6;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', header), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}
const images = new Map([16, 32, 64, 128, 256, 512, 1024].map(size => [size, png(size)]));
fs.writeFileSync(path.join(target, 'icon.png'), images.get(1024));
const iconTypes = [[16, 'icp4'], [32, 'icp5'], [64, 'icp6'], [128, 'ic07'], [256, 'ic08'], [512, 'ic09'], [1024, 'ic10']];
const resources = iconTypes.map(([size, name]) => { const data = images.get(size), length = Buffer.alloc(4); length.writeUInt32BE(data.length + 8); return Buffer.concat([Buffer.from(name), length, data]); });
const icnsLength = Buffer.alloc(4); icnsLength.writeUInt32BE(8 + resources.reduce((sum, resource) => sum + resource.length, 0));
fs.writeFileSync(path.join(target, 'icon.icns'), Buffer.concat([Buffer.from('icns'), icnsLength, ...resources]));
const png256 = images.get(256), icoHeader = Buffer.alloc(22); icoHeader.writeUInt16LE(1, 2); icoHeader.writeUInt16LE(1, 4); icoHeader.writeUInt16LE(1, 10); icoHeader.writeUInt16LE(32, 12); icoHeader.writeUInt32LE(png256.length, 14); icoHeader.writeUInt32LE(22, 18);
fs.writeFileSync(path.join(target, 'icon.ico'), Buffer.concat([icoHeader, png256]));
console.log('Generated Threatlint desktop icons (PNG, ICNS, ICO).');