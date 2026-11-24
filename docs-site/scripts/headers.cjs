'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const output = path.resolve(__dirname, '../../marketing/docs');
const hashes = new Set();
for (const file of fs.readdirSync(output, { recursive: true }).filter(file => file.endsWith('.html'))) {
  const html = fs.readFileSync(path.join(output, file), 'utf8');
  for (const match of html.matchAll(/<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)) {
    if (match[1].trim()) hashes.add(`'sha256-${crypto.createHash('sha256').update(match[1]).digest('base64')}'`);
  }
}
fs.writeFileSync(path.join(output, '.htaccess'), `DirectoryIndex index.html\nOptions -Indexes\n<IfModule mod_headers.c>\nHeader always set Content-Security-Policy "default-src 'self'; script-src 'self' ${[...hashes].join(' ')}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"\n</IfModule>\n`);
