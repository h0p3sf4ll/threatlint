'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { retired } = require('../navigation.cjs');
const root = path.resolve(__dirname, '../../marketing');
const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' };
function createPreviewServer() {
  return http.createServer((req, res) => {
    try {
      const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
      const removed = retired.find(item => pathname === `/docs/${item.route}` || pathname.startsWith(`/docs/${item.route}/`));
      if (removed) {
        if (removed.redirect) res.writeHead(301, { Location: removed.redirect }).end();
        else res.writeHead(410, { 'Content-Type': 'text/plain; charset=utf-8' }).end('This page is no longer published. Visit /docs/ for user guides.');
        return;
      }
      let file = path.resolve(root, '.' + pathname);
      if (!file.startsWith(root + path.sep) && file !== root) { res.writeHead(403).end(); return; }
      if (fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
      if (path.basename(file).startsWith('.')) { res.writeHead(404).end(); return; }
      if (pathname.startsWith('/docs/')) {
        const headers = fs.readFileSync(path.join(root, 'docs/.htaccess'), 'utf8');
        const csp = /Content-Security-Policy "([^"]+)"/.exec(headers)?.[1];
        if (csp) res.setHeader('Content-Security-Policy', csp);
      }
      res.setHeader('Content-Type', types[path.extname(file)] || 'application/octet-stream');
      fs.createReadStream(file).pipe(res);
    } catch { res.writeHead(404).end('Not found'); }
  });
}
if (require.main === module) {
  const server = createPreviewServer();
  server.listen(8088, '127.0.0.1', () => console.log('http://127.0.0.1:8088'));
}
module.exports = { createPreviewServer };
