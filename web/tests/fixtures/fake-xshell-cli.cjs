'use strict';
// Stand-in for `threatlint detect-xshell fleet` in tests. Records what it received, then behaves per FAKE_XSHELL_MODE.
const fs = require('node:fs');
const args = process.argv.slice(2);
const value = flag => args[args.indexOf(flag) + 1];
const record = process.env.FAKE_XSHELL_RECORD;
const targets = JSON.parse(fs.readFileSync(value('--targets-file'), 'utf8'));
if (record) fs.writeFileSync(record, JSON.stringify({ args, targets, credentials: process.env.THREATLINT_XSHELL_CREDENTIALS }));
const mode = process.env.FAKE_XSHELL_MODE || 'ok';
const emit = event => process.stderr.write(`${JSON.stringify(event)}\n`);
if (mode === 'hang') { emit({ event: 'plan', total: 3 }); setInterval(() => {}, 1000); return; }
if (mode === 'fail') {
  const token = JSON.parse(process.env.THREATLINT_XSHELL_CREDENTIALS).connections[0].token;
  process.stderr.write(`Traceback: secret source line with ${token}\n`);
  emit({ event: 'error', error: `GitHub rejected credential ${token}` });
  process.exit(2);
}
emit({ event: 'plan', total: 2 });
process.stderr.write('free-form log line that must never be retained\n');
emit({ event: 'target', index: 1, total: 2, provider: 'github', repository: 'acme/web', branch: 'main', status: 'vulnerable' });
emit({ event: 'target', index: 2, total: 2, provider: 'github', repository: 'acme/api', branch: 'main', status: 'clean' });
fs.writeFileSync(value('--output'), JSON.stringify({
  // 'legacy' mimics a CLI built before the detect-xshell rename.
  schema: mode === 'legacy' ? 'threatlint.detect-2shell/v1' : 'threatlint.detect-xshell/v1', generatedAt: '2026-11-28T00:00:00Z',
  summary: { targets: 2, scanned: 2, vulnerable: 1, clean: 1, notApplicable: 0, errors: 0, critical: 1, high: 0, medium: 0 },
  results: [
    { provider: 'github', organization: 'acme', project: null, repository: 'acme/web', branch: 'main', commit: 'a'.repeat(40), status: 'vulnerable',
      findings: [{ id: 'TS-001', advisory: 'next-react2shell', title: 'Next.js App Router remote code execution', severity: 'CRITICAL', confidence: 'CONFIRMED',
        package: 'next', version: '15.1.0', fixedIn: '15.1.9', file: 'package-lock.json', line: 12, cves: ['CVE-2025-66478'], exposure: 'App Router present', remediation: 'Upgrade next' }] },
    { provider: 'github', organization: 'acme', project: null, repository: 'acme/api', branch: 'main', commit: 'b'.repeat(40), status: mode === 'legacy' ? 'vulnerable' : 'clean', findings: mode === 'legacy' ? [{ id: 'TS-002', advisory: 'node2shell-brotli', family: '2Shell', title: 'Node2Shell: Brotli decoder out-of-bounds write', severity: 'CRITICAL', confidence: 'CONFIRMED', package: 'runtime:node', version: '20.18.0', fixedIn: 'no fix on this release line; move to a supported line', fixAvailable: false, file: '.nvmrc', line: 1, cves: ['CVE-2026-111497'], exposure: 'Node.js 20 is end-of-life', remediation: 'Move to Node.js 22.23.4+' }] : [] },
  ],
}));
emit({ event: 'done' });
