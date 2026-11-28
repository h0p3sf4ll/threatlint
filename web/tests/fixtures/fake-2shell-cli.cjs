'use strict';
// Stand-in for `threatlint detect-2shell fleet` in tests. Records what it received, then behaves per FAKE_2SHELL_MODE.
const fs = require('node:fs');
const args = process.argv.slice(2);
const value = flag => args[args.indexOf(flag) + 1];
const record = process.env.FAKE_2SHELL_RECORD;
const targets = JSON.parse(fs.readFileSync(value('--targets-file'), 'utf8'));
if (record) fs.writeFileSync(record, JSON.stringify({ args, targets, credentials: process.env.THREATLINT_2SHELL_CREDENTIALS }));
const mode = process.env.FAKE_2SHELL_MODE || 'ok';
const emit = event => process.stderr.write(`${JSON.stringify(event)}\n`);
if (mode === 'hang') { emit({ event: 'plan', total: 3 }); setInterval(() => {}, 1000); return; }
if (mode === 'fail') {
  const token = JSON.parse(process.env.THREATLINT_2SHELL_CREDENTIALS).connections[0].token;
  process.stderr.write(`Traceback: secret source line with ${token}\n`);
  emit({ event: 'error', error: `GitHub rejected credential ${token}` });
  process.exit(2);
}
emit({ event: 'plan', total: 2 });
process.stderr.write('free-form log line that must never be retained\n');
emit({ event: 'target', index: 1, total: 2, provider: 'github', repository: 'acme/web', branch: 'main', status: 'vulnerable' });
emit({ event: 'target', index: 2, total: 2, provider: 'github', repository: 'acme/api', branch: 'main', status: 'clean' });
fs.writeFileSync(value('--output'), JSON.stringify({
  schema: 'threatlint.detect-2shell/v1', generatedAt: '2026-11-28T00:00:00Z',
  summary: { targets: 2, scanned: 2, vulnerable: 1, clean: 1, notApplicable: 0, errors: 0, critical: 1, high: 0, medium: 0 },
  results: [
    { provider: 'github', organization: 'acme', project: null, repository: 'acme/web', branch: 'main', commit: 'a'.repeat(40), status: 'vulnerable',
      findings: [{ id: 'TS-001', advisory: 'next-react2shell', title: 'Next.js App Router remote code execution', severity: 'CRITICAL', confidence: 'CONFIRMED',
        package: 'next', version: '15.1.0', fixedIn: '15.1.9', file: 'package-lock.json', line: 12, cves: ['CVE-2025-66478'], exposure: 'App Router present', remediation: 'Upgrade next' }] },
    { provider: 'github', organization: 'acme', project: null, repository: 'acme/api', branch: 'main', commit: 'b'.repeat(40), status: 'clean', findings: [] },
  ],
}));
emit({ event: 'done' });
