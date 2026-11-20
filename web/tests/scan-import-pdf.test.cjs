'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const scan = require('../lib/scan-import.cjs');
const { pdfLines, pageLines } = require('../lib/pdf-text.cjs');
const { makePdf, page } = require('./helpers/pdf-fixture.cjs');

// Synthetic Invicti "Detailed Scan Report": one wrapped-title finding with an instance, request, and response.
const INVICTI = makePdf([page([
  [40, 9, '10/20/2026 09:00 AM (UTC)'],
  [40, 18, 'Detailed Scan Report'],
  [40, 9, 'https://shop.example.test/'],
  [40, 9, 'Scan Time : 10/20/2026 08:55 AM'],
  [560, 9, '1/3'],
  [40, 14, '1. HTTP Strict Transport Security (HSTS)'],
  [40, 14, 'Policy Not Enabled'],
  [40, 9, 'MEDIUM 1 CONFIRMED 1'],
  [40, 9, 'The target website lacks an HSTS policy.'],
  [40, 9, 'A browser can use the policy to keep traffic on', 22.5],
  [40, 9, 'secure connections.'],
  [68, 9, '- Review the policy at the edge.'],
  [40, 12, 'Impact'],
  [40, 9, 'Traffic can be downgraded to HTTP.'],
  [40, 12, 'Vulnerabilities'],
  [40, 9, '1.1. https://shop.example.test/account'],
  [40, 9, 'CONFIRMED'],
  [40, 9, 'Request Response'],
  [40, 9, 'Request'],
  [40, 9, 'GET /account HTTP/1.1'],
  [40, 9, 'Host: shop.example.test'],
  [40, 9, 'Cookie: session=abcdef0123456789abcdef'],
  [40, 9, 'Response'],
  [40, 9, 'Response Time (ms) : 12'],
  [40, 9, 'HTTP/1.1 200 OK'],
  [40, 9, 'Content-Type: text/html'],
  [40, 12, 'Remedy'],
  [40, 9, 'Send a Strict-Transport-Security header.'],
  [40, 12, 'CLASSIFICATION'],
  [40, 9, 'CWE 523'],
  [40, 9, 'OWASP 2021 A05'],
])]);

// Synthetic MobSF iOS report: 22pt headings, a 12pt table header, 9pt cells with wrapped lines inside rows.
const cells = (gap, ...columns) => [0, 9, columns, gap];
const MOBSF = makePdf([page([
  [40, 27, 'IOS STATIC ANALYSIS REPORT'],
  [40, 12, 'App Name: Example Demo'],
  [40, 12, 'Identifier: test.example.demo'],
  [40, 12, 'Version: 2.4.1'],
  [40, 12, 'Scan Date: Oct. 22, 2026, 5:11 p.m.'],
  [68, 22, 'IPA BINARY CODE ANALYSIS', 40],
  [0, 12, [[50, 'NO'], [88, 'ISSUE'], [205, 'SEVERITY'], [275, 'STANDARDS'], [392, 'DESCRIPTION']], 40],
  cells(34, [275, 'CWE: CWE-676 - Use of']),
  cells(13, [275, 'Potentially Dangerous Function']),
  cells(7, [50, '1'], [88, 'Binary makes use of'], [205, 'high'], [392, 'The binary may contain insecure APIs.']),
  cells(7, [88, 'insecure API(s)'], [275, 'OWASP MASVS: MSTG-']),
  cells(13, [275, 'CODE-8']),
  cells(32, [275, 'CWE: CWE-532 Insertion of Sensitive']),
  cells(7, [50, '2'], [88, 'Binary makes use of Logging function'], [205, 'info'], [392, 'The binary may use NSLog.']),
  cells(13, [275, 'OWASP MASVS: MSTG-STORAGE-3']),
  [68, 22, 'IPA BINARY ANALYSIS', 40],
  [0, 12, [[50, 'PROTECTION'], [142, 'STATUS'], [203, 'SEVERITY'], [273, 'DESCRIPTION']], 40],
  cells(34, [50, 'NX'], [142, 'True'], [203, 'info'], [273, 'The binary has NX bit set.']),
  cells(32, [50, 'ENCRYPTED'], [142, 'False'], [203, 'warning'], [273, 'This binary is not encrypted.']),
])]);

describe('PDF scan reports', () => {
  it('rebuilds positioned lines in reading order', async () => {
    const lines = await pdfLines(INVICTI);
    assert.equal(lines[1].text, 'Detailed Scan Report');
    assert.ok(lines.every(line => line.page === 1 && line.size > 0 && line.parts.length));
  });

  it('joins touching fi ligatures while retaining word spaces and table columns', () => {
    const run = (str, x, y, width) => ({ str, width, transform: [9, 0, 0, 9, x, y] });
    const [sentence, table] = pageLines([
      run('The scanner identi', 40, 700, 80.04), run('fi', 120, 700, 5.08), run('ed the header', 125, 700, 52),
      run(' ', 177, 700, 0.5), run('fi', 177.5, 700, 5), run('eld.', 182.5, 700, 14),
      run('Use the word ', 40, 686, 55), run('fi', 95, 686, 5), run('again', 102, 686, 20), run('High', 270, 686, 18),
    ]);
    assert.equal(sentence.text, 'The scanner identified the header field.');
    assert.equal(table.text, 'Use the word fi again High');
    assert.deepEqual(table.parts.map(part => part.x), [40, 95, 102, 270]);
  });

  it('parses an Invicti Detailed Scan Report PDF like the exports, with redaction', async () => {
    const parsed = await scan.parseScanReport(INVICTI);
    assert.equal(parsed.source, 'invicti'); assert.equal(parsed.format, 'pdf');
    assert.equal(parsed.target, 'https://shop.example.test/'); assert.equal(parsed.scanDate, '2026-10-20');
    const [finding] = parsed.findings;
    assert.equal(parsed.findings.length, 1);
    assert.equal(finding.title, 'HTTP Strict Transport Security (HSTS) Policy Not Enabled');
    assert.equal(finding.severity, 'MEDIUM'); assert.equal(finding.originalId, '1.1'); assert.ok(finding.confirmed);
    assert.equal(finding.url, 'https://shop.example.test/account'); assert.equal(finding.method, 'GET'); assert.equal(finding.cwe, 'CWE-523');
    assert.match(finding.description, /lacks an HSTS policy[\s\S]*Impact:[\s\S]*downgraded/);
    assert.match(finding.description, /policy\.\nA browser can use the policy to keep traffic on secure connections\.\n- Review the policy at the edge\./);
    assert.match(finding.remediation, /Strict-Transport-Security/);
    assert.match(finding.request, /^GET \/account HTTP\/1\.1\nHost: shop\.example\.test\nCookie:/);
    assert.match(finding.response, /^HTTP\/1\.1 200 OK\nContent-Type: text\/html/);
    assert.ok(!finding.request.includes('abcdef0123456789abcdef'), 'cookie values are redacted');
    assert.ok(!/Response Time/.test(finding.response));
  });

  it('parses a MobSF PDF report table by columns and rows, dropping passing checks', async () => {
    const parsed = await scan.parseScanReport(MOBSF);
    assert.equal(parsed.source, 'mobsf'); assert.equal(parsed.format, 'pdf');
    assert.equal(parsed.target, 'Example Demo 2.4.1 (test.example.demo)'); assert.equal(parsed.app.platform, 'iOS'); assert.equal(parsed.scanDate, '2026-10-22');
    const byRule = Object.fromEntries(parsed.findings.map(finding => [finding.rule, finding]));
    assert.deepEqual(Object.keys(byRule).sort(), ['binary:binarymakesuseofinsecureapis', 'binary:binarymakesuseofloggingfunction', 'binary:encrypted']);
    const insecure = byRule['binary:binarymakesuseofinsecureapis'];
    assert.equal(insecure.title, 'Binary makes use of insecure API(s)');
    assert.equal(insecure.severity, 'HIGH'); assert.equal(insecure.cwe, 'CWE-676'); assert.equal(insecure.masvs, 'MSTG-CODE-8');
    assert.equal(byRule['binary:encrypted'].severity, 'MEDIUM');
  });

  it('keeps closely spaced MobSF Android findings and their page continuations', async () => {
    const header = [0, 10.5, [[29, 'NO'], [74, 'ISSUE'], [310, 'SEVERITY'], [400, 'DESCRIPTION']]];
    const androidRow = (gap, ...columns) => [0, 9.5, columns, gap];
    const report = makePdf([
      page([
        [40, 19, 'ANDROID STATIC ANALYSIS REPORT'],
        [40, 11, 'App Name: Example Android App'],
        [40, 11, 'Package Name: test.example.android'],
        [40, 11, 'Android Version Name: 2.4.1'],
        [40, 11, 'Trackers Detection: 2/15'],
        [0, 15, [[25, '@'], [44, 'APPLICATION PERMISSIONS']]],
        [0, 10.5, [[29, 'PERMISSION'], [310, 'STATUS'], [400, 'DESCRIPTION']]],
        androidRow(20.1, [29, 'android.permission.READ_'], [310, 'dangerous'], [400, 'Read a device resource.']),
        androidRow(12.6, [29, 'CONTACTS']),
        [0, 15, [[25, '@'], [44, 'MANIFEST ANALYSIS']]],
        header,
        androidRow(20.1, [29, '1'], [74, 'Debugging is enabled'], [310, 'warning'], [400, 'Debugging was enabled in the manifest.']),
        androidRow(20.1, [29, '2'], [74, 'Backups are permitted'], [310, 'warning'], [400, 'App data can be included in backups.']),
        androidRow(12.6, [400, 'Review the backup configuration.']),
      ]),
      page([
        header,
        androidRow(12.6, [400, 'Verify which files are eligible for backup.']),
        androidRow(20.1, [29, '3'], [74, 'Cleartext is permitted'], [310, 'warning'], [400, 'The manifest permits cleartext traffic.']),
        [0, 15, [[25, '@'], [44, 'DOMAIN MALWARE CHECK']]],
        [0, 10.5, [[29, 'DOMAIN'], [310, 'STATUS'], [400, 'GEOLOCATION']]],
        androidRow(20.1, [29, 'example.test'], [310, 'ok'], [400, 'Unknown location']),
        [0, 15, [[25, '@'], [44, 'HARDCODED SECRETS']]],
        [29, 10.5, 'POSSIBLE SECRETS'],
        androidRow(20.1, [29, 'synthetic-secret-fixture-value']),
      ]),
    ]);
    const parsed = await scan.parseScanReport(report);
    assert.equal(parsed.source, 'mobsf');
    assert.equal(parsed.app.platform, 'Android');
    assert.equal(parsed.app.version, '2.4.1');
    assert.deepEqual(parsed.findings.map(({ title, severity }) => ({ title, severity })), [
      { title: 'Debugging is enabled', severity: 'MEDIUM' },
      { title: 'Backups are permitted', severity: 'MEDIUM' },
      { title: 'Cleartext is permitted', severity: 'MEDIUM' },
      { title: 'Dangerous permission: android.permission.READ_CONTACTS', severity: 'LOW' },
      { title: 'Privacy trackers detected', severity: 'INFO' },
      { title: 'Possible hardcoded secrets', severity: 'INFO' },
    ]);
    assert.ok(parsed.findings.slice(0, 3).every(finding => finding.rule.startsWith('manifest:')));
    assert.match(parsed.findings[1].description, /Review the backup configuration\. Verify which files are eligible for backup\./);
    assert.doesNotMatch(parsed.findings[2].description, /files are eligible for backup/);
    assert.equal(parsed.findings[4].scannerSeverity, 'not stated');
    assert.match(parsed.findings[4].description, /2 detected tracker/);
    assert.equal(parsed.findings[5].scannerSeverity, 'not stated');
    assert.equal(parsed.findings[5].location, 'PDF page 2');
    assert.doesNotMatch(JSON.stringify(parsed), /synthetic-secret-fixture-value/);
  });

  it('extracts page evidence from a scanner-neutral PDF finding block', async () => {
    const report = makePdf([
      page([[40, 18, 'Detailed Scan Report'], [40, 10, 'Target: portal.example.test']]),
      page([
        [40, 14, 'Finding: Missing transport policy'],
        [40, 10, 'Severity: High'],
        [40, 10, 'Description: The deployment does not declare'],
        [40, 10, 'a transport policy.'],
        [40, 10, 'Evidence: GET /account HTTP/1.1'],
        [40, 10, 'Cookie: session=synthetic-cookie-value'],
        [40, 10, 'Affected file: config/web.conf:17'],
        [40, 10, 'CWE: CWE-319'],
        [40, 10, 'Remediation: Declare the transport policy in the web configuration.'],
      ]),
    ]);
    const parsed = await scan.parseScanReport(report);
    assert.equal(parsed.source, 'generic');
    assert.equal(parsed.format, 'pdf');
    assert.equal(parsed.findings.length, 1);
    const [finding] = parsed.findings;
    assert.equal(finding.title, 'Missing transport policy');
    assert.equal(finding.severity, 'HIGH');
    assert.equal(finding.cwe, 'CWE-319');
    assert.match(finding.description, /does not declare a transport policy\./);
    assert.match(finding.description, /GET \/account HTTP\/1\.1\nCookie: session=<redacted:/);
    assert.doesNotMatch(finding.description, /synthetic-cookie-value/);
    assert.match(finding.remediation, /Declare the transport policy/);
    assert.match(finding.location, /config\/web\.conf:17/);
    assert.match(`${finding.location}\n${finding.description}`, /page 2/i);
  });

  it('extracts findings from a scanner-neutral severity table', async () => {
    const report = makePdf([page([
      [40, 18, 'Infrastructure security review'],
      [0, 12, [[40, 'Finding'], [270, 'Severity'], [360, 'Description']]],
      cells(22, [40, 'Verbose error messages'], [270, 'Low'], [360, 'Debugging details are visible.']),
      cells(22, [40, 'Missing backup encryption'], [270, 'High'], [360, 'Encryption is disabled.']),
    ])]);
    const parsed = await scan.parseScanReport(report);
    assert.deepEqual(parsed.findings.map(({ id, title, severity }) => ({ id, title, severity })), [
      { id: 'FP-001', title: 'Missing backup encryption', severity: 'HIGH' },
      { id: 'FP-002', title: 'Verbose error messages', severity: 'LOW' },
    ]);
  });

  it('honours the source hint and refuses PDFs it cannot import faithfully', async () => {
    await assert.rejects(() => scan.parseScanReport(MOBSF, { source: 'invicti' }), /does not match the selected scanner.*Auto-detect/);
    const dashboard = makePdf([page([[40, 20, 'Mob SF RECENT SCANS STATIC ANALYZER DYNAMIC ANALYZER'], [40, 16, 'Showing 1 to 10 of 35 entries']])]);
    await assert.rejects(() => scan.parseScanReport(dashboard), /browser printout of a paginated results page/);
    const newsletter = makePdf([page([[40, 12, 'Title: Quarterly newsletter'], [40, 12, 'Description: A recap of this quarter.'], [40, 12, 'HIGH: 18']])]);
    await assert.rejects(() => scan.parseScanReport(newsletter), /could not identify individual findings/i);
    await assert.rejects(() => scan.parseScanReport(makePdf([[]])), /OCR/i);
  });
});
