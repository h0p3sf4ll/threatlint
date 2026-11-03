'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const scan = require('../lib/scan-import.cjs');
const { pdfLines } = require('../lib/pdf-text.cjs');
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
    assert.match(finding.remediation, /Strict-Transport-Security/);
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

  it('honours the source hint and refuses PDFs it cannot import faithfully', async () => {
    await assert.rejects(() => scan.parseScanReport(MOBSF, { source: 'invicti' }), /MobSF report, not Invicti/);
    const dashboard = makePdf([page([[40, 20, 'Mob SF RECENT SCANS STATIC ANALYZER DYNAMIC ANALYZER'], [40, 16, 'Showing 1 to 10 of 35 entries']])]);
    await assert.rejects(() => scan.parseScanReport(dashboard), /browser print of the MobSF web page/);
    await assert.rejects(() => scan.parseScanReport(makePdf([page([[40, 12, 'Quarterly newsletter']])])), /not an Invicti Detailed Scan Report or a MobSF PDF report/);
  });
});
