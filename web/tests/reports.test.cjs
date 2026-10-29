'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { parseReport } = require('../lib/reports.cjs');

describe('Production report parser', () => {
  it('retains complete fixes and regression fixtures, ignoring headings inside code fences', () => {
    const parsed = parseReport(fs.readFileSync(path.join(__dirname, '../examples/fp-review.md'), 'utf8'), 'appsec-fp-reviewer');
    assert.equal(parsed.findings.length, 2);
    assert.equal(parsed.findings[0].disposition, 'TRUE POSITIVE');
    assert.equal(parsed.findings[0].severity, 'HIGH');
    assert.match(parsed.findings[0].body, /PROPOSED — NOT APPLIED/);
    assert.match(parsed.findings[0].body, /Acceptance Criteria/);
    assert.match(parsed.findings[1].body, /# ruleid: example.sql-query-construction/);
    assert.match(parsed.findings[1].body, /Approval and Rollback/);
    assert.doesNotMatch(parsed.findings[1].body, /TIER 3/);
    assert.deepEqual(parsed.quality.issues, []);
  });
  it('accepts a URL or file Location as evidence for runtime and mobile findings, but still flags none', () => {
    const report = (location) => `#### [FP-001] — Header\n**Severity**: INFO\n**Confidence**: CONFIRMED\n**Evidence**:\n\n${location}\n`;
    assert.deepEqual(parseReport(report('- Location: `https://shop.example.test/`')).quality.issues, []);
    assert.deepEqual(parseReport(report('- Location: `AndroidManifest.xml`')).quality.issues, []);
    assert.deepEqual(parseReport(report('No location.')).quality.issues, ['FP-001: no path:line evidence was detected.']);
  });
  it('does not interpret code-fenced finding headers as actual findings', () => {
    const report = '## Executive Summary\nNo material findings.\n```md\n#### [FP-999] — example\n```';
    assert.equal(parseReport(report).findings.length, 0);
  });
  it('supports both common bold-field conventions and table fields', () => {
    const report = '#### [CR-001] — Query boundary\n**Severity:** HIGH\n**Confidence**: PLAUSIBLE\n| Evidence | src/query.js:21 |\n| Mitigation | Bind values |';
    const finding = parseReport(report).findings[0];
    assert.equal(finding.severity, 'HIGH');
    assert.equal(finding.confidence, 'PLAUSIBLE');
    assert.deepEqual(finding.evidence, ['src/query.js:21']);
  });
  it('warns about missing evidence and fix criteria without rewriting the report', () => {
    const report = '#### [FP-001] — Unsubstantiated\n**Disposition**: TRUE POSITIVE\n**Severity**: HIGH';
    const parsed = parseReport(report, 'appsec-fp-reviewer');
    assert.equal(parsed.markdown, report);
    assert.equal(parsed.quality.status, 'needs-review');
    assert.ok(parsed.quality.issues.some(issue => issue.includes('evidence')));
    assert.ok(parsed.quality.issues.some(issue => issue.includes('remediation')));
  });
  it('flags duplicate IDs and never invents evidence or a clean security verdict', () => {
    const parsed = parseReport('#### [TM-001] — First\nbody\n#### [TM-001] — Second\nbody');
    assert.ok(parsed.quality.issues.some(issue => issue.includes('Duplicate')));
    assert.deepEqual(parsed.findings[0].evidence, []);
    assert.equal(parsed.findings[0].severity, 'UNSPECIFIED');
  });
});