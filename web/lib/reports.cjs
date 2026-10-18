'use strict';

const crypto = require('node:crypto');

function plain(text) { return text.replaceAll(/[*_`]/g, '').trim(); }

function field(body, name) {
  const names = new Set(name.toLowerCase().split('|'));
  for (const raw of body.split('\n')) {
    const line = plain(raw);
    const colon = line.indexOf(':');
    if (colon > 0 && names.has(line.slice(0, colon).trim().toLowerCase())) return line.slice(colon + 1).trim();
    if (line.startsWith('|')) {
      const cells = line.split('|').map(cell => cell.trim());
      if (names.has(cells[1]?.toLowerCase())) return cells[2] || '';
    }
  }
  return '';
}

function scanHeadings(text) {
  const headings = [];
  let fence = null;
  let offset = 0;
  for (const line of text.split('\n')) {
    const marker = /^\s*(`{3,}|~{3,})/.exec(line);
    if (marker) {
      if (!fence) fence = marker[1];
      else if (marker[1].startsWith(fence)) fence = null;
    } else if (!fence && line.startsWith('#')) {
      const match = /^(#{1,6})[ \t]/.exec(line);
      if (match) headings.push({ level: match[1].length, title: line.slice(match[0].length).trim(), offset, after: offset + line.length + 1 });
    }
    offset += line.length + 1;
  }
  return headings;
}

function evidenceLocations(body) {
  const locations = new Set();
  for (const token of body.split(/[\s`|<>"'()[\]]+/)) {
    let candidate = token;
    while (candidate.endsWith(',') || candidate.endsWith(';')) candidate = candidate.slice(0, -1);
    if (candidate.length > 500) continue;
    const match = /^([\w.@/-]+\.[a-zA-Z0-9]+):(\d+)(?:[-–](\d+))?$/.exec(candidate);
    if (match) locations.add(candidate);
  }
  return [...locations];
}

function findingFromHeading(heading, text, headings, agentId) {
  const match = /^\[([A-Z][A-Z0-9]*-\d+)\]/.exec(heading.title);
  if (!match) return null;
  const following = headings.find(next => next.offset > heading.offset && (
    /^\[[A-Z][A-Z0-9]*-\d+\]/.test(next.title) || next.level <= 2 ||
    (next.level === 3 && /^(?:TIER\s+[123]|Suppression Impact Assessment|(?:Prioritized )?Remediation Roadmap|Patterns and Systemic|Residual Risk|Security-Positive Changes)/i.test(next.title))
  ));
  const body = text.slice(heading.after, following?.offset ?? text.length).trim();
  const severity = /\b(CRITICAL|HIGH|MEDIUM|LOW|INFO(?:RMATIONAL)?)\b/i.exec(field(body, 'Severity'))?.[1]?.toUpperCase().replace('INFORMATIONAL', 'INFO') || 'UNSPECIFIED';
  const confidence = /\b(CONFIRMED|PLAUSIBLE|THEORETICAL)\b/i.exec(field(body, 'Confidence'))?.[1]?.toUpperCase() || 'UNSPECIFIED';
  const disposition = /TRUE POSITIVE|FALSE POSITIVE|AMBIGUOUS|PARTIALLY FIXED|STILL PRESENT|REMEDIATED|REGRESSED|RESOLVED|NEW|CANT ASSESS/i.exec(field(body, 'Disposition|Verdict'))?.[0]?.toUpperCase() || '';
  const evidence = evidenceLocations(body);
  const title = plain(heading.title.slice(match[0].length).trim().replace(/^[—–:-][ \t]*/, ''));
  const id = match[1];
  return { id, title, severity, confidence, disposition, evidence, body,
    fingerprint: crypto.createHash('sha256').update(`${agentId}|${id}|${title}|${evidence.join('|')}`).digest('hex').slice(0, 20) };
}

function findingIssues(finding, agentId) {
  const issues = [];
  const add = message => issues.push(`${finding.id}: ${message}`);
  if (!finding.evidence.length) add('no path:line evidence was detected.');
  if (finding.severity === 'UNSPECIFIED') add('severity was not explicitly reported.');
  if (finding.confidence === 'UNSPECIFIED') add('confidence was not explicitly reported.');
  const actionable = finding.disposition === 'TRUE POSITIVE' || (!finding.disposition && !['INFO', 'UNSPECIFIED'].includes(finding.severity));
  if (actionable && !/proposed fix|remediation|mitigation/i.test(finding.body)) add('proposed remediation was not detected.');
  if (agentId !== 'appsec-fp-reviewer') return issues;
  if (!finding.disposition) add('a triage disposition is missing.');
  if (finding.disposition === 'TRUE POSITIVE' && !/acceptance|regression/i.test(finding.body)) add('acceptance or regression criteria were not detected.');
  if (finding.disposition === 'FALSE POSITIVE' && !/blast radius|coverage|exact rule required/i.test(finding.body)) add('suppression impact needs review.');
  if (finding.disposition === 'AMBIGUOUS' && !/blocking|resolution plan|evidence gap/i.test(finding.body)) add('the blocking evidence or resolution plan is missing.');
  return issues;
}

function parseReport(markdown, agentId = '') {
  const text = String(markdown || '').replaceAll('\r\n', '\n');
  const headings = scanHeadings(text);
  const findings = headings.map(heading => findingFromHeading(heading, text, headings, agentId)).filter(Boolean);
  const executive = headings.find(heading => /^TIER\s*1\b|^EXECUTIVE SUMMARY/i.test(heading.title));
  const nextTier = executive && headings.find(heading => heading.offset > executive.offset && heading.level <= executive.level);
  const firstFinding = headings.find(heading => /^\[[A-Z]/.test(heading.title));
  const summary = (executive ? text.slice(executive.offset, nextTier?.offset ?? text.length) : text.slice(0, firstFinding?.offset ?? 3000)).slice(0, 8000);
  const issues = findings.flatMap(finding => findingIssues(finding, agentId));
  if (!text.trim()) issues.unshift('The agent returned an empty report.');
  if (text.trim() && !findings.length && !/no (?:material |actionable |security )?findings|zero findings|no (?:material )?security (?:regressions|issues|threats)/i.test(text)) issues.push('No structured findings or explicit no-findings conclusion was detected; review the complete report.');
  if (new Set(findings.map(finding => finding.id)).size !== findings.length) issues.push('Duplicate finding IDs need review.');
  return { markdown: text, summary, findings, quality: { status: issues.length ? 'needs-review' : 'format-checked', issues,
    note: 'Automated format checks only. Evidence, proposed fixes, and scanner coverage require human verification.' } };
}

module.exports = { parseReport, field, scanHeadings, evidenceLocations };