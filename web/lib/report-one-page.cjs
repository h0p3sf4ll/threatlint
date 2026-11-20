'use strict';

const { evidenceLocations, field } = require('./reports.cjs');
const { structure } = require('./finding-disposition.cjs');

const SEVERITY = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNSPECIFIED'];
const SECTION_LABEL = /^ {0,3}(?:#{1,6}[ \t]+([^\n#]+?)\s*#*\s*$|(?:[-*+][ \t]+)?\*\*([^*:]+?):\*\*[ \t]*(.*)$|(?:[-*+][ \t]+)?\*\*([^*]+?)\*\*(?:[ \t]*:[ \t]*(.*)|[ \t]*)$)/;
const CODE_FENCE = /^ {0,3}(`{3,}|~{3,})([^\n]*)$/;
const NON_SOURCE = /^(?:http|https|har|console|output|log|shell|shell-session|bash|sh|zsh|cmd|batch|powershell|pwsh)(?:\s|$)/i;

function sections(body) {
  const markers = [];
  let offset = 0;
  for (const line of structure(body).split('\n')) {
    const match = SECTION_LABEL.exec(line);
    if (match) {
      const label = (match[1] || match[2] || match[4]).trim().toLowerCase().replace(/:$/, '');
      const bareBold = match[4] && match[5] === undefined;
      if (!bareBold || /^(?:before\b|after\b|(?:vulnerable|original|fixed|proposed fixed) code$|evidence$|(?:finding and )?impact$|proposed fix$)/.test(label)) {
        markers.push({ label, inline: match[3] || match[5] || '', offset, after: offset + line.length + 1 });
      }
    }
    offset += line.length + 1;
  }
  return markers.map((marker, index) => ({ ...marker, text: body.slice(marker.after, markers[index + 1]?.offset) }));
}

function codeBlocks(section) {
  const blocks = [];
  let current;
  for (const line of section?.text?.split('\n') || []) {
    const fence = CODE_FENCE.exec(line);
    if (!current && fence) current = { marker: fence[1], language: fence[2].trim().toLowerCase(), lines: [] };
    else if (current && fence?.[1].startsWith(current.marker) && !fence[2].trim()) {
      if (current.lines.some(line => line.trim())) blocks.push({ language: current.language, lines: current.lines });
      current = null;
    } else if (current) current.lines.push(line);
  }
  return blocks;
}

function excerpt(section, { requireLanguage = false } = {}) {
  const block = codeBlocks(section).find(({ language }) => !NON_SOURCE.test(language) && language !== 'diff'
    && (!requireLanguage || (language && language !== 'text' && language !== 'plaintext')));
  return block?.lines.join('\n') || '';
}

/** Use one changed hunk so the comparison never stitches unrelated files together. */
function changedLines(section) {
  for (const { language, lines } of codeBlocks(section)) {
    if (language !== 'diff' && language !== 'patch') continue;
    const hunks = [[]];
    for (const line of lines) {
      if (/^(?:@@|diff --git )/.test(line)) hunks.push([]);
      else if (!/^(?:--- |\+\+\+ )/.test(line) && /^[+-]/.test(line)) hunks.at(-1).push(line);
    }
    for (const hunk of hunks) {
      const originalCode = hunk.filter(line => line[0] === '-').map(line => line.slice(1)).join('\n');
      const fixedCode = hunk.filter(line => line[0] === '+').map(line => line.slice(1)).join('\n');
      if (originalCode || fixedCode) return { originalCode, fixedCode };
    }
  }
  return {};
}

function summaryText(section) {
  if (!section) return '';
  const paragraph = [section.inline, structure(section.text).trim().split(/\n[ \t]*\n/)[0]].filter(Boolean).join(' ');
  return paragraph.replace(/\[([^\]]+)\]\([^)]*\)/g, '$1').replace(/[*`]/g, '').replace(/\s+/g, ' ').trim();
}

function onePageFinding(finding) {
  const detail = sections(finding.body);
  const pick = (...names) => detail.find(section => names.includes(section.label));
  const unsafe = detail.find(section => /^(?:vulnerable code|original code|before(?:\s*\([^)]*\))?)$/.test(section.label));
  const safe = detail.find(section => /^(?:fixed code|proposed fixed code|after(?:\s*\([^)]*\))?)$/.test(section.label));
  const observed = pick('evidence', 'source evidence');
  const fix = pick('proposed fix', 'remediation', 'mitigation');
  const difference = changedLines(pick('proposed fix patch') || fix);
  const originalCodeSource = evidenceLocations([unsafe?.inline, observed?.inline, observed?.text && structure(observed.text)].filter(Boolean).join('\n'))[0] || '';
  const falsePositive = finding.disposition === 'FALSE POSITIVE';
  const impact = summaryText(pick('impact', 'finding and impact', 'security impact', 'business impact')) || field(finding.body, 'impact|finding and impact')
    || (falsePositive ? summaryText(pick('verified safe behavior')) : '');
  const assessment = [finding.disposition || 'Reported finding', finding.confidence !== 'UNSPECIFIED' && finding.confidence].filter(Boolean).join(' · ');
  return {
    title: finding.title, id: finding.id, severity: finding.severity,
    status: finding.unverified ? 'Unverified finding' : assessment,
    location: originalCodeSource || finding.evidence?.[0] || field(finding.body, 'location'),
    originalCodeSource, impact,
    originalCode: falsePositive ? '' : excerpt(unsafe) || (originalCodeSource ? excerpt(observed, { requireLanguage: true }) : '') || difference.originalCode || '',
    fixedCode: falsePositive ? '' : excerpt(safe) || difference.fixedCode || '',
    remediation: falsePositive ? '' : summaryText(fix) || field(finding.body, 'proposed fix|remediation|mitigation'),
  };
}

function primaryFinding(findings) {
  return [...findings].sort((left, right) => {
    const rank = finding => finding.disposition === 'FALSE POSITIVE' ? 2 : finding.unverified ? 1 : 0;
    return rank(left) - rank(right) || SEVERITY.indexOf(left.severity) - SEVERITY.indexOf(right.severity);
  })[0];
}

module.exports = { onePageFinding, primaryFinding };
