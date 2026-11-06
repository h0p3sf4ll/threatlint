'use strict';

const CONSERVATIVE_NOTE = 'True positive (unverified): false positive was not proven beyond reasonable doubt. Left open pending the evidence the report names; this is not a claim of verified exploitation.';

/** Review outcomes are binary; uncertainty never closes or confirms a finding. */
function dispositionState(value, unverified = false) {
  const supplied = String(value || '').trim().toUpperCase();
  const valid = supplied === 'TRUE POSITIVE' || supplied === 'FALSE POSITIVE';
  return { disposition: valid && !(supplied === 'FALSE POSITIVE' && unverified) ? supplied : 'TRUE POSITIVE', unverified: Boolean(unverified || !valid) };
}

function structure(body) {
  let fence = null;
  return body.split(/(?<=\n)/).map(line => {
    const marker = /^\s*(`{3,}|~{3,})/.exec(line);
    const masked = fence !== null || marker !== null;
    if (marker) { if (!fence) fence = marker[1]; else if (marker[1].startsWith(fence)) fence = null; }
    return masked ? line.replace(/[^\r\n]/g, ' ') : line;
  }).join('');
}

function hasFpEvidence(body) {
  const structural = structure(body);
  const fieldStart = String.raw` {0,3}(?:[-*+][ \t]+)?`;
  const ending = String.raw`(?:[ \t]*:[ \t]*\*\*|\*\*[ \t]*:|\*\*(?=[ \t]*\r?$))`;
  const section = name => {
    const match = new RegExp(String.raw`^${fieldStart}(?:\*\*${name}${ending}|#{2,6}[ \t]+${name}[ \t]*:?[ \t]*(?:#+[ \t]*)?\r?$)`, 'im').exec(structural);
    if (!match) return false;
    const start = match.index + match[0].length;
    const following = new RegExp(String.raw`^${fieldStart}(?:\*\*[^*\r\n]+?${ending}|#{1,6}[ \t])`, 'm').exec(structural.slice(start));
    const value = body.slice(start, following ? start + following.index : body.length).trim();
    return value && !/^(?:none|n\/a|unknown|not available|not inspected|unverified|tbd)[.!]?$/i.test(value);
  };
  return Boolean(section('Evidence') && section('Verified Safe Behavior'));
}

function normalizeReviewMarkdown(markdown) {
  let text = String(markdown || '');
  let renamed = false, fence = null;
  // Evidence from a different finding must not justify closing this one.
  let finding = '';
  const boundaries = [0, ...[...structure(text).matchAll(/^#{2,6}\s+\[?[A-Z][A-Z0-9]*-\d+\b/gm)].map(match => match.index), text.length];
  const sections = boundaries.slice(0, -1).map((start, index) => text.slice(start, boundaries[index + 1]));
  const bodies = sections.filter(section => /^#{2,6}\s+\[?[A-Z][A-Z0-9]*-\d+\b/.test(section));
  let findingIndex = 0;
  text = text.split('\n').map(line => {
    const marker = /^\s*(`{3,}|~{3,})/.exec(line);
    if (marker) { if (!fence) fence = marker[1]; else if (marker[1].startsWith(fence)) fence = null; return line; }
    if (fence) return line;
    if (/^#{2,6}\s+\[?[A-Z][A-Z0-9]*-\d+\b/.test(line)) finding = bodies[findingIndex++] || '';
    if (/^#\s+(?:false[ -]+positive review|fp review|findings? triage|finding review)\b/i.test(line)) {
      renamed = true;
      return line.replace(/^(#\s+)(?:false[ -]+positive review|fp review|findings? triage|finding review)\b/i, '$1Finding Review');
    }
    const match = /^( {0,3}(?:[-*+][ \t]+)?(?:\*\*(?:Disposition|Verdict)(?:\*\*[ \t]*:|[ \t]*:\*\*)|(?:Disposition|Verdict)[ \t]*:)[ \t]*)(.+)$/i.exec(line);
    if (!match) return line;
    const raw = match[2].replaceAll('*', '').trim();
    if (raw.toUpperCase() !== 'AMBIGUOUS' && !(raw.toUpperCase() === 'FALSE POSITIVE' && !hasFpEvidence(finding || text))) return line;
    return `${match[1]}TRUE POSITIVE\n**Decision basis**: CONSERVATIVE DEFAULT\n**Decision rationale**: ${CONSERVATIVE_NOTE}`;
  }).join('\n');
  return renamed ? text : `# Finding Review\n\n${text}`;
}

module.exports = { dispositionState, normalizeReviewMarkdown, CONSERVATIVE_NOTE, hasFpEvidence, structure };
