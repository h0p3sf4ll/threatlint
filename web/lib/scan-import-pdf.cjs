'use strict';

/**
 * Layout parsers for PDF scan reports, with dedicated adapters for Invicti and MobSF.
 *
 * Input is the positioned lines from pdf-text.cjs. Output is *raw* fields only: scan-import.cjs feeds them through
 * the same invictiFinding / mobsfFinding builders as XML and JSON exports, so PDF findings get identical
 * normalisation, redaction, and size limits. PDFs carry less structure than exports (no lookup ids, no exact
 * certainty percentages), so the JSON/XML export stays the better source when it is available.
 */

const norm = value => String(value ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
const slug = value => norm(value).slice(0, 60) || 'item';
const PAGE_MARKER = /^\d{1,4}\/\d{1,4}$/;

// Recorded HTTP and explicit list/label lines keep their boundaries. Narrative continuations
// use nearby baselines and the same left margin, without flattening separate sentences or sections.
const STRUCTURED_LINE = /^(?:[-*•◦–]\s|\d{1,3}[.)]\s|[\w-]+:\s|[A-Z]+ \S+ HTTP\/|HTTP\/\d)/;
function continuesProse(previous, line) {
  if (!previous || previous.page !== line.page) return false;
  const size = Math.max(previous.size, line.size);
  const leading = previous.y - line.y;
  const marginChange = Math.abs(previous.parts[0].x - line.parts[0].x);
  if (leading <= 0 || leading > size * 1.8 || marginChange > size * 0.6) return false;
  if (STRUCTURED_LINE.test(previous.text) || STRUCTURED_LINE.test(line.text)) return false;
  return !(/[.!?]["'’”)\]]*$/.test(previous.text) && /^\p{Lu}/u.test(line.text));
}

function proseText(lines) {
  return lines.map((line, index) => {
    const separator = index === 0 ? '' : continuesProse(lines[index - 1], line) ? ' ' : '\n';
    return separator + line.text;
  }).join('');
}

// ── Detection ─────────────────────────────────────────────────────────────────

/**
 * 'invicti', 'mobsf', 'mobsf-web' (a browser print of the MobSF web page, whose tables are paginated and therefore
 * incomplete), or null, from the report's own title lines.
 */
function detectPdf(lines) {
  const head = lines.slice(0, 60).map(line => line.text).join('\n');
  if (/RECENT SCANS\s+STATIC ANALYZER/i.test(head) || (/\bMob\s*SF\b|Mobile Security Framework/i.test(head)
    && lines.some(line => /^Showing \d+ to \d+ of \d+ entries$/.test(line.text)))) return 'mobsf-web';
  if (/\b(?:ANDROID|IOS|IPA|APK|WINDOWS|APPX) (?:STATIC|DYNAMIC) ANALYSIS REPORT\b|\bMobSF\b|Mobile Security Framework/i.test(head)) return 'mobsf';
  if (/Detailed Scan Report|Invicti|Netsparker/i.test(head)) return 'invicti';
  return null;
}

// ── Invicti Detailed Scan Report ──────────────────────────────────────────────

const INVICTI_SEVERITY_LINE = /^(CRITICAL|HIGH|MEDIUM|LOW|BEST PRACTICE|INFORMATION)(?:\s+\d+)?(?:\s+CONFIRMED\s+\d+)?$/;
const INVICTI_SECTIONS = new Set(['impact', 'vulnerabilities', 'actionstotake', 'remedy', 'requiredskillsforsuccessfulexploitation',
  'externalreferences', 'remedyreferences', 'classification', 'proofofexploit', 'notes']);
const CVSS_LINE = /^CVSS (?:\d\.\d )?(?:SCORE|Score|Vector String)$/i;
const RESPONSE_META = /^(?:Response Time \(ms\)|Total Bytes Received|Body Length|Is Compressed)\s*:/;

/** Index of each "N. Title" heading that is followed (within the wrapped title) by a severity line. */
function invictiHeadings(texts) {
  const headings = [];
  for (let index = 0; index < texts.length; index += 1) {
    const match = /^(\d{1,3})\. (.+)$/.exec(texts[index]);
    if (!match || Number(match[1]) !== headings.length + 1) continue;
    const severityAt = texts.slice(index + 1, index + 4).findIndex(text => INVICTI_SEVERITY_LINE.test(text));
    if (severityAt < 0) continue;
    const titleLines = [match[2], ...texts.slice(index + 1, index + 1 + severityAt)];
    headings.push({ number: match[1], start: index, body: index + 2 + severityAt, title: titleLines.join(' '),
      severity: INVICTI_SEVERITY_LINE.exec(texts[index + 1 + severityAt])[1] });
  }
  return headings;
}

/** Splits a vulnerability block into { description: [...], sections: { impact: [...], ... }, instances: [...] }. */
function invictiBlock(lines, number) {
  const block = { description: [], sections: {}, instances: [] };
  let section = null, instance = null;
  for (const line of lines) {
    const { text } = line;
    const key = norm(text);
    const start = new RegExp(`^${number}\\.(\\d{1,3})\\. (\\S+)$`).exec(text);
    if (section === 'vulnerabilities' && start) {
      instance = { number: `${number}.${start[1]}`, url: start[2], lines: [] };
      block.instances.push(instance);
    } else if (INVICTI_SECTIONS.has(key) || CVSS_LINE.test(text)) {
      section = CVSS_LINE.test(text) ? 'cvss' : key;
      instance = null;
      block.sections[section] ??= [];
    } else if (instance) instance.lines.push(text);
    else if (section) block.sections[section].push(line);
    else block.description.push(line);
  }
  return block;
}

/** Certainty, request, and response from an instance's lines ("Request Response" / "Request" … / "Response" …). */
function invictiInstance(lines) {
  const certainty = lines[0] === 'CONFIRMED' ? 'Confirmed' : '';
  const requestAt = lines.findIndex((text, index) => text === 'Request' && lines[index - 1] !== undefined);
  const responseAt = lines.findIndex((text, index) => index > requestAt && text === 'Response');
  const request = requestAt < 0 ? [] : lines.slice(requestAt + 1, responseAt < 0 ? undefined : responseAt);
  const response = responseAt < 0 ? [] : lines.slice(responseAt + 1).filter(text => !RESPONSE_META.test(text));
  const evidence = lines.slice(certainty ? 1 : 0, requestAt < 0 ? undefined : requestAt).filter(text => !/^(Certainty|Request Response)$/.test(text));
  return { certainty, confirmed: Boolean(certainty), request: request.filter(text => text !== '[SSL Connection]').join('\n'),
    response: response.filter(text => text !== '[SSL Connection]').join('\n'), evidence: evidence.join('\n') };
}

/** "CWE 327", "OWASP 2017 A3", "PCI DSS v4.0 6.2.4" → { CWE: '327', 'OWASP 2017': 'A3', ... }. */
function invictiClassification(lines = []) {
  return Object.fromEntries(lines.map(line => /^(.+?)\s+(\S+)$/.exec(line.text)).filter(Boolean).map(([, key, value]) => [key, value]));
}

function parseInvictiPdf(lines) {
  const positioned = lines.filter(line => !PAGE_MARKER.test(line.text));
  const texts = positioned.map(line => line.text);
  const headings = invictiHeadings(texts);
  const findings = headings.flatMap((heading, index) => {
    const block = invictiBlock(positioned.slice(heading.body, headings[index + 1]?.start ?? positioned.length), heading.number);
    const description = [proseText(block.description), block.sections.impact?.length && `Impact:\n${proseText(block.sections.impact)}`].filter(Boolean).join('\n');
    const remediation = [proseText(block.sections.remedy || []), block.sections.actionstotake?.length && `Actions to take:\n${proseText(block.sections.actionstotake)}`].filter(Boolean).join('\n');
    const classification = invictiClassification(block.sections.classification);
    const instances = block.instances.length ? block.instances : [{ number: `${heading.number}.1`, url: '', lines: [] }];
    return instances.map(instance => {
      const details = invictiInstance(instance.lines);
      return { id: instance.number, name: heading.title, type: heading.title, severity: heading.severity, certainty: details.certainty, confirmed: details.confirmed,
        url: instance.url, method: '', parameter: '', request: details.request, response: details.response, classification, remediation,
        description: details.evidence ? `${description}\n\nEvidence:\n${details.evidence}` : description };
    });
  });
  const target = texts.slice(0, 40).find(text => /^https?:\/\/\S+$/.test(text)) || '';
  const scanTime = texts.map(text => /^Scan Time\s*:\s*(.+)$/.exec(text)?.[1]).find(Boolean) || '';
  return { target, scanTime, findings };
}

// ── MobSF static-analysis report ──────────────────────────────────────────────

const HEADING_SIZE = 14;        // section headings can be as small as 15pt; table headers are ~11pt
const ROW_GAP = 1.8;            // Mobile layouts can put row starts ~2× and wrapped lines ~1.5× apart.
const SEVERITY_COLUMNS = ['severity', 'status'];
const TITLE_COLUMNS = ['issue', 'protection', 'title', 'permissions', 'permission'];
const ROW_STATUS = /^(?:critical|high|medium|warning|low|info(?:rmational)?|secure|good|dangerous|normal|pass(?:ed)?|fail(?:ed)?|true|false)$/i;
const SECTION_PREFIX = [[/manifest/i, 'manifest'], [/binary|protection/i, 'binary'], [/network/i, 'network'], [/transport security|\bats\b/i, 'ats'],
  [/certificate/i, 'certificate'], [/permission/i, 'permission'], [/code analysis/i, 'code']];

function mobsfHeading(line) {
  const label = line.text.replace(/^[^\p{L}\p{N}]+\s*/u, '');
  return line.size >= HEADING_SIZE && /[A-Z]{2}/.test(label) && label === label.toUpperCase() ? label : '';
}

/** A findings table includes a severity or status column and an issue or description column. */
const isTableHeader = line => line.parts.length >= 2 && line.parts.every(part => part.text === part.text.toUpperCase())
  && line.parts.some(part => SEVERITY_COLUMNS.includes(norm(part.text)))
  && line.parts.some(part => TITLE_COLUMNS.includes(norm(part.text)) || norm(part.text) === 'description');

function columnOf(columns, x) {
  let found = columns[0];
  for (const column of columns) if (x >= column.x - 4) found = column;
  return found;
}

/** Rows split at same-page gaps. On a new page, a running row can continue beneath a repeated header. */
function tableRows(header, body) {
  const columns = header.parts.map(part => ({ x: part.x, name: norm(part.text) }));
  const rows = [];
  let row = null, previous = null;
  for (const line of body) {
    const parts = line.parts.map(part => ({ column: columnOf(columns, part.x).name, text: part.text }));
    const newRowAtPageBreak = previous?.page !== line.page && parts.some(({ column, text }) =>
      (column === 'no' && /^\d+$/.test(text)) || (SEVERITY_COLUMNS.includes(column) && ROW_STATUS.test(text)));
    const newRowOnPage = previous?.page === line.page && previous.y - line.y > line.size * ROW_GAP;
    if (!row || newRowAtPageBreak || newRowOnPage) rows.push(row = Object.fromEntries(columns.map(column => [column.name, []])));
    for (const { column, text } of parts) row[column].push(text);
    previous = line;
  }
  return rows.map(cells => Object.fromEntries(Object.entries(cells).map(([name, texts]) => [name, texts.join(' ').replace(/\s+/g, ' ').trim()])));
}

/** Tables in reading order: { section, rows }. A header repeated on a new page continues the same table. */
function mobsfTables(lines) {
  const tables = [];
  let section = '', table = null;
  for (const line of lines) {
    if (PAGE_MARKER.test(line.text)) continue;
    const heading = mobsfHeading(line);
    if (heading) { section = heading; table = null; continue; }
    if (isTableHeader(line)) {
      const columns = line.parts.map(part => norm(part.text)).join('|');
      if (!table || table.columns !== columns) tables.push(table = { section, columns, header: line, body: [] });
      continue;
    }
    if (table) table.body.push(line);
  }
  return tables.map(({ section: name, header, body }) => ({ section: name, rows: tableRows(header, body) }));
}

function standards(text) {
  const cwe = /CWE:\s*(CWE-\d{1,5})/i.exec(text)?.[1] || '';
  const owasp = /OWASP Top 10:\s*(.+?)(?=\s+OWASP MASVS:|$)/i.exec(text)?.[1] || '';
  const masvs = /OWASP MASVS:\s*(MSTG-\s*[A-Z]+-\d+|MASVS-\s*[A-Z]+-\d+|\S+)/i.exec(text)?.[1]?.replace(/\s+/g, '') || '';
  return { cwe, owasp, masvs };
}

const field = (lines, label) => lines.map(line => new RegExp(`^${label}:\\s*(.+)$`, 'i').exec(line.text)?.[1]).find(Boolean) || '';
const PASSING = new Set(['secure', 'good', 'pass', 'passed', 'true', 'normal']);

/** Android's tracker and secrets sections do not label an individual severity. */
function mobsfAndroidObservations(lines) {
  const findings = [];
  const trackers = lines.find(line => /^Trackers Detection:/i.test(line.text));
  const count = Number(/^Trackers Detection:\s*(\d+)\s*\/\s*\d+$/i.exec(trackers?.text)?.[1]);
  if (Number.isSafeInteger(count) && count > 0) {
    findings.push({ id: 'tracker:detected', title: 'Privacy trackers detected', location: `PDF page ${trackers.page}`,
      description: `MobSF reports ${count} detected tracker(s). Presence alone does not establish that the app collects or sends data.` });
  }
  const secrets = lines.findIndex(line => mobsfHeading(line) === 'HARDCODED SECRETS');
  if (secrets >= 0) {
    const [header, firstEntry] = lines.slice(secrets + 1, secrets + 5).filter(line => !PAGE_MARKER.test(line.text));
    if (header?.text === 'POSSIBLE SECRETS' && firstEntry && !mobsfHeading(firstEntry)) {
      findings.push({ id: 'secret:possible', title: 'Possible hardcoded secrets', location: `PDF page ${lines[secrets].page}`,
        description: 'MobSF lists possible hardcoded secrets. Review the original PDF to identify the candidates. Secret values were omitted from the import.' });
    }
  }
  return findings;
}

function parseMobsfPdf(lines) {
  const title = lines.find(line => /ANALYSIS REPORT/i.test(line.text))?.text || '';
  const platform = /\bIOS|IPA\b/i.test(title) ? 'iOS' : /WINDOWS|APPX/i.test(title) ? 'Windows' : 'Android';
  const findings = [];
  for (const { section, rows } of mobsfTables(lines)) {
    const prefix = SECTION_PREFIX.find(([pattern]) => pattern.test(section))?.[1] || slug(section);
    for (const row of rows) {
      const severity = row.severity || row.status || '';
      const titleText = TITLE_COLUMNS.map(name => row[name]).find(Boolean) || row.description?.split(/[.\n]/)[0] || '';
      if (!titleText || !severity) continue;
      if (prefix === 'permission') {
        if (norm(row.status) !== 'dangerous') continue;
        const permission = platform === 'Android' ? titleText.replace(/\s+/g, '') : titleText.split(' ')[0];
        findings.push({ id: `permission:${permission}`, title: `Dangerous permission: ${permission}`, severity: 'dangerous',
          description: [row.description, row.reasoninmanifest].filter(Boolean).join('\n') });
        continue;
      }
      // Protection tables list passing checks as "info"; only failing checks are findings.
      if (PASSING.has(norm(severity)) || (prefix === 'binary' && row.protection !== undefined && norm(row.severity) === 'info')) continue;
      findings.push({ id: `${prefix}:${slug(titleText)}`, title: titleText, severity: row.severity || severity, description: row.description || '',
        ...standards(row.standards || ''), files: row.files ? [{ path: row.files.split(' ')[0], lines: [] }] : [] });
    }
  }
  if (platform === 'Android') findings.push(...mobsfAndroidObservations(lines));
  return {
    app: { name: field(lines, 'App Name'), version: field(lines, 'Version') || field(lines, 'Version Name') || field(lines, 'Android Version Name'),
      identifier: field(lines, 'Identifier') || field(lines, 'Package Name'), platform },
    scanDate: field(lines, 'Scan Date'), findings,
  };
}

// Generic reports have no schema. Look for explicit finding fields or a table with both a title and severity.
const GENERIC_FIELDS = {
  finding: 'title', findingname: 'title', findingtitle: 'title', name: 'title', title: 'title', issue: 'title', issuename: 'title',
  issuetitle: 'title', vulnerability: 'title', vulnerabilityname: 'title', vulnerabilitytitle: 'title', pluginname: 'title', alert: 'title',
  severity: 'severity', risk: 'severity', risklevel: 'severity', riskfactor: 'severity', priority: 'severity',
  description: 'description', details: 'description', synopsis: 'description',
  evidence: 'evidence', observation: 'evidence', observations: 'evidence', pluginoutput: 'evidence',
  remediation: 'remediation', recommendation: 'remediation', solution: 'remediation', mitigation: 'remediation',
  impact: 'impact', cwe: 'cwe', id: 'id', findingid: 'id', ruleid: 'id', pluginid: 'id',
  location: 'location', affectedlocation: 'location', affectedasset: 'location', affectedresource: 'location',
  affectedurl: 'location', url: 'location', host: 'location', endpoint: 'location',
  affectedfile: 'file', file: 'file', filepath: 'file', line: 'line', linenumber: 'line',
};
const RISK_LABEL = 'critical|high|medium|moderate|low|info(?:rmation(?:al)?)?|note|warning|blocker|major|minor';
const riskValue = new RegExp(`^(${RISK_LABEL})(?:\\s*\\(\\d{1,2}(?:\\.\\d+)?\\))?$`, 'i');
const riskHeading = new RegExp(`^(?:\\[(${RISK_LABEL})\\]\\s+|(${RISK_LABEL})\\s*[:–—-]\\s+)(.+)$`, 'i');
const numbered = /^\d{1,7}[.)-]\s+|^\d{4,7}\s+-\s+/;
const pageFooter = /^(?:page\s+)?\d{1,4}(?:\s+of\s+|\s*\/\s*)\d{1,4}$/i;
const summaryTitle = /^\d+(?:\s+(?:findings?|issues?|alerts?|vulnerabilities))?$|^(?:scan|findings?|vulnerabilit(?:y|ies)|issues?|alerts?|risk|severity|executive)\s+(?:summary|overview|totals?|counts?|report)\b|\.{3,}\s*\d+$/i;
const reportField = (lines, names) => lines.slice(0, 60).map(line => {
  const match = /^([^:]+):\s*(.+)$/.exec(line.text);
  return match && names.includes(norm(match[1])) ? match[2] : '';
}).find(Boolean) || '';

function genericField(text) {
  const match = /^([a-z][a-z /_-]{0,35})(?::\s*(.*))?$/i.exec(text);
  const key = match && Object.hasOwn(GENERIC_FIELDS, norm(match[1])) ? GENERIC_FIELDS[norm(match[1])] : '';
  return key ? { key, value: match[2] || '', label: norm(match[1]) } : null;
}

function genericDetails(lines) {
  const findings = [];
  let finding, field, fieldLine, weakTitle;
  const finish = () => {
    if (!finding) return;
    const hasContext = finding.description || finding.evidence || finding.file || finding.location || finding.cwe;
    if (riskValue.test(finding.severity || '') || (hasContext && !weakTitle)) findings.push(finding);
  };
  for (let row = 0; row < lines.length; row += 1) {
    const line = lines[row];
    const text = line.text.replace(numbered, '');
    const label = genericField(text), risk = riskHeading.exec(text);
    const next = lines[row + 1]?.page === line.page ? genericField(lines[row + 1].text) : null;
    const looksLikeHeading = !label && next?.key === 'severity' && (numbered.test(line.text) || line.size > lines[row + 1].size);
    const title = label?.key === 'title' ? label.value : risk?.[3] || (looksLikeHeading ? text : '');
    if (title && !summaryTitle.test(title)) {
      finish();
      finding = { title, page: line.page, row: row + 1 };
      if (risk) finding.severity = risk[1] || risk[2];
      weakTitle = ['name', 'title'].includes(label?.label);
      field = '';
    } else if (finding && label && label.key !== 'title') {
      field = label.key;
      fieldLine = { ...line, text: label.value };
      if (label.value) finding[field] = [finding[field], label.value].filter(Boolean).join('\n');
    } else if (finding && field && !risk && !pageFooter.test(text)) {
      const previous = lines[row - 1];
      if (line.page !== previous.page || line.size > previous.size + 2) field = '';
      if (field && (!finding[field] || ['description', 'impact', 'evidence', 'remediation'].includes(field))) {
        const separator = field !== 'evidence' && continuesProse(fieldLine, line) ? ' ' : '\n';
        finding[field] = [finding[field], line.text].filter(Boolean).join(separator);
        fieldLine = line;
      }
    }
  }
  finish();
  return findings;
}

function genericTables(lines) {
  const findings = [];
  let header, columns, finding, previous;
  for (let row = 0; row < lines.length; row += 1) {
    const line = lines[row];
    if (pageFooter.test(line.text)) continue;
    const keys = line.parts.map(part => genericField(part.text)?.key);
    if (keys.includes('title') && keys.includes('severity')) {
      header = line;
      columns = line.parts.map((part, index) => ({ x: part.x, name: keys[index] }));
      finding = null;
      continue;
    }
    if (!header || line.page !== header.page || line.size > header.size + 2) {
      header = null;
      continue;
    }
    const cells = {};
    for (const part of line.parts) {
      const key = columnOf(columns, part.x).name;
      if (key) cells[key] = [cells[key], part.text].filter(Boolean).join(' ');
    }
    if (cells.title && !summaryTitle.test(cells.title) && riskValue.test(cells.severity || '')) {
      finding = { ...cells, page: line.page, row: row + 1 };
      findings.push(finding);
    } else if (finding && !cells.severity && line.y < previous.y && previous.y - line.y <= line.size * 2) {
      for (const [key, value] of Object.entries(cells)) finding[key] = [finding[key], value].filter(Boolean).join(' ');
    } else {
      finding = null;
    }
    previous = line;
  }
  return findings;
}

const titleKey = finding => finding.title.normalize().toLowerCase().replace(/\s+/g, ' ').trim();

function parseGenericPdf(lines) {
  const details = genericDetails(lines);
  const detailedTitles = new Set(details.map(titleKey));
  const tables = genericTables(lines).filter(finding => !detailedTitles.has(titleKey(finding)) || finding.file || finding.location);
  const findings = [...details, ...tables].sort((a, b) => a.row - b.row);
  return {
    target: reportField(lines, ['scantarget', 'target', 'application', 'project', 'appname']),
    scanDate: reportField(lines, ['scandate', 'scantime']),
    findings,
  };
}

module.exports = { detectPdf, parseInvictiPdf, parseMobsfPdf, parseGenericPdf, tableRows, mobsfTables };
