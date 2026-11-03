'use strict';

/**
 * Layout parsers for PDF scan reports: Invicti "Detailed Scan Report" and MobSF static-analysis reports.
 *
 * Input is the positioned lines from pdf-text.cjs. Output is *raw* fields only: scan-import.cjs feeds them through
 * the same invictiFinding / mobsfFinding builders as XML and JSON exports, so PDF findings get identical
 * normalisation, redaction, and size limits. PDFs carry less structure than exports (no lookup ids, no exact
 * certainty percentages), so the JSON/XML export stays the better source when it is available.
 */

const norm = value => String(value ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
const slug = value => norm(value).slice(0, 60) || 'item';
const PAGE_MARKER = /^\d{1,4}\/\d{1,4}$/;

// ── Detection ─────────────────────────────────────────────────────────────────

/**
 * 'invicti', 'mobsf', 'mobsf-web' (a browser print of the MobSF web page, whose tables are paginated and therefore
 * incomplete), or null, from the report's own title lines.
 */
function detectPdf(lines) {
  const head = lines.slice(0, 60).map(line => line.text).join('\n');
  if (/RECENT SCANS\s+STATIC ANALYZER/i.test(head) || lines.some(line => /^Showing \d+ to \d+ of \d+ entries$/.test(line.text))) return 'mobsf-web';
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
function invictiBlock(texts, number) {
  const block = { description: [], sections: {}, instances: [] };
  let section = null, instance = null;
  for (const text of texts) {
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
    else if (section) block.sections[section].push(text);
    else block.description.push(text);
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
  return Object.fromEntries(lines.map(text => /^(.+?)\s+(\S+)$/.exec(text)).filter(Boolean).map(([, key, value]) => [key, value]));
}

function parseInvictiPdf(lines) {
  const texts = lines.map(line => line.text).filter(text => !PAGE_MARKER.test(text));
  const headings = invictiHeadings(texts);
  const findings = headings.flatMap((heading, index) => {
    const block = invictiBlock(texts.slice(heading.body, headings[index + 1]?.start ?? texts.length), heading.number);
    const description = [...block.description, ...(block.sections.impact?.length ? ['Impact:', ...block.sections.impact] : [])].join('\n');
    const remediation = [...(block.sections.remedy || []), ...(block.sections.actionstotake?.length ? ['Actions to take:', ...block.sections.actionstotake] : [])].join('\n');
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

const HEADING_SIZE = 18;        // section headings are ~22pt; table headers ~12pt; cells ~9pt
const ROW_GAP = 2.5;            // a vertical gap over this many times the cell font size starts a new table row
                                // (wrapped lines in a cell are ~1.5× apart; rows are padded to ~3.5×)
const SEVERITY_COLUMNS = ['severity', 'status'];
const TITLE_COLUMNS = ['issue', 'protection', 'title', 'permissions', 'permission'];
const SECTION_PREFIX = [[/manifest/i, 'manifest'], [/binary|protection/i, 'binary'], [/network/i, 'network'], [/transport security|\bats\b/i, 'ats'],
  [/certificate/i, 'certificate'], [/permission/i, 'permission'], [/code analysis/i, 'code']];

const isHeading = line => line.size >= HEADING_SIZE && /[A-Z]/.test(line.text) && line.text === line.text.toUpperCase();
/** A table header names its columns in upper case and includes a severity or status column. */
const isTableHeader = line => line.parts.length >= 2 && line.parts.every(part => part.text === part.text.toUpperCase())
  && line.parts.some(part => SEVERITY_COLUMNS.includes(norm(part.text)));

function columnOf(columns, x) {
  let found = columns[0];
  for (const column of columns) if (x >= column.x - 4) found = column;
  return found;
}

/** Rows of one table: parts go to the column whose header starts at or left of them; large vertical gaps split rows. */
function tableRows(header, body) {
  const columns = header.parts.map(part => ({ x: part.x, name: norm(part.text) }));
  const rows = [];
  let row = null, previous = null;
  for (const line of body) {
    const gap = previous && previous.page === line.page ? previous.y - line.y : Infinity;
    if (!row || gap > line.size * ROW_GAP) rows.push(row = Object.fromEntries(columns.map(column => [column.name, []])));
    for (const part of line.parts) row[columnOf(columns, part.x).name].push(part.text);
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
    if (isHeading(line)) { section = line.text; table = null; continue; }
    if (isTableHeader(line)) {
      const columns = line.parts.map(part => norm(part.text)).join('|');
      if (!table || table.columns !== columns) tables.push(table = { section, columns, header: line, body: [] });
      else table.body.push({ ...line, parts: [] }); // a repeated header still ends the previous row
      continue;
    }
    if (table) table.body.push(line);
  }
  return tables.map(({ section: name, header, body }) => ({ section: name, rows: tableRows(header, body.filter(line => line.parts.length || line.text)) }));
}

function standards(text) {
  const cwe = /CWE:\s*(CWE-\d{1,5})/i.exec(text)?.[1] || '';
  const owasp = /OWASP Top 10:\s*(.+?)(?=\s+OWASP MASVS:|$)/i.exec(text)?.[1] || '';
  const masvs = /OWASP MASVS:\s*(MSTG-\s*[A-Z]+-\d+|MASVS-\s*[A-Z]+-\d+|\S+)/i.exec(text)?.[1]?.replace(/\s+/g, '') || '';
  return { cwe, owasp, masvs };
}

const field = (lines, label) => lines.map(line => new RegExp(`^${label}:\\s*(.+)$`, 'i').exec(line.text)?.[1]).find(Boolean) || '';
const PASSING = new Set(['secure', 'good', 'pass', 'passed', 'true', 'normal']);

function parseMobsfPdf(lines) {
  const title = lines.find(line => /ANALYSIS REPORT/i.test(line.text))?.text || '';
  const platform = /\bIOS|IPA\b/i.test(title) ? 'iOS' : /WINDOWS|APPX/i.test(title) ? 'Windows' : 'Android';
  const findings = [];
  for (const { section, rows } of mobsfTables(lines)) {
    const prefix = SECTION_PREFIX.find(([pattern]) => pattern.test(section))?.[1] || slug(section);
    for (const row of rows) {
      const severity = row.severity || row.status || '';
      const titleText = TITLE_COLUMNS.map(name => row[name]).find(Boolean) || row.description?.split(/[.\n]/)[0] || '';
      if (!titleText) continue;
      if (prefix === 'permission') {
        if (norm(row.status) !== 'dangerous') continue;
        findings.push({ id: `permission:${titleText.split(' ')[0]}`, title: `Dangerous permission: ${titleText.split(' ')[0]}`, severity: 'dangerous',
          description: [row.description, row.reasoninmanifest].filter(Boolean).join('\n') });
        continue;
      }
      // Protection tables list passing checks as "info"; only failing checks are findings.
      if (PASSING.has(norm(severity)) || (prefix === 'binary' && row.protection !== undefined && norm(row.severity) === 'info')) continue;
      findings.push({ id: `${prefix}:${slug(titleText)}`, title: titleText, severity: row.severity || severity, description: row.description || '',
        ...standards(row.standards || ''), files: row.files ? [{ path: row.files.split(' ')[0], lines: [] }] : [] });
    }
  }
  return {
    app: { name: field(lines, 'App Name'), version: field(lines, 'Version') || field(lines, 'Version Name'),
      identifier: field(lines, 'Identifier') || field(lines, 'Package Name'), platform },
    scanDate: field(lines, 'Scan Date'), findings,
  };
}

module.exports = { detectPdf, parseInvictiPdf, parseMobsfPdf, tableRows, mobsfTables };
