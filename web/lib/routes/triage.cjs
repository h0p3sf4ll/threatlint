'use strict';

/**
 * Acting on FP-review verdicts: close a ServiceNow AVIT as a false positive with the report attached,
 * then tune Semgrep so the same finding stays quiet. Both act only on findings the FP reviewer marked
 * FALSE POSITIVE, and only after the user confirms in the UI. Credentials and tokens are used per
 * request and never stored.
 */

const fs = require('node:fs');
const { field } = require('../reports.cjs');
const { handle, HttpError } = require('../http.cjs');
const servicenow = require('../servicenow.cjs');
const semgrep = require('../semgrep-cloud.cjs');
const trackers = require('../trackers.cjs');

const FP_REVIEWER = 'appsec-fp-reviewer';
const AVIT_TOKEN = /\bAVIT\d{4,12}\b/g;

/** The AVIT a finding refers to, from its Original finding field, title, or body; exactly one is required. */
function avitFor(finding) {
  for (const text of [field(finding.body, 'Original finding|Original ID|Original finding ID'), finding.title, finding.body]) {
    const found = [...new Set(String(text || '').toUpperCase().match(AVIT_TOKEN) || [])];
    if (found.length === 1) return found[0];
    if (found.length > 1) throw new HttpError(`${finding.id} references several AVITs (${found.join(', ')}); close them from a report with one AVIT per finding`);
  }
  throw new HttpError(`${finding.id} does not reference an AVIT number`);
}

const DOCX = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';

/** The report as files named after the tracker item, e.g. AVIT0012345-threatlint-fp-review.md. */
function reportFiles(report, prefix) {
  const files = [{ name: `${prefix}-threatlint-fp-review.md`, content: fs.readFileSync(report.mdPath), type: 'text/markdown' }];
  if (report.docxPath && fs.existsSync(report.docxPath)) files.push({ name: `${prefix}-threatlint-fp-review.docx`, content: fs.readFileSync(report.docxPath), type: DOCX });
  return files;
}

function closingNote(finding, report, files) {
  return [`Closed by Threatlint as a false positive.`, '',
    `Finding: ${finding.id} — ${finding.title}`, `Disposition: FALSE POSITIVE (confidence ${finding.confidence})`,
    `Reviewed by: Threatlint ${report.label} (${report.agentId}), ${new Date(report.timestamp).toISOString()}`,
    `Report attached: ${files.map(file => file.name).join(', ')}`, '',
    'The attached report holds the evidence and reasoning for this verdict.'].join('\n');
}

function registerTriageRoutes(app, { reports, integrations = {} }) {
  const fetchImpl = integrations.fetchImpl;
  const tokenFor = integrations.semgrepToken || semgrep.semgrepToken;

  function falsePositive(reportId, findingId) {
    const located = typeof reportId === 'string' ? reports.find(reportId) : null;
    if (!located) throw new HttpError('Report not found', 404);
    const { report } = located;
    if (report.agentId !== FP_REVIEWER) throw new HttpError('Only Findings triage reports can close AVITs or tune Semgrep');
    const finding = reports.read(report).findings.find(item => item.id === findingId);
    if (!finding) throw new HttpError('Finding not found in this report', 404);
    if (finding.disposition !== 'FALSE POSITIVE') throw new HttpError(`${finding.id} is ${finding.disposition || 'not triaged'}, not FALSE POSITIVE`);
    return { report, finding };
  }

  app.post('/api/servicenow/close-false-positive', handle(async req => {
    const { report, finding } = falsePositive(req.body?.reportId, req.body?.findingId);
    const avit = avitFor(finding);
    const credentials = servicenow.validateCredentials(req.body?.servicenow);
    const files = reportFiles(report, avit);
    return servicenow.closeAvitAsFalsePositive(credentials, avit, { note: closingNote(finding, report, files), files }, { fetchImpl });
  }));

  // The tracker items a FALSE POSITIVE finding references: ServiceNow AVIT, ADO work item, or GHAS alert.
  app.post('/api/trackers/references', handle(req => {
    const { finding } = falsePositive(req.body?.reportId, req.body?.findingId);
    return { references: trackers.trackerRefs(finding, field) };
  }));

  // Same flow as ServiceNow for Azure DevOps Boards and GitHub Advanced Security: attach, close, note.
  app.post('/api/trackers/close-false-positive', handle(async req => {
    const { report, finding } = falsePositive(req.body?.reportId, req.body?.findingId);
    const refs = trackers.trackerRefs(finding, field).filter(ref => ref.tracker === req.body?.tracker);
    if (refs.length !== 1) throw new HttpError(`${finding.id} must reference exactly one ${req.body?.tracker || 'tracker'} item`);
    const [ref] = refs;
    const files = reportFiles(report, ref.label);
    const note = closingNote(finding, report, files);
    if (ref.tracker === 'azure-devops') return trackers.closeAdoWorkItem(req.body?.azureDevOps, ref.id, { note, files }, { fetchImpl });
    if (ref.tracker === 'github') return trackers.dismissGithubAlert(req.body?.github, ref.owner, ref.repo, ref.id, { note, files, reportName: files[0].name }, { fetchImpl });
    const result = await servicenow.closeAvitAsFalsePositive(servicenow.validateCredentials(req.body?.servicenow), ref.id, { note, files }, { fetchImpl });
    return { tracker: 'servicenow', item: result.avit, ...result };
  }));

  // Preview: the open Semgrep findings this tuning would ignore. Nothing changes until /ignore.
  app.post('/api/semgrep/false-positive/matches', handle(async req => {
    falsePositive(req.body?.reportId, req.body?.findingId);
    const target = semgrep.validateTarget(req.body?.target);
    return semgrep.matchFindings(await tokenFor({ token: req.body?.semgrepToken }), target, { fetchImpl });
  }));

  app.post('/api/semgrep/false-positive/ignore', handle(async req => {
    const { report, finding } = falsePositive(req.body?.reportId, req.body?.findingId);
    let avit = null;
    try { avit = avitFor(finding); } catch { avit = trackers.trackerRefs(finding, field)[0]?.label || null; }
    const note = `False positive per Threatlint ${report.label}, ${finding.id}${avit ? ` (${/^AVIT/.test(avit) ? `ServiceNow ${avit}` : avit})` : ''}: ${finding.title}`;
    const target = semgrep.validateTarget(req.body?.target);
    const token = await tokenFor({ token: req.body?.semgrepToken });
    // Re-match server-side so only findings inside the narrow rule/repo/file scope can be ignored.
    const { deployment, matches } = await semgrep.matchFindings(token, target, { fetchImpl });
    const allowed = new Set(matches.map(match => match.id));
    const ids = (Array.isArray(req.body?.issueIds) ? req.body.issueIds.map(Number) : []).filter(id => allowed.has(id));
    if (!ids.length) throw new HttpError('None of the selected findings are still open for this rule, repository, and file', 409);
    return { deployment, ...await semgrep.ignoreAsFalsePositive(token, deployment.slug, ids, note, { fetchImpl }) };
  }));
}

module.exports = { registerTriageRoutes, avitFor, closingNote, reportFiles };
