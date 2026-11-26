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
const onePager = require('../one-pager.cjs');
const semgrep = require('../semgrep-cloud.cjs');
const scanners = require('../scanners.cjs');
const { reviewSemgrepAvit } = require('../scan-import.cjs');

const FP_REVIEWER = 'appsec-fp-reviewer';
const AVIT_TOKEN = /\bAVIT\d{7,15}\b/g;

/** The AVIT a finding refers to, from its Original finding field, title, or body; exactly one is required. */
function avitFor(finding) {
  for (const text of [field(finding.body, 'Original finding|Original ID|Original finding ID'), finding.title, finding.body]) {
    const found = [...new Set(String(text || '').toUpperCase().match(AVIT_TOKEN) || [])];
    if (found.length === 1) return found[0];
    if (found.length > 1) throw new HttpError(`${finding.id} references several AVITs (${found.join(', ')}); close them from a report with one AVIT per finding`);
  }
  throw new HttpError(`${finding.id} does not reference an AVIT number`);
}

function closingNote() { return servicenow.CLOSING_COMMENT; }

function registerTriageRoutes(app, { reports, scannerPolicies, integrations = {} }) {
  const fetchImpl = integrations.fetchImpl;
  const tokenFor = integrations.semgrepToken || semgrep.semgrepToken;

  function falsePositive(reportId, findingId) {
    const located = typeof reportId === 'string' ? reports.find(reportId) : null;
    if (!located) throw new HttpError('Report not found', 404);
    const { report } = located;
    if (report.agentId !== FP_REVIEWER) throw new HttpError('Only Finding Review reports can close AVITs or tune Semgrep');
    const finding = reports.read(report).findings.find(item => item.id === findingId);
    if (!finding) throw new HttpError('Finding not found in this report', 404);
    if (finding.disposition !== 'FALSE POSITIVE') throw new HttpError(`${finding.id} is ${finding.disposition || 'not triaged'}, not FALSE POSITIVE`);
    return { report, finding, session: located.session };
  }

  // Scanner-native handling is deliberately per finding; never deactivate a shared rule/profile.
  app.post('/api/triage/scanner-tuning', handle(async req => {
    if (req.body?.confirm !== true) throw new HttpError('Confirm scanner tuning first');
    const { report, finding, session } = falsePositive(req.body?.reportId, req.body?.findingId);
    const origin = (field(finding.body, 'Scanner origin') || (report.source?.tool === 'sonar' ? 'sonarqube' : report.source?.scanner) || '').toLowerCase();
    if (/sonarqube/.test(origin)) {
      const ref = /\bSONAR-(?:HOTSPOT-)?[A-Za-z0-9_-]{6,64}\b/.exec(field(finding.body, 'Original finding'))?.[0] || (report.source?.tool === 'sonar' ? report.source.reference : null);
      if (!ref) throw new HttpError('No exact SonarQube issue reference was recorded; supply a SonarQube export with issue keys', 409);
      const result = await scanners.resolveSonar(scanners.connection('sonar'), ref, { disposition: 'FALSE POSITIVE', summary: finding.title, where: `Threatlint Findings: ${report.id} / ${finding.id}` }, { fetchImpl });
      return { scanner: 'sonarqube', ...result };
    }
    if (origin === 'trivy') {
      let target;
      try { target = field(finding.body, 'Scanner target') ? JSON.parse(field(finding.body, 'Scanner target')) : report.source?.tuning; if (!target) throw new Error(); } catch { throw new HttpError('The original Trivy finding has no precise ignore scope', 409); }
      if (!['vulnerabilities', 'misconfigurations', 'secrets', 'licenses'].includes(target.kind) || typeof target.rule !== 'string' || !target.rule || target.rule.length > 200 || /[\r\n]/.test(target.rule) || typeof target.path !== 'string' || !target.path || target.path.length > 600 || /[\r\n*?\[\]{}]/.test(target.path)) throw new HttpError('Trivy tuning requires a finding kind, ID, and exact target path', 409);
      const expires = new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10);
      // JSON is valid YAML and quotes untrusted paths/IDs safely. An explicit path avoids a global ID suppression.
      const policy = { [target.kind]: [{ id: target.rule, paths: [target.path], ...(target.kind === 'vulnerabilities' && typeof target.purl === 'string' && /^pkg:[^\r\n]{1,500}$/.test(target.purl) ? { purls: [target.purl] } : {}), statement: `False positive per Threatlint ${report.id}/${finding.id}`, expired_at: expires }] };
      const content = `${JSON.stringify(policy, null, 2)}\n`;
      const file = require('node:path').join(require('node:path').dirname(report.mdPath), `${report.id}-${finding.id}.trivyignore.yaml`);
      fs.writeFileSync(file, content, { mode: 0o600 });
      const appliedLocally = scannerPolicies?.save(session, target, expires, report.id, finding.id) || false;
      return { scanner: 'trivy', action: 'saved-local-policy', appliedLocally, content, filename: '.trivyignore.yaml', expires,
        detail: appliedLocally ? 'Approved exception saved for future Workbench Trivy scans of these exact file bytes. Changed files require a new review. The downloadable policy supports external Trivy runs; no validation scan was run by this action.' : 'Path-scoped policy saved with this report. Merge it into your Trivy ignore policy and pass --ignorefile .trivyignore.yaml on subsequent scans. No matching source file was available for automatic Workbench tuning.' };
    }
    throw new HttpError('Use the scanner-specific action for the recorded origin. Unknown scanner origins must be established before tuning.', 409);
  }));

  app.post('/api/servicenow/attach-review', handle(async req => {
    const { reportId, number, confirm, servicenow: connection } = req.body || {};
    if (confirm !== true) throw new HttpError('Confirm the ServiceNow attachment before posting');
    const ticket = servicenow.parseReviewTicket(number);
    const located = typeof reportId === 'string' ? reports.find(reportId) : null;
    if (!located) throw new HttpError('Report not found', 404);
    if (located.report.agentId !== FP_REVIEWER) throw new HttpError('Only Finding Review reports can be attached from this view');
    const credentials = servicenow.validateCredentials(connection);
    const action = await servicenow.attachReview(credentials, ticket, located.report, { fetchImpl });
    return { ok: true, actions: [action] };
  }));

  app.post('/api/servicenow/close-false-positive', handle(async req => {
    const { report, finding } = falsePositive(req.body?.reportId, req.body?.findingId);
    const avit = avitFor(finding);
    const credentials = servicenow.validateCredentials(req.body?.servicenow);
    // The Word report and its one-page summary are attached together.
    if (!report.docxPath || !fs.existsSync(report.docxPath)) throw new HttpError('The Word report is unavailable; install python-docx so the report can be attached', 409);
    const name = `${avit}-threatlint-fp-review.docx`;
    const files = [{ name, content: fs.readFileSync(report.docxPath), type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' },
      await onePager.attachment(report.mdPath, name, { avit, findingId: finding.id })];
    return servicenow.resolveAvit(credentials, avit, { disposition: 'FALSE POSITIVE', files }, { fetchImpl,
      reviewSemgrep: number => reviewSemgrepAvit(number, { body: req.body || {}, credentials, integrations }) });
  }));

  // Preview: the open Semgrep findings this tuning would ignore. Nothing changes until /ignore.
  app.post('/api/semgrep/false-positive/matches', handle(async req => {
    falsePositive(req.body?.reportId, req.body?.findingId);
    const target = semgrep.validateTarget(req.body?.target);
    return semgrep.matchFindings(await tokenFor({ profile: req.body?.profile || undefined }), target, { fetchImpl });
  }));

  app.post('/api/semgrep/false-positive/ignore', handle(async req => {
    const { report, finding } = falsePositive(req.body?.reportId, req.body?.findingId);
    let avit = null;
    try { avit = avitFor(finding); } catch { /* Semgrep tuning does not require an AVIT */ }
    const note = `False positive per Threatlint ${report.label}, ${finding.id}${avit ? ` (ServiceNow ${avit})` : ''}: ${finding.title}`;
    const target = semgrep.validateTarget(req.body?.target);
    const token = await tokenFor({ profile: req.body?.profile || undefined });
    // Re-match server-side so only findings inside the narrow rule/repo/file scope can be ignored.
    const { deployment, matches } = await semgrep.matchFindings(token, target, { fetchImpl });
    const allowed = new Set(matches.map(match => match.id));
    const ids = (Array.isArray(req.body?.issueIds) ? req.body.issueIds.map(Number) : []).filter(id => allowed.has(id));
    if (!ids.length) throw new HttpError('None of the selected findings are still open for this rule, repository, and file', 409);
    return { deployment, ...await semgrep.ignoreAsFalsePositive(token, deployment.slug, ids, note, { fetchImpl }) };
  }));
}

module.exports = { registerTriageRoutes, avitFor, closingNote };
