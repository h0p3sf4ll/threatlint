---
description: "Review supplied redacted runtime captures against source, authentication state, and deployment revisions. Analysis only; no runtime testing."
argument-hint: "Scope and optional redacted capture/report path; never credentials or session tokens"
---

Delegate to `appsec-runtime-reviewer`. Pass `$ARGUMENTS` as the scope and explicitly supplied redacted evidence locations.

Load the assigned workflows in order: `threatlint-evidence-analysis`, `threatlint-actionable-reporting`, `threatlint-runtime-validation`, then `threatlint-runtime-auth-workflows`.

Correlate captures with inspected source, build/revision, identity role/tenant, and provenance. Distinguish observations, hardening notes, blocked checks, and supported vulnerabilities; missing headers/statuses alone are not vulnerabilities. Missing source or auth evidence is a limitation.

Do not send requests, capture traffic, browse targets, log in, automate SSO/MFA, use credentials, or run scanners/tests. Proposed validation is **NOT RUN** and requires separate authorization.

Return the complete DX-NNN review as text with advisory fixes, owners/effort, acceptance criteria, and evidence gaps. Report persistence is host-owned; the delegated agent must not write files or export reports.
