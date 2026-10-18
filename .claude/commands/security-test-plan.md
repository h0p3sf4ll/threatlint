---
description: "Design source-grounded security regression and acceptance plans with finding traceability, role/tenant cases, and auth prerequisites."
argument-hint: "Finding/report, invariant, component, or redacted evidence path; planning only"
---

Delegate to `appsec-security-test-planner`. Pass `$ARGUMENTS` as the source-backed findings, invariants, scope, and supplied evidence locations.

Load `threatlint-evidence-analysis`, `threatlint-actionable-reporting`, `threatlint-security-test-design`, then `threatlint-runtime-auth-workflows`. Preserve original finding IDs; ST-NNN identifies plan cases, not newly verified vulnerabilities.

Specify synthetic fixtures, allowed/denied/boundary/role/tenant cases, observable state/side-effect oracles, owners/effort, budgets, cleanup, and acceptance gates. Runtime cases need separate action approval and manual SSO/MFA prerequisites; missing approval/auth evidence means BLOCKED.

Do not implement or run tests, start services, send requests, browse targets, use credentials, or automate authentication. Proposed cases are **NOT RUN**; cite provenance for supplied results and never equate a plan with a verified fix.

Return the complete traceable plan as text. Report persistence is host-owned; the delegated agent must not write files or export reports.
