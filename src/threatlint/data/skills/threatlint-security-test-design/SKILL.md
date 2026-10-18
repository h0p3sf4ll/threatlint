---
name: threatlint-security-test-design
description: "Use for evidence-grounded security test planning: risk and requirement traceability, safe fixtures, positive/negative/bypass assertions, role/tenant coverage, separate runtime authorization, and honest execution status."
---

# Security acceptance and test planning

## Planning boundary

Design tests from inspected source, requirements, and supplied findings/artifacts. Do not
implement test files, install dependencies, start services, invoke scanners/browsers, send
requests, use credentials, or run test/attack code. A separate user-authorized runtime engine
may execute an approved plan; neither its existence nor an approval grants the LLM executor
access. Runtime execution and authentication approvals must remain separate from this role.

## Procedure

1. Record revision, scope, source-backed invariants/findings, input provenance, and inspected
   test framework/fixtures. Preserve upstream IDs and dispositions. Unverified scanner claims
   are hypotheses to assess, not facts a test plan may silently promote to vulnerabilities.
2. Build a requirement/finding → boundary/control → case mapping. Prioritize by asset impact,
   reachability, role/tenant exposure, and confidence; state uninspected areas and evidence
   gaps. Use ST-NNN for plan items, not as replacement IDs for original findings.
3. Select the lowest-risk useful layer: static/unit, component, isolated integration, then
   separately authorized runtime or manual checks only where necessary. Prefer mocks/stubs,
   disposable local fixtures, synthetic keys/accounts/data, and deterministic state reset.
   Do not assume a proposed framework or test file already exists.
4. Specify each case's invariant, source evidence, preconditions, actor/role/tenant, fixture,
   action description, observable oracle, expected result, cleanup responsibility, and limits.
   Include allowed-success, denied, boundary, replay/alternate-path and cross-tenant variants
   as applicable. Check side effects and data isolation, not just status codes or headers.
5. For races, design bounded deterministic interleavings and assert durable invariants after
   both operations, retries, and rollback. Do not propose unbounded concurrency, production
   load, real purchases/transfers, credential guessing, destructive payloads, or exfiltration.
6. For runtime-dependent cases, define an authorization envelope: explicit environment and
   allowed origins/actions, approved synthetic identities, request/concurrency/time budgets,
   manual SSO/MFA handoff, stop conditions, data redaction, and engine-owner cleanup. Use the
   runtime-auth-workflows skill. Missing approval or auth state means **BLOCKED**, not a bypass.
7. Keep **NOT RUN**, **BLOCKED**, and **INCONCLUSIVE** distinct from **PASS/FAIL supported by
   supplied evidence**. A pass needs revision, environment, actual assertion result, artifact
   reference, and provenance; a plan or existing test name is not evidence of execution.
8. Define an acceptance gate with must-pass case IDs, residual-risk decisions, suggested
   owners/effort, rollout dependencies, and the exact evidence needed for closure. Never claim
   a proposed fix is verified because its test design is complete.

## Deliverables

Provide a prioritized ST plan, traceability/coverage matrix, case specifications, authorization
and authentication prerequisites, proposed fix or test-coverage improvement where warranted,
owner/effort, acceptance criteria, and an evidence-status ledger. Unknown expectations require
an owner decision rather than an invented oracle. Advisory snippets are explicitly illustrative
and **NOT RUN**. Report zero security findings when appropriate; test gaps are not themselves
proof of a vulnerable implementation.
