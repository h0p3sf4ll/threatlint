---
name: threatlint-runtime-validation
description: "Use for read-only runtime security evidence review: correlate authorized captures with source, distinguish observations from vulnerabilities, and assess reachability, authentication, controls, and validation limits."
---

# Runtime evidence and validation review

## Execution boundary

Review source and already supplied, redacted runtime artifacts only. A user-authorized runtime
engine is a separate executor with its own target, action, and authentication approvals. This
skill does not authorize the LLM to start that engine, issue requests, replay traffic, open a
browser, run scanners or payloads, authenticate, or invoke an executor through another tool.
If evidence is absent, propose a bounded collection plan and mark it **NOT RUN**.

## Procedure

1. Record repository/revision, deployed build if known, target/environment, capture provenance,
   timestamp, engine/check version if supplied, request method/path, redirects, and redaction
   limits. An approved target is not proof that every action or redirected origin is approved.
2. Correlate each observation to the actual route, middleware, configuration, dependency, and
   sensitive operation. Account for reverse proxies, caches, service workers, feature flags,
   and deployment drift. Do not invent source locations when only a capture is available.
3. Establish the observed identity, role, tenant, authentication state, resource ownership, and
   expected access policy. Use the runtime-auth-workflows skill when assigned. An expired
   session, SSO redirect, WAF response, or error page may invalidate an apparent comparison.
4. Separate **observation**, **hardening opportunity**, **vulnerability candidate**, and
   **verified vulnerability**. A missing header, unexpected status, scanner label, CORS header,
   cookie attribute, or server banner alone does not demonstrate a security boundary failure.
   For example, HTTP 200 can be a login page; 403 can occur after a forbidden side effect.
5. Evaluate actual semantics: browser applicability and credential mode for CORS, protected
   content and effective framing policy for clickjacking, TLS termination for HSTS, and
   identity/tenant/object outcomes for authorization. Inspect compensating controls and
   alternate paths. A candidate needs a credible attacker-to-impact path, not just a signature.
6. Distinguish a source-established defect from a runtime-observed failure. A verified runtime
   vulnerability requires supplied evidence of the relevant boundary failure and impact;
   **CONFIRMED** never means this reviewer executed an exploit. Name each missing condition
   for **PLAUSIBLE** or **THEORETICAL**, and keep severity independent of confidence.
7. Propose the smallest source/configuration fix, owner, effort, compatibility effects, and
   acceptance assertions. Any additional engine collection needs separate user authorization,
   allowlisted origins/actions, synthetic fixtures, request/time budgets, redaction, and stop
   conditions. Do not turn an evidence gap into a claim that a control passed or failed.

## Sandbox DAST evidence (dynamic-scan AVITs)

Evidence from `threatlint avit dast` is SUPPLIED EVIDENCE from an ephemeral sandbox: the named
branch built and deployed with synthetic configuration on a network without egress, the
repository's own test results, and redacted requests/responses sent only to that sandbox. The
scanned production origin was never contacted. Judge it as follows:

- Confirm the deployment was healthy and its tests ran; a failed build, unhealthy app, or route
  that returned 404/500 for an unrelated reason means the check did not exercise the finding.
- Observed exploit behaviour (unencoded marker in an HTML response, database error or boolean
  differential, redirect to the probe origin, file content returned) on the flagged route,
  traced to the sink in source, supports TRUE POSITIVE. Encoding/parameterisation in source that
  explains why the behaviour was not observed supports FALSE POSITIVE.
- The sandbox lacks the production edge (TLS, WAF, proxy headers, CDN). HSTS, Secure cookies and
  edge-set headers cannot be judged from it; decide those from deployment configuration or stay
  AMBIGUOUS. Passive header/cookie/banner observations are hardening signals, not the finding.
- Differences between the branch and what was scanned (revision, feature flags, configuration)
  are named limits. Write the report lines the evidence supplies and propose no Semgrep tuning.

## Deliverables

DX findings include quoted source paths with 1-based lines and artifact IDs/locations, revision
alignment, observation versus inference, affected identity/tenant, control and bypass assessment,
prerequisites, impact, proposed fix, owner/effort, and positive/negative/boundary acceptance
criteria. Preserve upstream check IDs separately. Classify validation as **SUPPLIED EVIDENCE**
(with provenance and limits) or **NOT RUN**; never imply independent reproduction. Inventory
blocked, inconclusive, out-of-scope, and uninspected cases separately from vulnerability counts.
