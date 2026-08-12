---
name: "Threat Model Report"
description: "Generate a standardized, decision-ready AppSec threat model report for source code, a feature, service, architecture, or relevant configuration. Produces a two-tier report: executive summary with risk posture and top actions, plus a full technical threat register with STRIDE/OWASP/CWE mapping, attack chains, confidence levels, and a prioritized remediation roadmap."
argument-hint: "Source code, feature, service, repository area, or architecture to analyze"
agent: "AppSec Threat Modeler"
---

Create a team-ready application security threat model report for the code, configuration, or architecture supplied in this chat. Treat the supplied target as the review scope and inspect directly relevant local context when needed. If no usable target is supplied, autonomously discover the repository, select an evidence-supported scope, and explain the selection before writing the report.

## Report Requirements

- Ground each material conclusion in inspected code or configuration. Label assumptions, exclusions, and unknowns explicitly.
- Assign each finding a confidence tier: CONFIRMED (directly exploitable as written), PLAUSIBLE (likely exploitable; one unverified condition separates it from confirmed), or THEORETICAL (possible but not confirmable from static analysis).
- Evaluate each attack surface against applicable attacker personas: External/Unauthenticated, Authenticated User, Privileged Insider, Supply-Chain, Infrastructure/Cloud.
- Apply STRIDE and OWASP Top 10 as complementary lenses. Prefer concrete end-to-end attacker paths over broad security checklists.
- Prioritize findings by combined impact and likelihood.
- Include IaC, CI/CD, and dependency configuration when it affects the security posture.
- Use repository-relative file paths and line numbers for all evidence.

## Required Report Structure

### TIER 1 — EXECUTIVE SUMMARY

1. **Risk Posture** — one to two sentences: overall security maturity and the single highest-priority concern
2. **Finding Summary** — table of severity counts broken down by CONFIRMED / PLAUSIBLE / THEORETICAL
3. **Top Immediate Actions** — Critical and High findings only, each with one sentence of business risk and one sentence of required technical action
4. **Regulatory and Compliance Exposure** — when evidence supports it: implicated regime, specific data type or control gap
5. **Recommended Next Step** — the single most important decision or action the team should take this week

### TIER 2 — TECHNICAL THREAT MODEL

6. **Discovery and Scope Selection** — when scope was autonomously selected: repository inventory, candidate components ranked by risk, selected scope with rationale, excluded components
7. **Scope and Assumptions** — reviewed components, excluded areas, numbered assumption list, unresolved unknowns
8. **System Model** — assets with data classifications, actors with trust levels, entry points, data flows, trust boundaries, key dependencies
9. **Threat Register** — each finding as a structured block containing:
   - Finding ID, Severity, Confidence tier, Attacker persona
   - STRIDE category, OWASP Top 10 mapping, CWE identifier
   - Preconditions
   - Step-by-step attack chain
   - Code or configuration evidence with file:line reference
   - Affected asset or boundary
   - Impact and Likelihood
   - Mitigation (smallest effective fix)
   - Validation step
   - Remediation effort: Immediate / Short-term / Long-term
10. **Prioritized Remediation Roadmap** — table: Priority, Finding ID, Severity, Effort, Suggested Owner
11. **Residual Risk and Open Questions** — THEORETICAL findings, runtime conditions that would change the risk profile, evidence needed to close open questions, excluded areas with unknown risk

State clearly when no material threats are found in the reviewed scope. Do not claim comprehensive coverage beyond the inspected evidence.
