---
name: "Discover Application Threat Model"
description: "Autonomously discover an unfamiliar repository's application architecture, select an evidence-supported security scope, and produce a two-tier AppSec threat model: executive summary with risk posture and top actions, plus a full technical threat register with attack chains, STRIDE/OWASP/CWE mapping, confidence levels, and a prioritized remediation roadmap."
argument-hint: "Optional focus, risk area, or path; leave blank to discover the application"
agent: "AppSec Threat Modeler"
---

Start an initial threat model without assuming the user knows the application or can name a target. Autonomously inspect the repository, select an evidence-supported scope, and produce a two-tier report.

## Discovery Instructions

1. Inventory top-level documentation, manifests, source roots, dependency files, deployment configuration, IaC, and CI/CD workflows.
2. Identify candidate application components, external entry points, identities, sensitive data, privileged operations, external services, and trust boundaries.
3. Rank candidate scopes by: (a) external exposure, (b) privilege level of the executing identity, (c) sensitivity of data touched, (d) blast radius if compromised. Select the highest-risk representative scope and state the rationale with evidence references.
4. Proceed immediately with the full threat model. Do not ask the user to identify a target before completing this initial discovery.

Clearly separate repository evidence, assumptions, unknowns, and items that need user or runtime confirmation. Do not claim the initial scope represents every component in a multi-application repository.

## Required Output

Produce a two-tier report directly in the response. Do not create, edit, or save workspace files.

**TIER 1 — EXECUTIVE SUMMARY** must include:
- Risk posture (one to two sentences: overall security maturity and highest-priority concern)
- Finding summary table (severity × confidence tier: CONFIRMED / PLAUSIBLE / THEORETICAL)
- Top Immediate Actions — Critical and High findings only, each with a one-sentence business risk and one-sentence technical action
- Regulatory and compliance exposure when evidence supports it (PCI-DSS, GDPR, HIPAA, SOC 2, ISO 27001)
- A single Recommended Next Step for the team

**TIER 2 — TECHNICAL THREAT MODEL** must include:
- Discovery and scope selection: inventory summary, candidate ranking, selected scope rationale, excluded components
- Scope and assumptions: reviewed components, exclusions, numbered assumption list, unresolved unknowns
- System model: assets with data classifications, actors with trust levels, entry points, data flows, trust boundaries, key dependencies
- Threat register: each finding as a structured block with Finding ID, severity, confidence tier, attacker persona, STRIDE/OWASP/CWE, preconditions, step-by-step attack chain, code/configuration evidence (file:line), affected asset, impact, likelihood, mitigation, validation step, and remediation effort (Immediate / Short-term / Long-term)
- Prioritized remediation roadmap table: Priority, Finding ID, Severity, Effort, Suggested Owner
- Residual risk and open questions: THEORETICAL findings, unresolved runtime unknowns, evidence needed to close open questions

## Focused Follow-Ups

End the report with **Suggested Focused Follow-Ups** — three to five ready-to-send prompts, each:
- Naming an actual discovered component, path, workflow, integration, or trust boundary
- Asking one narrow security question rather than requesting another repository-wide review
- Prioritizing the highest-risk or least-certain areas from the discovery findings
- Including the relevant threat focus (authorization, secrets, tenant isolation, request validation, webhook verification, data exposure, CI/CD privileges, supply-chain risk)

Only suggest follow-ups supported by discovered evidence. If no application component can be identified, suggest the smallest set of repository or runtime details that would enable a focused review.
