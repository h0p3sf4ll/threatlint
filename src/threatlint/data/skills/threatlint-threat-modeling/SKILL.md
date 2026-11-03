---
name: threatlint-threat-modeling
description: "Use for evidence-based threat modeling, autonomous repository discovery, trust boundaries, STRIDE analysis, abuse cases, and risk-ranked attack chains."
---

# Source-grounded threat modeling

1. Inventory runtime components, entry points, identities, sensitive assets, external services,
   deployment settings, and CI/CD. Read supplied design inputs (diagrams, design documents, API specs,
   images, prior threat models) and in-repo design artifacts first to learn the intended architecture,
   then verify each claim against source; never trust a diagram over the code. Rank candidate scope by exposure, privilege, data sensitivity,
   and blast radius. Explain the selected scope and exclusions with evidence.
2. Draw a compact system/data-flow model with actor, process, store, and trust-boundary labels.
   Distinguish checked-in defaults from observed runtime configuration.
3. For each boundary, ask how spoofing, tampering, repudiation, disclosure, denial of service,
   or privilege escalation could affect the specific asset. Do not force a finding per STRIDE class.
4. Trace each candidate abuse path through actual functions/configuration. Test every claimed
   defense against a realistic alternate path: encoding, route alias, role, tenant, protocol,
   redirect, race, or fallback. Record "no feasible bypass found" with the verified control.
5. Model combined paths only when prerequisites connect. Identify the earliest effective cut
   in the chain; do not count one root cause repeatedly to inflate risk.
6. Prioritize on actual impact and exposure. Document the assumptions that would promote or
   invalidate a plausible finding. Do not present ordinal risk scores as measured probabilities.

## Deliverables

- Scope/ranking rationale, asset/actor inventory, data flows, and numbered assumptions.
- Design drift: undocumented implementation, unimplemented design, and claimed controls that the
  code does not enforce, citing `<design input> › <element>` alongside `path:line`.
- Stable TM findings with boundary, evidence, impact, feasible attack steps, and controls.
- Concrete proposed fixes, validation assertions, owners/effort, and residual runtime questions.
- Focused follow-up prompts naming real discovered components, not generic review topics.