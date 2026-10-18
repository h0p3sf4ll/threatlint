---
name: threatlint-attack-tree
description: "Use for formal AND/OR attack trees: evidence-grounded leaves, prerequisite semantics, defense bypass analysis, risk ranking, and defensive test cases."
---

# Evidence-grounded attack trees

1. Define one asset, attacker objective, relevant persona/capability, system boundary, and
   successful outcome. Reuse prior findings only as leads; verify their current source evidence.
2. Decompose OR nodes into alternatives and AND nodes into genuinely required joint steps.
   Avoid mixing sequential order with logical necessity; annotate order separately when needed.
3. Ground every leaf in inspected code/configuration and name its prerequisites. Mark unknown
   runtime dependencies explicitly; unsupported branches are hypotheses, not exploitable facts.
4. Insert existing defenses at the actual boundary. For each defense evaluate a concrete bypass,
   evidence of effective enforcement, and whether runtime verification is still needed.
5. Rank leaves using the declared ordinal difficulty/impact scale and formula consistently.
   State that the resulting score is a prioritization aid, not a measured likelihood.
6. Identify minimal defensive cuts that interrupt the highest-impact paths and propose concrete
   code/config changes plus safe regression checks. Do not execute the attack tree.

## Deliverables

A valid Mermaid AND/OR tree, a leaf-to-evidence/prerequisite table, defense/bypass matrix,
ranked leaves, top-path purple-team validation plans with authorization/stop conditions, and
an engineering remediation roadmap. Keep diagram node IDs stable and labels safely quoted.