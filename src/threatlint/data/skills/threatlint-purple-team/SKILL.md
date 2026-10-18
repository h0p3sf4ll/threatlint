---
name: threatlint-purple-team
description: "Use for evidence-based adversarial scenario planning and purple-team validation: bounded kill chains, detection hypotheses, ATT&CK mappings, safe test plans, and hardening."
---

# Defensive adversarial scenario planning

1. Identify exposed assets, trust boundaries, controls, and evidence-backed attacker capabilities.
   Develop distinct scenarios rather than renaming the same exploit for different personas.
2. Include only supported kill-chain stages. If persistence or lateral movement is not visible,
   say it is not established instead of fabricating infrastructure or attacker access.
3. Map ATT&CK tactics/techniques only when the behavior actually matches a known technique.
   An uncertain identifier is **mapping unverified**, never an invented authoritative citation.
4. Separate observed telemetry from suggested detection. Absence of a logger in source does
   not prove no infrastructure/SIEM detection exists; name that operational visibility gap.
5. Write purple-team plans as authorized, non-destructive validation: isolated test environment,
   synthetic data, bounded inputs, required access, expected prevention/detection, stop criteria,
   and cleanup owner. No live exploitation, credential testing, persistence, or exfiltration.
6. Prioritize code-specific prevention and detection improvements. Explain which scenario step
   each proposed change interrupts and how a defender can verify the outcome.

## Deliverables

RT scenarios include actor, objective, prerequisites, source-grounded chain, evidence,
detection hypotheses, proposed defenses, and expected safe-test outcomes. If the requested
five personas lack distinct evidence, retain the slots as evidence gaps rather than inventing attacks.