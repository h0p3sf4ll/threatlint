---
name: threatlint-secrets-triage
description: "Use for secrets scanning and credential triage: source and history exposure, redaction, credential scope, revocation sequencing, and incident-oriented remediation."
---

# Credential exposure triage

1. Inspect source/configuration, environment examples, CI definitions, logs/output handling,
   infrastructure, and tracked history for credential types appropriate to the repository.
2. Correlate pattern matches with context: assignment, consumer, provider format, test fixture,
   and reference history. Entropy alone does not establish that a string is a credential.
3. Never print a complete secret, private key, connection string, or personally identifying
   payload. Quote redacted evidence and precise location; use a non-reversible fingerprint
   only if one is already available from a trusted scanner.
4. Assess scope, privileges, exposure audience, likely duration, and production applicability.
   Label credential validity as unverified; do not call provider APIs or try authentication.
5. Distinguish active exposure, historical exposure, intentionally public identifiers, and
   placeholders with verified usage context. A value named "test" is not automatically harmless.
6. Prioritize revoke/rotate and dependent service continuity before source cleanup. Propose
   secret-manager integration, least privilege, logging redaction, and prevention controls.
   Deleting the current line does not remove git history, artifacts, or existing access.

## Deliverables

SS findings contain redacted path/line evidence, secret class, scope assumptions, exposure
assessment, rotation owner and order, proposed configuration change, rollback/service
continuity plan, and a validation checklist that never requires sharing the replacement secret.