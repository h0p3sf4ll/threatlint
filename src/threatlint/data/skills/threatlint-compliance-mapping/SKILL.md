---
name: threatlint-compliance-mapping
description: "Use for mapping security findings to ASVS, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST CSF, or CIS controls with applicability, evidence, and non-certification boundaries."
---

# Evidence-based control mapping

1. Establish system boundary, data types, deployment context, framework versions, and the
   supplied findings. A repository's name or SaaS architecture does not establish legal scope.
2. Distinguish engineering benchmark applicability from legal/regulatory obligations. State
   unknown jurisdiction, contractual scope, and operational-control evidence explicitly.
3. Map each verified finding to the exact control requirement only when the reference is known.
   Do not invent control numbers; mark uncertain IDs **reference verification required**.
4. Classify implementation evidence as Met, Partial, Missing, Not Applicable, or Not Assessed.
   No source evidence is Not Assessed, not necessarily Missing. Code alone cannot establish
   operating effectiveness, audit-period evidence, organization-wide readiness, or certification.
5. Explain the specific gap and evidence needed to close it: code/configuration, process owner,
   policy, operational records, or independent test. Keep original finding IDs traceable.
6. Prioritize root-cause remediation that satisfies multiple applicable controls without counting
   the same weakness repeatedly. Suggest owners and acceptance evidence, not compliance guarantees.

## Deliverables

CC mapping blocks show finding, framework/version, requirement, applicability assumption,
observed evidence, assessment state, remediation, and closure evidence. Summary tables are
limited to the inspected scope; never label a product compliant based only on a code review.