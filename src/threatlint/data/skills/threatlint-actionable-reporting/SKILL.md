---
name: threatlint-actionable-reporting
description: "Use when writing any Threatlint findings report: executive communication, prioritized remediation, proposed fixes, engineering handoff, acceptance criteria, and honest validation status."
---

# Professional findings and remediation reports

## Writing standard

Write for both a security decision-maker and the engineer implementing the fix. Use complete,
precise sentences, descriptive titles, consistent terminology, and a neutral professional tone.
Explain what is wrong, why it matters here, and exactly what to change. Avoid vague advice
such as "sanitize input", unsupported alarmism, boilerplate checklists, and repeated prose.

## Required structure

1. **Document header**: report type, repository, date, scope, revision, input provenance,
   reviewer, and limitations. Do not guess a scan revision or an unavailable timestamp.
2. **Executive summary**: concise overall risk, reconciled counts, and a prioritized action
   table linking stable finding IDs to business impact, action, suggested owner, and effort.
   Order actions by supported impact, reachability, attacker prerequisites, affected assets,
   and blast radius. Explain the ordering when a noisy scanner severity differs from the
   source-backed risk. Clearly distinguish unresolved evidence gaps from verified vulnerabilities.
3. **Technical findings**: use `#### [PREFIX-NNN] — Descriptive title` and explicit
   `**Severity**`, `**Confidence**`, and, when relevant, `**Disposition**` fields.
   Preserve upstream IDs in a separate original-ID field. Quote inspected `path:line`
   evidence. For code-path findings, show the reachable entry/caller, gate or branch,
   sensitive operation, observed control, and at least one inspected bypass variant or named
   unresolved variant. For declarative findings, show resource activation, dependency usage,
   or credential exposure and the affected boundary without inventing a call chain.
   Separate inspected code, supplied runtime observation, and inference. Give a validation
   status for each finding: static path only, supplied runtime evidence with provenance,
   blocked/inconclusive, or NOT RUN. Do not call a scanner label a reproduced vulnerability.
4. **Prioritized root-cause fix**: for each actionable vulnerability, give the smallest
   effective change as a before/after snippet or unified diff anchored to a real
   function/configuration. Explain which root cause and equivalent paths it closes, why a
   symptom-only change would leave the bypass, compatibility implications, migration order,
   rollback considerations, and remaining defenses. Keep fix and priority tied to the
   traced impact and reachability. Never apply the proposal yourself.
5. **Bypass regression acceptance**: specify positive, negative, boundary, alternate-path,
   and bypass assertions with expected behavior at the security boundary and sensitive
   side effect. Where the repository's test stack is known, name a concrete test layer and
   fixture. State which pre-fix assertion would expose the root cause and what post-fix
   evidence would close the finding. Label every proposed command/test **NOT RUN**; cite
   artifact, revision, environment, and observed assertion for any supplied result. A
   planned test or patch snippet is not evidence that validation succeeded.
6. **Remediation roadmap**: ID, priority, action, suggested owner, effort estimate, dependency,
   acceptance criterion, and residual risk. Group duplicate symptoms under one root-cause
   action while retaining all original IDs and affected locations. Distinguish recommendation
   from agreed ownership.

## Before delivery

- Reconcile summary totals with detailed findings, including duplicates/unreviewed items.
- Every material claim has observed evidence or an explicit assumption; every proposed fix
  addresses that specific claim. Do not fabricate file locations for examples.
- The report names the path to the affected code or configuration, disconfirming result,
  validation provenance or its absence, root-cause fix, and bypass regression acceptance for
  each material finding.
- No raw secrets, personal data, unsupported certification claims, or fake validation results.
- Mark illustrative snippets and unvalidated scanner-rule proposals explicitly.
- Include "No material findings in the inspected scope" when true; do not manufacture issues.
- End with a clear decision and the next concrete engineering action, not a generic disclaimer.
