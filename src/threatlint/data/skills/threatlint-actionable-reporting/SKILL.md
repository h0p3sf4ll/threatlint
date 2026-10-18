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
   Clearly distinguish unresolved evidence gaps from verified vulnerabilities.
3. **Technical findings**: use `#### [PREFIX-NNN] — Descriptive title` and explicit
   `**Severity**`, `**Confidence**`, and, when relevant, `**Disposition**` fields.
   Preserve upstream IDs in a separate original-ID field. Quote inspected `path:line`
   evidence; distinguish existing code from a hypothetical example or proposed change.
4. **Proposed fix**: for each actionable vulnerability, give the smallest effective change
   as a before/after snippet or unified diff anchored to a real function/configuration.
   Explain why it closes the root cause, compatibility implications, migration order,
   rollback considerations, and remaining defenses. Never apply the proposal yourself.
5. **Validation plan**: specify positive, negative, boundary, and bypass regression assertions
   with expected outcomes. Use the repository's actual test stack when known. Label every
   proposed command/test **NOT RUN** unless execution evidence was provided or obtained.
6. **Remediation roadmap**: ID, priority, action, suggested owner, effort estimate, dependency,
   acceptance criterion, and residual risk. Distinguish recommendation from agreed ownership.

## Before delivery

- Reconcile summary totals with detailed findings, including duplicates/unreviewed items.
- Every material claim has observed evidence or an explicit assumption; every proposed fix
  addresses that specific claim. Do not fabricate file locations for examples.
- No raw secrets, personal data, unsupported certification claims, or fake validation results.
- Mark illustrative snippets and unvalidated scanner-rule proposals explicitly.
- Include "No material findings in the inspected scope" when true; do not manufacture issues.
- End with a clear decision and the next concrete engineering action, not a generic disclaimer.