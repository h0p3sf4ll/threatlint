---
name: threatlint-finding-triage
description: "Use for false-positive review of SARIF, Semgrep JSON, or security reports: provenance, source-to-sink adjudication, original-ID mapping, actionable true-positive fixes, and unresolved evidence."
---

# Scanner finding adjudication

1. Identify artifact format, scanner/rule/version when supplied, scan revision, repository
   revision, and total findings. Resolve SARIF artifact indices/base URIs and related locations;
   do not follow remote URIs. Flag stale revisions and source excerpts that do not match.
2. Preserve original finding/rule IDs and all affected locations. Deduplicate by rule, location,
   and root cause while retaining the original-to-review mapping. Reconcile reviewed,
   duplicate, unreviewed, and invalid input totals; never silently drop a result.
3. Read the flagged function, callers, relevant configuration, and sink implementation. Trace
   attacker source → transforms → control → sink. Verify controls on the same value/path/context.
4. Assign TRUE POSITIVE, FALSE POSITIVE, or AMBIGUOUS independently of severity/confidence.
   Reachable exploit evidence supports TP. A demonstrably incorrect match or effective
   contextual defense supports FP. Missing rule/source/runtime evidence remains AMBIGUOUS.
5. Do not dismiss input because it is authenticated, admin-only, internal, constant-looking,
   or in tests/generated/vendor code. Verify the specific rule's claim and actual usage.
   Structural misconfiguration and secret rules may not require an attacker-controlled input.
6. For TPs provide a concrete proposed code/config fix, root-cause explanation, deployment
   considerations, regression assertions, acceptance, suggested owner, and effort.
7. For FPs separate the verdict from tuning safety. A correct FP verdict does not prove a
   broad suppression is safe. Require scanner-rule evidence before proposing an exact patch.
8. For ambiguous results keep the finding open, identify the single decisive evidence gap,
   who can resolve it, how to obtain it safely, and the conservative interim action.

## Report gate

Deliver executive decisions plus detailed per-finding reasoning, original-ID mapping,
proposed fixes, suppression impact, unresolved questions, and an ordered remediation plan.
Never report a finding resolved or a proposal validated simply because code was suggested.