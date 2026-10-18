---
name: threatlint-threat-delta
description: "Use for comparing prior security reports against current source: stable finding identity, revision alignment, resolved/regressed/new classification, and transparent net-risk accounting."
---

# Security report delta analysis

1. Extract prior finding IDs, rule/title, scope, severity, confidence, source revision, affected
   locations, root cause, and required fix. Record absent metadata instead of guessing a baseline.
2. Align old/current revisions and moved files/symbols. A line number change or removed file
   does not establish a fix; trace replacement code, callers, and equivalent vulnerable paths.
3. Re-evaluate each original path and defense. RESOLVED requires the root cause eliminated
   or a verified architectural barrier; PARTIALLY FIXED retains a reachable variant; STILL
   PRESENT has no material closure; REGRESSED requires evidence a previous effective fix existed.
4. Separate WONT FIX/ACCEPTED decisions and CANT ASSESS evidence gaps from technical closure.
   An accepted risk remains risk. Preserve original IDs; assign distinct IDs to new root causes.
5. Inspect changes within the stated comparison for NEW findings. Do not imply full repository
   coverage when only a diff or partial artifact was available.
6. Reconcile verdict counts and severity changes. Explain net risk qualitatively rather than
   treating ordinal severities as additive financial values or hiding unresolved unknowns.

## Deliverables

Finding-by-finding old/new evidence, verdict rationale, severity/confidence changes,
regressions prominently flagged, ticket close/reopen/open actions, proposed remaining fixes,
acceptance criteria, and baseline/coverage limitations.