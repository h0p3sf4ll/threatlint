---
name: threatlint-secure-code-review
description: "Use for security review of working-tree diffs, commits, branches, and pull requests: regression scope, call-graph context, removed controls, and merge recommendations."
---

# Security change review

1. Establish base/head or working-tree scope, staged and unstaged changes, and untracked files
   relevant to the change. Record the exact comparison; do not silently substitute another range.
2. Identify changed boundaries: routes, identity decisions, input parsing, query/shell/file/URL
   sinks, cryptography, secret handling, dependencies, build pipelines, and infrastructure.
3. Read the entire changed function, immediate callers, and control registration. A correct
   helper that is no longer invoked is a regression. Follow deleted validation to its replacement.
4. Compare old and new behavior. Label pre-existing issues separately instead of calling every
   adjacent vulnerability a newly introduced regression. Inspect history when intent matters.
5. Trace realistic attacker input to impact; consider alternate verbs/routes, role and tenant
   boundaries, parser differences, error/fallback paths, and security-relevant concurrency.
6. Recommend BLOCK for confirmed critical/high regressions, MERGE WITH ACTION for plausible
   high or confirmed medium risk, otherwise MERGE only within the inspected scope. Explain
   uncertainty and missing callers rather than treating an incomplete review as approval.

## Engineering handoff

For each CR finding cite changed lines plus supporting caller/control evidence, propose the
smallest patch, identify compatibility risks, and give a regression assertion that fails before
and passes after. Include security-positive changes and explicit coverage limitations.