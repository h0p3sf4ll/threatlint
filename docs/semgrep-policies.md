# Semgrep policy compatibility and tuning

Threatlint reads legacy policies first. Only **HTTP 410** selects Unified Policies
V2; authentication, authorization, transport, and other errors are not hidden by
a fallback. Unified reads inspect both Code and Secrets, since a finding classified
as Secrets can reference a Code rule. Only a structured `PRODUCT_NOT_ENABLED`
404 skips a disabled product.

## Project context

Pass the **exact Semgrep project name**, not its numeric ID or a local directory:

```shell
threatlint semgrep rule-base example.rule --kind secrets \
  --project organization/repository --output rule.yaml
```

The Python `existing_tuning`, `rule_base`, `tune_rule`, `disable_originals`, and
`replace_in_policies` interfaces accept keyword-only `project=...`. Legacy calls
remain compatible. Unified reads without a project inspect deployment selections
only; they cannot discover project-only includes. Reads with a project honor its
individual rule includes/excludes. Pack expansion and project-tag membership are
not inferred; relevant ambiguous exceptions fail closed.

## Unified mutation limits

V2 detection selection is **not** legacy `MODE_MONITOR`, `MODE_COMMENT`, or
`MODE_BLOCK`. Automatic `tune_rule` publication and shared-rule republishing are
unsupported on Unified deployments and fail before publication. Existing live
tuning can still supply the rule base and satisfy the no-op path without
republishing. A shared rule is never republished as a project-scoped change.
If the live tuning already covers the false positive but the original still
runs, `tune_rule` can repair the project exception and returns that change with
its rollback data; an already-correct policy produces no writes.

For an already published, independently validated rule, an explicitly reviewed
detection-only replacement can use:

```python
changes = semgrep_platform.replace_in_policies(
    token, deployment, "sast", original_rule, published_tuned_rule,
    project="organization/repository", mode="include",
)
```

This opts into detection selection only, not a remediation or blocking mode.
Without that explicit mode, the legacy monitor default is rejected on V2.
Replacement requires a directly selected original rule; ruleset-only membership
cannot establish which product to replace. `disable_originals(..., project=...)`
can add a project exclusion for a ruleset original when an enabled tuned rule
already identifies the product. It never disables the original deployment-wide.
Unified mutations without an explicit project name fail closed.

## Replacement safety and rollback

The adapter reads the complete bundle and state version, preserves unrelated
rulesets, rules, disabled entries, and all existing exceptions, and changes only
the target project's original exclusion and tuned inclusion. It submits that
exact bundle to `:dryRun`, rejects validation errors or a changed preview version,
then PUTs with `If-Match` using the previewed version. Conditional writes are
never automatically retried, including after timeouts or server failures.
HTTP 409 requires a new read and proposal; no stale write is replayed.

A fresh GET verifies the persisted bundle and version. Each successful change
returns `state_version` and `rollback`, containing the endpoint, the complete
prior bundle in `body`, and the post-apply `if_match` version. Errors after an
attempted write also expose available recovery data as `SemgrepError.rollback`.
An uncertain write may have no safe rollback version: inspect current state
first. Do not execute rollback blindly or substitute a newer concurrent version.
Dry-run any proposed rollback and reject conflicts just like a forward change.
No rollback is executed automatically.
