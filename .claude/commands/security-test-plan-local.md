---
description: "Plan traceable security acceptance cases with an LM Studio snapshot model; no test implementation or execution."
argument-hint: "Finding, invariant, or scope; explicit redacted evidence path supplied separately"
---

The host invokes the installed snapshot runner from the repository root and chooses the report path:

```bash
python3 ~/.claude/scripts/appsec_api.py \
  --mode security-test-plan \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output "<host-selected-report-path>.md"
```

For explicitly supplied findings or invariants, optionally add `--findings "<redacted-evidence-path>"` for a UTF-8 SARIF/JSON/Markdown/text artifact (maximum 5 MB). Never pass credentials or session tokens. If LM Studio is unavailable, stop and report the prerequisite; do not install or start services.

The runner injects the canonical test planner and ordered skills, including runtime-auth-workflows. It sees only supplied snapshot evidence; disclose truncation, unknown oracles, and missing source/auth/authorization context. Plan synthetic cases and preserve original finding IDs. Do not write/execute tests, start services, make requests, browse targets, log in, or automate SSO/MFA. Proposed cases are **NOT RUN**; missing approval/auth state is BLOCKED.

Report persistence is host-owned. Return the ST-NNN plan and saved Markdown path; a completed plan is not a verified fix, and the analysis agent must not modify source or export reports.
