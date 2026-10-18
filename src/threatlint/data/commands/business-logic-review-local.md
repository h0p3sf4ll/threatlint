---
description: "Review business-logic evidence using an LM Studio snapshot model; no transactions, requests, races, or test execution."
argument-hint: "Optional business flow or component; redacted evidence path supplied separately"
---

The host invokes the installed snapshot runner from the repository root and chooses the report path:

```bash
python3 ~/.claude/scripts/appsec_api.py \
  --mode business-logic-review \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output "<host-selected-report-path>.md"
```

For an explicitly supplied redacted UTF-8 SARIF/JSON/Markdown/text artifact, optionally add `--findings "<evidence-path>"` (maximum 5 MB). Never pass credentials or session tokens. If LM Studio is unavailable, stop and report the prerequisite; do not install or start services.

The runner injects the canonical business-logic reviewer and ordered skills. Analyze only supplied snapshot evidence; disclose truncation, uninspected code, and unknown invariants/concurrency semantics. Do not send requests, execute races, replay webhooks, place orders, transfer value, or run tests. Proposed validation is **NOT RUN**.

Report persistence is host-owned. Return the BL-NNN report and saved Markdown path; the analysis agent must not modify source or export reports.
