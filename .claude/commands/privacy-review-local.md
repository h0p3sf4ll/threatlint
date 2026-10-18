---
description: "Review personal/sensitive-data flows with an LM Studio snapshot model; no data access, network calls, or test execution."
argument-hint: "Optional data domain or module; redacted evidence path supplied separately"
---

The host invokes the installed snapshot runner from the repository root and chooses the report path:

```bash
python3 ~/.claude/scripts/appsec_api.py \
  --mode privacy-review \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output "<host-selected-report-path>.md"
```

For an explicitly supplied redacted UTF-8 SARIF/JSON/Markdown/text artifact, optionally add `--findings "<evidence-path>"` (maximum 5 MB). Never pass real personal data or credentials. If LM Studio is unavailable, stop and report the prerequisite; do not install or start services.

The runner injects the canonical privacy reviewer and ordered skills. Analyze only supplied snapshot evidence; disclose truncation, uninspected integrations, and unknown infrastructure. Do not query data stores, contact third parties, or execute tests. This is not a legal opinion; proposed validation is **NOT RUN**.

Report persistence is host-owned. Return the PD-NNN report and saved Markdown path; the analysis agent must not modify source or export reports.
