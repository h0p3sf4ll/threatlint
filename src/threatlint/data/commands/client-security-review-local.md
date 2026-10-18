---
description: "Review browser, Electron, or mobile source evidence using an LM Studio snapshot model; no browser/app or test execution."
argument-hint: "Optional client or component; redacted evidence path supplied separately"
---

The host invokes the installed snapshot runner from the repository root and chooses the report path:

```bash
python3 ~/.claude/scripts/appsec_api.py \
  --mode client-security-review \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output "<host-selected-report-path>.md"
```

For an explicitly supplied redacted UTF-8 SARIF/JSON/Markdown/text artifact, optionally add `--findings "<evidence-path>"` (maximum 5 MB). Never pass credentials or session tokens. If LM Studio is unavailable, stop and report the prerequisite; do not install or start services.

The runner injects the canonical client reviewer and ordered skills. Analyze only supplied snapshot evidence; disclose truncation, uninspected source, platform assumptions, and unavailable runtime observations. Do not open browsers/apps, navigate targets, inject scripts, invoke IPC/deep links, access sessions, or run tests. Proposed validation is **NOT RUN**.

Report persistence is host-owned. Return the CL-NNN report and saved Markdown path; the analysis agent must not modify source or export reports.
