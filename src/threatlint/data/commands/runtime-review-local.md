---
description: "Review redacted runtime evidence with an LM Studio snapshot model. No live requests, authentication, captures, or test execution."
argument-hint: "Scope; provide an explicit redacted Markdown/text/JSON evidence path separately"
---

Use the installed snapshot runner from the repository root. The host, not the analysis agent, invokes the runner and selects the report output path:

```bash
python3 ~/.claude/scripts/appsec_api.py \
  --mode runtime-review \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --findings "<explicit-redacted-evidence-path>" \
  --output "<host-selected-report-path>.md"
```

Only use an explicitly supplied UTF-8 SARIF/JSON/Markdown/text artifact (maximum 5 MB); omit `--findings` when none is supplied. Never include credentials, cookies, or session tokens. If LM Studio is unavailable or no model is loaded, stop and report the prerequisite; do not install or start services.

The runner injects the canonical runtime-reviewer and ordered skills. It has a bounded repository snapshot, not live inspection or runtime tools. Disclose truncation, uninspected files, missing source/build/auth context, and supplied evidence provenance. Do not collect captures, browse targets, log in, automate SSO/MFA, or execute scans/tests; proposed validation is **NOT RUN**.

Report persistence is host-owned. Return the DX-NNN analysis and saved Markdown path without modifying repository source or delegating export to the analysis agent.
