---
description: "Review generated or new code for insecure defaults with an LM Studio snapshot model; no code execution or test runs."
argument-hint: "Optional files or generated-code scope; redacted evidence path supplied separately"
---

The host invokes the installed snapshot runner from the repository root and chooses the report path:

```bash
python3 ~/.claude/scripts/appsec_api.py \
  --mode secure-codegen-review \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output "<host-selected-report-path>.md"
```

For an explicitly supplied redacted UTF-8 SARIF/JSON/Markdown/text artifact, optionally add `--findings "<evidence-path>"` (maximum 5 MB). Never pass secrets or credentials. If LM Studio is unavailable, stop and report the prerequisite; do not install or start services.

The runner injects the canonical secure-codegen reviewer and ordered skills. Analyze only supplied snapshot evidence; disclose truncation, uninspected callers, and unknown framework defaults. Do not execute code, payloads, or tests. Secure rewrites are **NOT APPLIED**; proposed validation is **NOT RUN**.

Report persistence is host-owned. Return the SG-NNN report and saved Markdown path; the analysis agent must not modify source or export reports.
