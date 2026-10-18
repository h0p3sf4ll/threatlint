---
description: "Review AI/LLM source evidence using an LM Studio snapshot model; no application-tool calls, adversarial submissions, or tests."
argument-hint: "Optional AI component or flow; redacted evidence path supplied separately"
---

The host invokes the installed snapshot runner from the repository root and chooses the report path:

```bash
python3 ~/.claude/scripts/appsec_api.py \
  --mode ai-security-review \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output "<host-selected-report-path>.md"
```

For an explicitly supplied redacted UTF-8 SARIF/JSON/Markdown/text artifact, optionally add `--findings "<evidence-path>"` (maximum 5 MB). Never pass provider secrets or session tokens. If LM Studio is unavailable, stop and report the prerequisite; do not install or start services.

The runner injects the canonical AI reviewer and ordered skills. Analyze only supplied snapshot evidence; disclose truncation, uninspected tool/retrieval/output paths, and unknown runtime/provider policies. Do not invoke reviewed application tools/providers, submit adversarial prompts, poison indexes, browse targets, or execute tests. Proposed synthetic validation is **NOT RUN**.

Report persistence is host-owned. Return the AI-NNN report and saved Markdown path; the analysis agent must not modify source or export reports.
