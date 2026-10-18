---
description: "Review cryptographic source/configuration with an LM Studio snapshot model; no key use, TLS probes, or test execution."
argument-hint: "Optional cryptographic module; redacted evidence path supplied separately"
---

The host invokes the installed snapshot runner from the repository root and chooses the report path:

```bash
python3 ~/.claude/scripts/appsec_api.py \
  --mode crypto-review \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output "<host-selected-report-path>.md"
```

For an explicitly supplied redacted UTF-8 SARIF/JSON/Markdown/text artifact, optionally add `--findings "<evidence-path>"` (maximum 5 MB). Never pass keys, credentials, or session tokens. If LM Studio is unavailable, stop and report the prerequisite; do not install or start services.

The runner injects the canonical crypto reviewer and ordered skills. Analyze only supplied snapshot evidence; disclose truncation, uninspected callers, unknown library/deployment semantics, and missing key-lifecycle evidence. Do not use real keys, decrypt/crack data, probe TLS, run experiments, or execute tests. Proposed synthetic validation is **NOT RUN**.

Report persistence is host-owned. Return the CY-NNN report and saved Markdown path; the analysis agent must not modify source or export reports.
