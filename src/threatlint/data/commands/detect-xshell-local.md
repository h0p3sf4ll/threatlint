---
description: "Detect *-2Shell (React2Shell, Next.js, PHP2Shell, WP2Shell, Node2Shell) and *-4Shell (Log4Shell, Spring4Shell, Text4Shell, Java4Shell) exposures with an LM Studio snapshot model; no installs, network probes, or test execution."
argument-hint: "Optional package root, app or module directory; detector output path supplied separately"
---

The host invokes the installed snapshot runner from the repository root and chooses the report path:

```bash
python3 ~/.claude/scripts/appsec_api.py \
  --mode detect-xshell \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output "<host-selected-report-path>.md"
```

For stronger evidence, first run `threatlint detect-xshell scan --path . --format markdown --output <detector-report>.md` and add `--findings "<detector-report>.md"` (maximum 5 MB). If LM Studio is unavailable, stop and report the prerequisite; do not install or start services.

The runner injects the canonical *-Shell detector and ordered skills. Analyze only supplied snapshot evidence; disclose truncation, uninspected package roots, and unknown deployment exposure. Do not install packages, contact live hosts, or execute tests; proposed validation is **NOT RUN**.

Report persistence is host-owned. Return the TS-NNN report and saved Markdown path; the analysis agent must not modify source or export reports.
