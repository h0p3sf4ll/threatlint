---
description: "Triage security scanner findings as true or false positives. Generates precise Semgrep rule tuning for FPs and confirms exploit paths for TPs. Accepts a SARIF file, Semgrep JSON output, or a threatlint report."
argument-hint: "Path to SARIF file, Semgrep JSON, or threatlint report (e.g., security-review-2026-01-15.docx or /tmp/semgrep.json)"
---

Invoke the `appsec-fp-reviewer` agent to triage security scanner findings.

## Routing

- If `$ARGUMENTS` is empty: look for a SARIF file, Semgrep JSON, or threatlint report in the current directory. Check these locations in order: `.sarif`, `semgrep.json`, `semgrep-results.json`, `results.sarif`, `*.sarif`, any `*.json` matching `semgrep` in the filename, or the most recent `*.md` threatlint report in the repo root.
- If `$ARGUMENTS` is a file path: use that file as the findings source.
- If `$ARGUMENTS` is a finding ID or range (e.g., `TM-001` or `TM-001..TM-005`): look for those findings in the most recent threatlint report in the repo root.
- If no findings file is found: tell the user to run Semgrep first (`semgrep --config=auto --json > semgrep.json`) or provide a path.

## Instructions for the Agent

Tell the agent:

1. Begin with the document header (repo name, date, input source, total finding count).
2. Parse the findings file. Print the total count before beginning analysis.
3. For each finding:
   a. Read the matched file at the flagged line with ≥60 lines of context (30 before, 30 after).
   b. Trace the input source: is the flagged value attacker-controlled?
   c. Trace to the sink: what transformations and validation occur along the path?
   d. Identify any code-level sanitizers that break the exploit path.
   e. Classify as TRUE POSITIVE, FALSE POSITIVE, or AMBIGUOUS with cited code evidence.
4. For every FALSE POSITIVE:
   a. Generate a Semgrep rule patch using the lowest-level tuning option that correctly suppresses only this FP.
   b. State explicitly which true positives the patched rule still catches.
   c. Validate that the YAML is syntactically correct before outputting it.
5. For every TRUE POSITIVE: confirm the exploit path and recommend severity and action.
6. For every AMBIGUOUS: state the blocking question and resolution path.
7. End with a Suppression Impact Assessment table and a Patterns section for systemic issues.
8. Do not modify any files.

## Output: Save as Word Document

After the agent delivers its report:

1. **Output directory**: the root of the current git repository (`git rev-parse --show-toplevel`), or current working directory if not in a git repo.

2. **Filename**: `<repo-name>-<branch>-fp-review-YYYY-MM-DD.docx` (use today's date), where `<repo-name>` and `<branch>` are derived from:
   ```
   REPO_NAME=$(basename "$(git rev-parse --show-toplevel 2>/dev/null || pwd)" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
   BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null | tr '/' '-' | tr '[:upper:]' '[:lower:]')
   BRANCH=${BRANCH:-no-branch}
   ```

3. **Convert to Word document**:
   ```
   TIMESTAMP=$(date +%s)
   Write the full report text to /tmp/fp_review_${TIMESTAMP}.md
   python3 ~/.claude/scripts/md_to_docx.py /tmp/fp_review_${TIMESTAMP}.md <output-dir>/<repo-name>-<branch>-fp-review-YYYY-MM-DD.docx
   rm /tmp/fp_review_${TIMESTAMP}.md
   ```

4. **Confirm** the saved path to the user.
