---
description: "Compare two threat model reports to surface new risks, resolved findings, regressions, and severity changes. Saves a delta report as a Word document."
argument-hint: "Previous report path or git ref (e.g., path/to/old-report.md, HEAD~1, main)"
---

Compare the current state of the repository against a previous threat model to produce a security delta report.

## Steps

Using the Read and Bash tools:

### 1. Locate the previous report

From `$ARGUMENTS`:
- If a file path: read the file directly
- If a git ref (`HEAD~1`, `main`, a commit SHA): run `git show <ref>:path/to/report.md` or search for a report file at that ref
- If blank: look for the most recent report file in the current directory and repo root

```bash
find . -maxdepth 2 \( -name "threat-model-*.md" -o -name "threat-model-*.docx" \) 2>/dev/null | sort | tail -2
```

### 2. Locate the current report

Look for the most recent threat model report (newer than the previous one). If no current report exists, run the `appsec-threat-modeler` agent first to generate one.

### 3. Produce the delta

Compare the two reports and produce a structured delta:

#### New Findings (in current, not in previous)
| ID | Title | Severity | Confidence | Notes |
|----|-------|----------|-----------|-------|

#### Resolved Findings (in previous, not in current)
| ID | Title | Severity | Resolution Evidence | Notes |
|----|-------|----------|---------------------|-------|

#### Regressed Findings (severity increased from previous to current)
| ID | Title | Previous Severity | Current Severity | Change |
|----|-------|------------------|-----------------|--------|

#### Unchanged Open Findings
| ID | Title | Severity | Age (reports) | Notes |
|----|-------|----------|---------------|-------|

#### Risk Trend Summary
One paragraph summarizing whether the overall risk posture improved, regressed, or held steady, and the single most important change since the last report.

### 4. Save output

Filename: `<repo-name>-<branch>-threat-delta-YYYY-MM-DD.docx`
Directory: current working directory

```bash
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
REPO_NAME=$(basename "$REPO_ROOT" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null | tr '/' '-' | tr '[:upper:]' '[:lower:]')
BRANCH=${BRANCH:-no-branch}
TIMESTAMP=$(date +%s)
```

Write the full report text to `/tmp/delta_${TIMESTAMP}.md`. Then convert and clean up:
```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/delta_${TIMESTAMP}.md ./${REPO_NAME}-${BRANCH}-threat-delta-YYYY-MM-DD.docx
rm /tmp/delta_${TIMESTAMP}.md
```

Report the saved path. Do not modify any repository source files.
