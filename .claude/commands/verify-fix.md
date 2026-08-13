---
description: "Re-examine a specific finding from a previous report after a fix has been applied. Confirms remediated, partially fixed, or still present. Saves a short verification report."
argument-hint: "Finding ID to verify (e.g., TM-003, CR-012) — optionally followed by the branch or commit containing the fix"
---

Re-examine a specific finding from a previous report to verify whether the remediation is effective.

## Steps

Using the Read and Bash tools:

### 1. Parse the finding ID

From `$ARGUMENTS`, extract:
- Finding ID (e.g., `TM-003`, `CR-012`)
- Optional: branch or commit ref for the fix (e.g., `feature/fix-sql-injection`, `abc123`)

### 2. Locate the original finding

Search recent report files for the finding ID:

```bash
FINDING_ID=$(echo "$ARGUMENTS" | grep -oE '(TM|CR|DA|IC|CI|AR|AU|SS)-[0-9]+' | head -1)
grep -r "\[${FINDING_ID}\]" . --include="*.md" -l 2>/dev/null | head -5
```

Read the original finding block: evidence file path, line number, exploit path, and remediation steps.

### 3. Inspect the fix

If a commit ref was provided:
```bash
git show <ref> -- <evidence-file-path>
```

If no ref: read the current state of the evidence file at the line(s) cited in the original finding.

### 4. Verify the remediation

Assess whether the fix:
- Addresses the root cause (not just the symptom)
- Follows the Remediation Guidance from the original finding
- Introduces any new risks in the process

### 5. Produce the verification report

```
# Fix Verification: <Finding ID>

**Finding**: [TM-NNN] / [CR-NNN] — <title>
**Original Severity**: <severity>
**Verified**: YYYY-MM-DD
**Branch / Commit**: <ref or "working tree">

## Verdict

REMEDIATED / PARTIALLY FIXED / STILL PRESENT / REGRESSED

## Evidence

[What changed, what was expected, what was found]

## Remaining Risk (if any)

[What still needs to be done, or what new risk was introduced]

## Validation Step

[Reproduce the original exploit path and confirm it is blocked]
```

Save the report to a temp file and convert to Word:
```bash
TIMESTAMP=$(date +%s)
```

Write the report text to `/tmp/verify_${TIMESTAMP}.md`. Then convert and clean up:
```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/verify_${TIMESTAMP}.md verify-<finding-id>-YYYY-MM-DD.docx
rm /tmp/verify_${TIMESTAMP}.md
```

Report the verdict and saved path. Do not modify any repository source files.
