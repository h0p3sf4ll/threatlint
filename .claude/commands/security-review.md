---
description: "Run an application security code review. Analyzes the working-tree diff by default, or a specified branch, commit range, or PR target. Produces a two-tier report with merge recommendation, structured findings, and codebase-specific remediation guidance. Saves the report as a Word document in the repository root."
argument-hint: "Optional: branch, commit range (base..head), PR number, or path to review (defaults to working-tree diff)"
---

Invoke the `appsec-code-reviewer` agent to produce a security-focused code review.

## Routing

- If `$ARGUMENTS` is empty or blank: review the current **working-tree diff** (`git diff HEAD` plus `git diff --cached`).
- If `$ARGUMENTS` is a commit range or branch name (e.g., `main..feature/auth`, `abc123..def456`): review that range.
- If `$ARGUMENTS` is a path: review only changes to that path (pass `-- $ARGUMENTS` to git diff).
- If `$ARGUMENTS` is a PR number (e.g., `#42` or `42`): fetch the PR diff via `gh pr diff 42` and review it.

## Instructions for the Agent

Tell the agent:

1. Begin with the document header (repo name, date, change identifier) as defined in its instructions.
2. Scope the change first: run the appropriate `git diff` or `gh pr diff` command, record changed files, and identify which are security-relevant.
3. Produce the full two-tier report: Tier 1 executive summary with change risk level, finding summary table, top issues, and merge recommendation; Tier 2 with review scope, findings, security-positive changes, and residual risk.
4. Every finding must include a **Remediation Guidance** block with numbered, codebase-specific steps and a before/after code snippet, followed by a **Test Case**.
5. If the diff is empty or unavailable, say so explicitly — do not invent scope.
6. Do not modify the workspace.

## Output: Save as Word Document

After the agent delivers its report, save the full report to a Word document:

1. **Output directory**: the root of the current git repository (`git rev-parse --show-toplevel`). Fall back to the current working directory if not in a git repo.

2. **Filename**:
   - No argument: `security-review-YYYY-MM-DD.docx`
   - Branch/range: `security-review-<sanitized-ref>-YYYY-MM-DD.docx` (lowercase, `/` and `..` → `-`)
   - PR number: `security-review-pr<N>-YYYY-MM-DD.docx`
   - Use today's date.

3. **Convert to Word document** by running these shell steps:
   ```
   # Write markdown to a temp file
   Write the full report text to /tmp/cr_report_<timestamp>.md

   # Convert using the helper script
   python3 ~/.claude/scripts/md_to_docx.py /tmp/cr_report_<timestamp>.md <repo-root>/<filename>.docx

   # Remove the temp file
   rm /tmp/cr_report_<timestamp>.md
   ```

4. **Confirm** the saved path to the user once the file is written.
