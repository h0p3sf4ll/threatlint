---
description: "Run an application security threat model. Discovers the repo automatically when no target is given, or focuses on a specified component, path, service, or feature area."
argument-hint: "Optional: component, path, service name, or feature to analyze (leave blank to discover)"
---

Invoke the `appsec-threat-modeler` agent to produce a two-tier AppSec threat model.

## Routing

- If `$ARGUMENTS` is empty or blank: use **discovery mode** — the agent will autonomously inventory the repository, rank candidate components by risk, select the highest-risk scope, and explain that choice before producing the full report.
- If `$ARGUMENTS` names a component, path, service, or feature area: use **focused mode** — pass that as the review target and instruct the agent to inspect the named scope directly. The agent should still read relevant context (callers, middleware, configuration) to build a complete system model.

## Instructions for the Agent

Tell the agent:

1. Produce the full two-tier report as defined in its instructions, beginning with the document header (repo name, date, scope) followed by Tier 1 executive summary and Tier 2 technical threat model.
2. Every material claim must be grounded in inspected code or configuration with a file:line reference. No generic checklist findings.
3. Every finding must include a **Remediation Guidance** block with numbered, codebase-specific steps and before/after code snippets where applicable, followed by a **Validation** step.
4. End the report with **Suggested Focused Follow-Ups** — three to five ready-to-send prompts that name actual discovered components and ask narrow, high-value security questions about them.
5. Do not modify the workspace.

## Output: Save as Word Document

After the agent delivers its report, save the full report to a Word document:

1. **Determine the output directory.**
   - If `$ARGUMENTS` is an existing file path: use its parent directory.
   - If `$ARGUMENTS` is an existing directory path: use that directory.
   - Otherwise (component name, service name, or blank): use the current working directory.

2. **Choose a filename** — prefix with `<repo-name>-<branch>-` where `<repo-name>` is the lowercased basename of the repo root (spaces → hyphens) and `<branch>` is the current branch name (lowercased, `/` → `-`). Derive them with:
   ```
   REPO_NAME=$(basename "$(git rev-parse --show-toplevel 2>/dev/null || pwd)" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
   BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null | tr '/' '-' | tr '[:upper:]' '[:lower:]')
   BRANCH=${BRANCH:-no-branch}
   ```
   - No target argument: `<repo-name>-<branch>-threat-model-YYYY-MM-DD.docx`
   - Named target: `<repo-name>-<branch>-threat-model-<sanitized-target>-YYYY-MM-DD.docx` (lowercase, spaces → hyphens, strip slashes)
   - Use today's date.

3. **Convert to Word document** by running these shell steps:
   ```
   # Write markdown to a temp file
   Write the full report text to /tmp/tm_report_<timestamp>.md

   # Convert using the helper script
   python3 ~/.claude/scripts/md_to_docx.py /tmp/tm_report_<timestamp>.md <output-dir>/<filename>.docx

   # Remove the temp file
   rm /tmp/tm_report_<timestamp>.md
   ```

4. **Confirm** the saved path to the user once the file is written.
