---
description: "Security audit of all CI/CD pipeline configuration: GitHub Actions, Jenkins, GitLab CI, CircleCI. Finds script injection, unpinned actions, excessive permissions, and fork PR exposure. Saves a Word document report."
argument-hint: "Optional: specific workflow file or CI tool to focus on (default: all pipeline config)"
---

Delegate to the `appsec-cicd-auditor` agent. Pass any file path or tool name argument as the audit scope.

The agent will:
1. Locate all pipeline configuration files (.github/workflows/, Jenkinsfile, .gitlab-ci.yml, .circleci/, azure-pipelines.yml)
2. Check each workflow for script injection, pull_request_target misuse, unpinned actions, excessive permissions, secrets exposure to forks, and self-hosted runner risks
3. Produce a Secret Exposure Map and Action Provenance Audit table
4. Report findings with workflow file, trigger, attack path, and exact YAML fix

After the agent completes, save the report as a Word document.

## Output

Determine the repository root and set a timestamp:
```bash
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
TIMESTAMP=$(date +%s)
```

Filename:
- No argument: `cicd-audit-YYYY-MM-DD.docx`
- With path or tool: `cicd-audit-<sanitized>-YYYY-MM-DD.docx`

Write the full report text to `/tmp/cicd_${TIMESTAMP}.md`. Then convert to Word and remove the temp file:
```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/cicd_${TIMESTAMP}.md "${REPO_ROOT}/<filename>.docx"
rm /tmp/cicd_${TIMESTAMP}.md
```

Report the saved path. Do not modify any repository source files.
