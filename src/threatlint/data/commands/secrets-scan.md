---
description: "Scan the entire repository and git history for hardcoded secrets, API keys, credentials, private keys, and high-entropy tokens. Saves a Word document report."
argument-hint: "Optional: path to limit scan scope (default: full repository)"
---

Delegate to the `appsec-secrets-scanner` agent. Pass any path argument as the scan scope.

The agent will:
1. Scan all files for known secret formats and high-entropy strings
2. Scan git history for secrets committed then deleted
3. Assess each finding's production risk and service impact
4. Produce a report with rotation and removal steps for each finding

After the agent completes, save the report as a Word document.

## Output

Determine the repository root and set a timestamp:
```bash
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
REPO_NAME=$(basename "$REPO_ROOT" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null | tr '/' '-' | tr '[:upper:]' '[:lower:]')
BRANCH=${BRANCH:-no-branch}
TIMESTAMP=$(date +%s)
```

Filename:
- No argument: `<repo-name>-<branch>-secrets-scan-YYYY-MM-DD.docx`
- With path: `<repo-name>-<branch>-secrets-scan-<sanitized-path>-YYYY-MM-DD.docx`

Write the full report text to `/tmp/secrets_${TIMESTAMP}.md`. Then convert to Word and remove the temp file:
```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/secrets_${TIMESTAMP}.md "${REPO_ROOT}/<filename>.docx"
rm /tmp/secrets_${TIMESTAMP}.md
```

Report the saved path. Do not modify any repository source files.
