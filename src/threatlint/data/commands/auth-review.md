---
description: "Deep-dive authentication and authorization security review: OAuth/OIDC, JWT, sessions, CSRF, MFA, RBAC, privilege escalation paths, and multi-tenancy isolation. Saves a Word document."
argument-hint: "Optional: specific auth component, file, or flow to focus on (default: full auth system)"
---

Delegate to the `appsec-auth-reviewer` agent. Pass any component name or file path as the review scope.

The agent will:
1. Map the complete authentication flow (token issuance, transmission, validation, refresh, revocation)
2. Review OAuth/OIDC, JWT security, session management, CSRF, MFA, RBAC, and multi-tenancy isolation
3. Enumerate privilege escalation paths from lower to higher privilege
4. Produce a Coverage Matrix and Privilege Escalation Path map
5. Report findings with component, file location, exploit path, and specific library/API remediation

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
- No argument: `<repo-name>-<branch>-auth-review-YYYY-MM-DD.docx`
- With path: `<repo-name>-<branch>-auth-review-<sanitized>-YYYY-MM-DD.docx`

Write the full report text to `/tmp/auth_${TIMESTAMP}.md`. Then convert to Word and remove the temp file:
```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/auth_${TIMESTAMP}.md "${REPO_ROOT}/<filename>.docx"
rm /tmp/auth_${TIMESTAMP}.md
```

Report the saved path. Do not modify any repository source files.
