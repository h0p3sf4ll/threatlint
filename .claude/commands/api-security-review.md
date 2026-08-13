---
description: "OWASP API Security Top 10 (2023) review of REST, GraphQL, or gRPC APIs. Finds broken object-level auth, excessive data exposure, missing rate limits, function-level auth gaps, and more. Saves a Word document."
argument-hint: "Optional: specific API path, router file, or service to review (default: all APIs discovered)"
---

Delegate to the `appsec-api-security-reviewer` agent. Pass any path or service name as the review scope.

The agent will:
1. Map all API endpoints from router and controller files
2. Review each endpoint against all 10 OWASP API Security categories
3. Produce an API Endpoint Inventory and OWASP API Top 10 Coverage Matrix
4. Report findings with endpoint, handler file location, exploit path, and framework-specific remediation

After the agent completes, save the report as a Word document.

## Output

Determine the repository root and set a timestamp:
```bash
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
TIMESTAMP=$(date +%s)
```

Filename:
- No argument: `api-security-review-YYYY-MM-DD.docx`
- With path: `api-security-review-<sanitized>-YYYY-MM-DD.docx`

Write the full report text to `/tmp/api_${TIMESTAMP}.md`. Then convert to Word and remove the temp file:
```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/api_${TIMESTAMP}.md "${REPO_ROOT}/<filename>.docx"
rm /tmp/api_${TIMESTAMP}.md
```

Report the saved path. Do not modify any repository source files.
