---
description: "Software supply chain audit: third-party dependency risk, unpinned versions, dependency confusion, typosquatting, lockfile integrity, and malicious install hooks. Saves a Word document report."
argument-hint: "Optional: specific manifest file or ecosystem to audit (default: all manifests)"
---

Delegate to the `appsec-dependency-auditor` agent. Pass any manifest path or ecosystem name as the scope.

The agent will:
1. Locate all package manifests and verify lockfile presence
2. Check version pinning, dependency confusion risk, typosquatting, install hooks, abandoned packages, and known CVE-affected version ranges
3. Produce a Dependency Inventory table
4. Report findings with package name, manifest location, attack vector, and specific remediation steps

After the agent completes, save the report as a Word document.

## Output

Determine the repository root and set a timestamp:
```bash
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
TIMESTAMP=$(date +%s)
```

Filename:
- No argument: `dependency-audit-YYYY-MM-DD.docx`
- With path: `dependency-audit-<sanitized>-YYYY-MM-DD.docx`

Write the full report text to `/tmp/dep_${TIMESTAMP}.md`. Then convert to Word and remove the temp file:
```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/dep_${TIMESTAMP}.md "${REPO_ROOT}/<filename>.docx"
rm /tmp/dep_${TIMESTAMP}.md
```

Report the saved path. Do not modify any repository source files.
