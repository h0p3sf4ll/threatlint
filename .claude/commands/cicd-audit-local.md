---
description: "CI/CD pipeline security audit using a local LM Studio model. No API key required."
argument-hint: "Optional: specific workflow file or CI tool to focus on (default: all pipeline config)"
---

Run a CI/CD security audit using the local LM Studio model.

## Steps

### 1. Verify LM Studio is reachable
```bash
curl -s http://localhost:1234/v1/models
```
If empty or unreachable, stop and tell the user to start the LM Studio local server.

### 2. Run the audit
```bash
TIMESTAMP=$(date +%s)
python3 ~/.claude/scripts/appsec_api.py \
  --mode cicd-audit \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output /tmp/cicd_local_${TIMESTAMP}.md
```

### 3. Save output
Filename: `cicd-audit-local-YYYY-MM-DD.docx` (or with sanitized target)
Directory: repository root

```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/cicd_local_${TIMESTAMP}.md <dir>/<filename>.docx
rm /tmp/cicd_local_${TIMESTAMP}.md
```

Report the saved path. Do not modify any repository source files.
