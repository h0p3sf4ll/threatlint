---
description: "Dependency supply chain audit using a local LM Studio model. No API key required."
argument-hint: "Optional: specific manifest file or ecosystem (default: all manifests)"
---

Run a dependency supply chain audit using the local LM Studio model.

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
  --mode dependency-audit \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output /tmp/dep_local_${TIMESTAMP}.md
```

### 3. Save output
Filename: `dependency-audit-local-YYYY-MM-DD.docx` (or with sanitized target)
Directory: repository root

```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/dep_local_${TIMESTAMP}.md <dir>/<filename>.docx
rm /tmp/dep_local_${TIMESTAMP}.md
```

Report the saved path. Do not modify any repository source files.
