---
description: "Scan the repository for hardcoded secrets using a local LM Studio model. No API key required."
argument-hint: "Optional: path to limit scan scope (default: full repository)"
---

Run a secrets scan using the local LM Studio model.

## Steps

### 1. Verify LM Studio is reachable
```bash
curl -s http://localhost:1234/v1/models
```
If empty or unreachable, stop and tell the user to start the LM Studio local server.

### 2. Run the scan
```bash
TIMESTAMP=$(date +%s)
python3 ~/.claude/scripts/appsec_api.py \
  --mode secrets-scan \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output /tmp/secrets_local_${TIMESTAMP}.md
```

### 3. Save output
Filename: `secrets-scan-local-YYYY-MM-DD.docx` (or with sanitized target)
Directory: repository root (`git rev-parse --show-toplevel 2>/dev/null || pwd`)

```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/secrets_local_${TIMESTAMP}.md <dir>/<filename>.docx
rm /tmp/secrets_local_${TIMESTAMP}.md
```

Report the saved path. Do not modify any repository source files.
