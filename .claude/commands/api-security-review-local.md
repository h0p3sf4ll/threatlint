---
description: "OWASP API Security Top 10 review using a local LM Studio model. No API key required."
argument-hint: "Optional: specific API path or service (default: all APIs discovered)"
---

Run an OWASP API Security Top 10 review using the local LM Studio model.

## Steps

### 1. Verify LM Studio is reachable
```bash
curl -s http://localhost:1234/v1/models
```
If empty or unreachable, stop and tell the user to start the LM Studio local server.

### 2. Run the review
```bash
TIMESTAMP=$(date +%s)
python3 ~/.claude/scripts/appsec_api.py \
  --mode api-security \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output /tmp/api_local_${TIMESTAMP}.md
```

### 3. Save output
Filename: `api-security-review-local-YYYY-MM-DD.docx` (or with sanitized target)
Directory: repository root

```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/api_local_${TIMESTAMP}.md <repo-root>/<filename>.docx
rm /tmp/api_local_${TIMESTAMP}.md
```

Report the saved path. Do not modify any repository source files.
