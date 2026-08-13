---
description: "IaC security review using a local LM Studio model. Covers Terraform, Kubernetes, Helm, Dockerfile, docker-compose. No API key required."
argument-hint: "Optional: specific IaC path or tool to focus on (default: all IaC)"
---

Run an IaC security review using the local LM Studio model.

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
  --mode iac-review \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output /tmp/iac_local_${TIMESTAMP}.md
```

### 3. Save output
Filename: `iac-review-local-YYYY-MM-DD.docx` (or with sanitized target)
Directory: repository root

```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/iac_local_${TIMESTAMP}.md <dir>/<filename>.docx
rm /tmp/iac_local_${TIMESTAMP}.md
```

Report the saved path. Do not modify any repository source files.
