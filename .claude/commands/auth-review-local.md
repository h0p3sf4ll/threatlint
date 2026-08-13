---
description: "Deep-dive auth security review using a local LM Studio model. OAuth, JWT, sessions, CSRF, MFA, RBAC, multi-tenancy. No API key required."
argument-hint: "Optional: specific auth component or file (default: full auth system)"
---

Run an authentication and authorization security review using the local LM Studio model.

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
  --mode auth-review \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output /tmp/auth_local_${TIMESTAMP}.md
```

### 3. Save output
Filename: `auth-review-local-YYYY-MM-DD.docx` (or with sanitized target)
Directory: repository root

```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/auth_local_${TIMESTAMP}.md <repo-root>/<filename>.docx
rm /tmp/auth_local_${TIMESTAMP}.md
```

Report the saved path. Do not modify any repository source files.
