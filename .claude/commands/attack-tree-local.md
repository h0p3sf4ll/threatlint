---
description: "Attack tree generation using a local LM Studio model. No API key required."
argument-hint: "Asset to attack-tree: database, payment-service, admin-panel, auth-service, or any named component"
---

Build an attack tree for the named asset using the local LM Studio model.

## Steps

### 1. Verify LM Studio is reachable
```bash
curl -s http://localhost:1234/v1/models
```
If empty or unreachable, stop and tell the user to start the LM Studio local server.

### 2. Run the analysis
```bash
TIMESTAMP=$(date +%s)
python3 ~/.claude/scripts/appsec_api.py \
  --mode attack-tree \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output /tmp/atree_local_${TIMESTAMP}.md
```

### 3. Save output
Filename: `<repo-name>-<branch>-attack-tree-local-<sanitized-target>-YYYY-MM-DD.docx`
Directory: current working directory

```bash
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
REPO_NAME=$(basename "$REPO_ROOT" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null | tr '/' '-' | tr '[:upper:]' '[:lower:]')
BRANCH=${BRANCH:-no-branch}
python3 ~/.claude/scripts/md_to_docx.py /tmp/atree_local_${TIMESTAMP}.md ./${REPO_NAME}-${BRANCH}-<filename>.docx
rm /tmp/atree_local_${TIMESTAMP}.md
```

If `md_to_docx.py` or `python-docx` is not installed, save as `.md` instead by omitting the conversion step.

Report the saved path. Do not modify any repository source files.
