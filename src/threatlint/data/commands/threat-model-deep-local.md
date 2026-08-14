---
description: "Deep-dive aggressive AppSec threat model using a local model via LM Studio. Maximum finding coverage: bypass chain analysis for every control, chained kill chains, per-category breadth, runtime blindspot inventory. No API key required."
argument-hint: "Optional: component, path, service name, or feature to analyze (leave blank to discover)"
---

Run an aggressive deep-dive application security threat model against the local LM Studio model. No Anthropic, OpenAI, or GitHub credentials are required.

This is the local-model equivalent of `/threat-model-deep`: it uses the `--deep` flag on `appsec_api.py`, which applies a more aggressive system prompt requiring bypass chain analysis for every control, chained attack scenarios, per-category coverage audit, and a runtime blindspot inventory.

## Steps

Using the Bash tool, run the following in order:

### 1. Verify LM Studio is reachable

```bash
curl -s http://localhost:1234/v1/models
```

If the command fails or returns an empty model list, stop and tell the user: "LM Studio is not running or no model is loaded. Open LM Studio, load a model, and start the local server (Developer > Local Server > Start Server), then retry."

### 2. Run the deep-dive analysis

```bash
TIMESTAMP=$(date +%s)
python3 ~/.claude/scripts/appsec_api.py \
  --mode threat-model \
  --provider lmstudio \
  --deep \
  --target "$ARGUMENTS" \
  --output /tmp/tm_deep_local_${TIMESTAMP}.md
```

### 3. Determine output directory and filename

- If `$ARGUMENTS` is an existing file path: use its parent directory.
- If `$ARGUMENTS` is an existing directory path: use that directory.
- Otherwise (component name or blank): use the current working directory.

Resolve repo name and branch:
```bash
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
REPO_NAME=$(basename "$REPO_ROOT" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null | tr '/' '-' | tr '[:upper:]' '[:lower:]')
BRANCH=${BRANCH:-no-branch}
```

Filename (prefix with `${REPO_NAME}-${BRANCH}-`):
- No target: `<repo-name>-<branch>-threat-model-deep-local-YYYY-MM-DD.docx`
- Named target: `<repo-name>-<branch>-threat-model-deep-local-<sanitized-target>-YYYY-MM-DD.docx` (lowercase, spaces → hyphens)

### 4. Convert to Word document

```bash
python3 ~/.claude/scripts/md_to_docx.py \
  /tmp/tm_deep_local_${TIMESTAMP}.md \
  <output-dir>/<filename>.docx
rm /tmp/tm_deep_local_${TIMESTAMP}.md
```

### 5. Confirm

Report the full saved path to the user.

If `md_to_docx.py` is not installed, save as `<filename>.md` instead and note that `python-docx` is not installed (`pip3 install python-docx`).

Do not modify any repository source files.
