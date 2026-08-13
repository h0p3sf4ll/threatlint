---
description: "Run an AppSec threat model using a local model via LM Studio. No API key required — uses the model currently loaded in LM Studio at localhost:1234."
argument-hint: "Optional: component, path, service name, or feature to analyze (leave blank to discover)"
---

Run an application security threat model against the local LM Studio model. No Anthropic, OpenAI, or GitHub credentials are required.

## Steps

Using the Bash tool, run the following in order:

### 1. Verify LM Studio is reachable

```bash
curl -s http://localhost:1234/v1/models
```

If the command fails or returns an empty model list, stop and tell the user: "LM Studio is not running or no model is loaded. Open LM Studio, load a model, and start the local server (Developer > Local Server > Start Server), then retry."

### 2. Run the analysis

```bash
TIMESTAMP=$(date +%s)
python3 ~/.claude/scripts/appsec_api.py \
  --mode threat-model \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output /tmp/tm_local_${TIMESTAMP}.md
```

### 3. Determine output directory and filename

- If `$ARGUMENTS` is an existing file path: use its parent directory.
- If `$ARGUMENTS` is an existing directory path: use that directory.
- Otherwise (component name or blank): use the current working directory.

Filename:
- No target: `threat-model-local-YYYY-MM-DD.docx`
- Named target: `threat-model-local-<sanitized-target>-YYYY-MM-DD.docx` (lowercase, spaces → hyphens)

### 4. Convert to Word document

```bash
python3 ~/.claude/scripts/md_to_docx.py \
  /tmp/tm_local_${TIMESTAMP}.md \
  <output-dir>/<filename>.docx
rm /tmp/tm_local_${TIMESTAMP}.md
```

### 5. Confirm

Report the full saved path to the user.

If `md_to_docx.py` is not installed, save as `<filename>.md` instead and note that `python-docx` is not installed (`pip3 install python-docx`).

Do not modify any repository source files.
