---
description: "Red team adversarial scenario generation using a local LM Studio model. No API key required."
argument-hint: "Target component, service, or asset (leave blank for autonomous highest-risk selection)"
---

Generate adversarial attack scenarios using the local LM Studio model.

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
  --mode red-team \
  --provider lmstudio \
  --target "$ARGUMENTS" \
  --output /tmp/redteam_local_${TIMESTAMP}.md
```

### 3. Save output
Filename: `red-team-local-YYYY-MM-DD.docx` (or with sanitized target)
Directory: current working directory

```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/redteam_local_${TIMESTAMP}.md ./<filename>.docx
rm /tmp/redteam_local_${TIMESTAMP}.md
```

If `md_to_docx.py` or `python-docx` is not installed, save as `.md` instead by omitting the conversion step.

Report the saved path. Do not modify any repository source files.
