---
description: "Security review of all IaC: Terraform, Kubernetes, Helm, Dockerfile, docker-compose. Finds misconfigured IAM, open network rules, missing encryption, and hardcoded secrets. Saves a Word document report."
argument-hint: "Optional: specific path or IaC tool to focus on (default: all IaC in repository)"
---

Delegate to the `appsec-iac-reviewer` agent. Pass any path or tool name argument as the review scope.

The agent will:
1. Locate all IaC files (Terraform, CloudFormation, Kubernetes YAML, Helm, Dockerfile, docker-compose)
2. Review each resource for IAM permissions, network rules, encryption, secret handling, privilege levels, and logging
3. Construct an IaC Inventory and Prioritized Remediation Roadmap
4. Produce a report with resource name, misconfiguration detail, blast radius, and exact attribute to change

After the agent completes, save the report as a Word document.

## Output

Determine the repository root and set a timestamp:
```bash
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
TIMESTAMP=$(date +%s)
```

Filename:
- No argument: `iac-review-YYYY-MM-DD.docx`
- With path: `iac-review-<sanitized-path>-YYYY-MM-DD.docx`

Write the full report text to `/tmp/iac_${TIMESTAMP}.md`. Then convert to Word and remove the temp file:
```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/iac_${TIMESTAMP}.md "${REPO_ROOT}/<filename>.docx"
rm /tmp/iac_${TIMESTAMP}.md
```

Report the saved path. Do not modify any repository source files.
