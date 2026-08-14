---
description: "Adversarial scenario generation: produce realistic, detailed attack scenarios from multiple threat actor perspectives. Covers kill chain steps, MITRE ATT&CK techniques, detection gaps, and proof-of-concept descriptions. Saves a Word document."
argument-hint: "Target component, service, or asset to red-team (leave blank for autonomous highest-risk selection)"
---

Generate adversarial attack scenarios for the named target, modeling realistic attacker behavior across multiple threat actor personas.

## Steps

Delegate to the `appsec-threat-modeler` agent with the following additional instructions:

Produce **five distinct attack scenarios** for the target from different threat actor perspectives. For each scenario:

1. **Threat Actor**: External attacker / Authenticated insider / Compromised dependency / Nation-state APT / Opportunistic automated scanner
2. **Objective**: What the attacker is trying to achieve (data exfiltration, persistence, lateral movement, supply chain compromise, DoS, financial fraud)
3. **Kill Chain**:
   - **Reconnaissance**: What public or visible information enables this scenario
   - **Initial Access**: How the attacker enters (MITRE ATT&CK technique + ID)
   - **Execution / Persistence**: What they do once in
   - **Privilege Escalation**: How they expand access (ATT&CK technique + ID)
   - **Lateral Movement / Collection**: How they reach the objective
   - **Exfiltration / Impact**: The final action and its business consequence
4. **Proof-of-Concept**: A concrete, specific description of the attack — not generic. Name the specific endpoint, parameter, package, or credential. Describe what the attacker would send and what they would receive.
5. **Detection Gaps**: What logging, alerting, or monitoring is absent that would otherwise catch this
6. **Feasibility**: Time estimate for a skilled attacker (hours / days / weeks), prerequisites, and required tooling
7. **Mitigations**: The two most effective controls that would stop or detect this scenario

After generating scenarios, also produce:
- **Detection Engineering Recommendations**: For each scenario, one SIEM rule or alert that would catch the attack
- **Purple Team Test Cases**: Specific commands or payloads a red team could use to validate detection coverage

## Output

Filename (prefix with `<repo-name>-<branch>-`):
- No argument: `<repo-name>-<branch>-red-team-YYYY-MM-DD.docx`
- With target: `<repo-name>-<branch>-red-team-<sanitized-target>-YYYY-MM-DD.docx`

Directory: current working directory

```bash
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
REPO_NAME=$(basename "$REPO_ROOT" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null | tr '/' '-' | tr '[:upper:]' '[:lower:]')
BRANCH=${BRANCH:-no-branch}
TIMESTAMP=$(date +%s)
```

Write the full report text to `/tmp/red_team_${TIMESTAMP}.md`. Then convert and clean up:
```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/red_team_${TIMESTAMP}.md ./<filename>.docx
rm /tmp/red_team_${TIMESTAMP}.md
```

Report the saved path. Do not modify any repository source files.
