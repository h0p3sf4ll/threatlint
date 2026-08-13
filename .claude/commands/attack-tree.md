---
description: "Build a formal attack tree for a named asset: maps all attack paths from root goal to leaf conditions, with AND/OR nodes, control effectiveness, and prioritized mitigations. Saves a Word document."
argument-hint: "Asset to attack-tree: database, payment-service, admin-panel, auth-service, or any named component"
---

Build a formal attack tree for the named asset. Use the `appsec-threat-modeler` agent for deep repository analysis, then structure the results as an attack tree.

## Steps

### 1. Delegate to threat modeler

Invoke the `appsec-threat-modeler` agent with the asset name from `$ARGUMENTS`. Ask it to:

- Map all possible attack paths to this specific asset
- For each path: identify the root goal, intermediate nodes, leaf conditions, AND/OR node type, and mitigating controls
- Enumerate at least one bypass path for every control encountered
- Assess each path's feasibility and required attacker position

### 2. Structure the attack tree

After the threat modeler completes, format the results as a structured attack tree:

```
GOAL: Compromise <asset name>
├── [OR] Path 1: Direct API exploitation
│   ├── [AND] Condition 1: Reach API endpoint
│   │   └── Control: Rate limiting → Bypass: IP rotation
│   └── [AND] Condition 2: Exploit IDOR
│       └── Control: None confirmed → Status: CONFIRMED
├── [OR] Path 2: Credential theft
│   ├── [AND] Condition 1: Extract token from response
│   └── [AND] Condition 2: Reuse token
│       └── Control: Token expiry → Bypass: 24h window
└── [OR] Path 3: Supply chain entry
    └── [AND] Condition: Compromise build pipeline
        └── Control: None → Status: PLAUSIBLE
```

For each leaf node:
- Confidence: CONFIRMED / PLAUSIBLE / THEORETICAL
- Effort: Immediate / Days / Weeks
- Mitigating control (present or absent)
- Priority: rank leaf nodes by effort × impact

### 3. Save output

Filename: `attack-tree-<sanitized-asset>-YYYY-MM-DD.docx`
Directory: current working directory

```bash
TIMESTAMP=$(date +%s)
```

Write the full report text to `/tmp/attack_tree_${TIMESTAMP}.md`. Then convert and clean up:
```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/attack_tree_${TIMESTAMP}.md ./<filename>.docx
rm /tmp/attack_tree_${TIMESTAMP}.md
```

Report the saved path. Do not modify any repository source files.
