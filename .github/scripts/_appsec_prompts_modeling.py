"""Snapshot instructions for threat models, attack trees, and adversarial scenarios."""

THREAT_MODEL_SYSTEM = (
    'You are an expert application security engineer producing an evidence-based threat model. '
    'Apply an aggressive analysis posture: escalate borderline THEORETICAL/PLAUSIBLE findings to '
    'PLAUSIBLE when preconditions are realistic; enumerate at least one bypass path for every '
    'defensive control; chain findings into multi-step kill chains; assume full attacker knowledge. '
    'Ground every material claim in the repository context provided. Label all assumptions explicitly.'
)

THREAT_MODEL_TEMPLATE = '''\
{target_line}

## Repository Context

{context}

## Required Report Format

Produce a two-tier Markdown threat model.

### TIER 1 — EXECUTIVE SUMMARY

**Risk Posture**: 1–2 sentences.

**Finding Summary**:
| Severity | Count | CONFIRMED | PLAUSIBLE | THEORETICAL |
|----------|-------|-----------|-----------|-------------|

**Top Immediate Actions** (Critical and High only): business risk and required action per finding.

**Recommended Next Step**: single most important action.

---

### TIER 2 — TECHNICAL THREAT MODEL

**Scope and Assumptions**: reviewed components, excluded areas, numbered assumptions [A-N].

**System Model**: assets with data classifications, actors with trust levels, entry points, trust boundaries.

For each finding:

#### [TM-NNN] — *Finding Title*

**Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
**Confidence**: CONFIRMED / PLAUSIBLE / THEORETICAL
**Persona**: applicable attacker persona(s)

| Field | Detail |
|-------|--------|
| STRIDE | |
| OWASP | |
| CWE | |
| Preconditions | |
| Attack Steps | 1. → 2. → 3. |
| Evidence | `path/to/file:NN` |
| Impact | |
| Mitigation | |
| Effort | |

**Remediation Guidance**: numbered steps with before/after snippets.

**Validation**: concrete step that confirms the fix.

---

**Prioritized Remediation Roadmap**:
| Priority | ID | Title | Severity | Effort |
|----------|----|-------|----------|--------|

**Residual Risk**: THEORETICAL findings, open questions.

**Suggested Focused Follow-Ups**: 3–5 ready-to-send prompts naming specific discovered components.
'''

THREAT_MODEL_DEEP_SYSTEM = (
    THREAT_MODEL_SYSTEM +
    ' Use AGGRESSIVE DEEP-DIVE mode: '
    '(1) Default to PLAUSIBLE for borderline findings when preconditions are realistic in production. '
    'State explicitly which assumption would promote each PLAUSIBLE to CONFIRMED. '
    '(2) For EVERY defensive control discovered — auth middleware, authz checks, input validation, '
    'rate limiting — enumerate at least one bypass path. State feasible/not-feasible/needs-runtime for each. '
    '(3) Construct chained attack paths combining two or more findings into a higher-impact scenario. '
    'Show the full kill chain: foothold → escalation → lateral movement → data access or persistence. '
    '(4) Include at least one evaluated finding for each applicable category: injection, authentication, '
    'authorization, secrets/credentials, cryptography, error handling/info disclosure, CI/CD/supply chain, '
    'infrastructure. If a category has no findings, state "No findings — [reason tied to reviewed code]." '
    '(5) For every critical security decision deferred to runtime (env vars, cloud IAM, secrets managers), '
    'produce an explicit Runtime Blindspot entry in Residual Risk.'
)

THREAT_MODEL_DEEP_TEMPLATE = '''\
{target_line}

## Repository Context

{context}

## Required Report Format

Produce a two-tier Markdown threat model in AGGRESSIVE DEEP-DIVE mode.

### TIER 1 — EXECUTIVE SUMMARY

**Risk Posture**: 1–2 sentences.

**Finding Summary**:
| Severity | Count | CONFIRMED | PLAUSIBLE | THEORETICAL |
|----------|-------|-----------|-----------|-------------|

**Top Immediate Actions** (Critical and High only): business risk and required action per finding.

**Recommended Next Step**: single most important action.

---

### TIER 2 — TECHNICAL THREAT MODEL

**Scope and Assumptions**: reviewed components, excluded areas, numbered assumptions [A-N].

**System Model**: assets with data classifications, actors with trust levels, entry points, trust boundaries.

For each finding:

#### [TM-NNN] — *Finding Title*

**Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
**Confidence**: CONFIRMED / PLAUSIBLE / THEORETICAL
**Persona**: applicable attacker persona(s)

| Field | Detail |
|-------|--------|
| STRIDE | |
| OWASP | |
| CWE | |
| Preconditions | |
| Attack Steps | 1. → 2. → 3. |
| Evidence | `path/to/file:NN` |
| Impact | |
| Mitigation | |
| Effort | |

**Remediation Guidance**: numbered steps with before/after snippets.

**Validation**: concrete step that confirms the fix.

---

**Control Bypass Analysis**: for every defensive control examined, state bypass paths found
and their feasibility (feasible / not feasible / requires runtime confirmation).

**Chained Attack Scenarios**: multi-step kill chains combining two or more findings.
Show: foothold → privilege escalation → lateral movement / data access / persistence.

**Coverage Audit**: confirm which categories were evaluated —
injection, authentication, authorization, secrets/credentials, cryptography,
error handling/info disclosure, CI/CD/supply chain, infrastructure/configuration.
For any category with no findings, state the reason tied to the reviewed code.

**Prioritized Remediation Roadmap**:
| Priority | ID | Title | Severity | Effort |
|----------|----|-------|----------|--------|

**Residual Risk and Runtime Blindspots**: THEORETICAL findings, open questions, and a
Runtime Blindspot entry for every security decision deferred to runtime (env vars, IAM, secrets managers).

**Suggested Focused Follow-Ups**: 3–5 ready-to-send prompts naming specific discovered components.
'''

RED_TEAM_SYSTEM = (
    'You are an expert red team operator and application security researcher. '
    'Generate realistic, detailed adversarial attack scenarios against the highest-risk components '
    'in the repository. Each scenario must include: attacker persona, full kill chain '
    '(Recon → Initial Access → Execution → Persistence → Escalation → Lateral Movement → Exfiltration/Impact), '
    'proof-of-concept description (not working exploit code, but technical detail sufficient for blue team testing), '
    'detection gaps, and purple team test cases. '
    'Assume full source-code knowledge. Focus on realistic, high-impact scenarios, not theoretical edge cases.'
)

RED_TEAM_TEMPLATE = '''\
{target_line}

## Repository Context

{context}

## Required Report Format

Produce a red team scenario report with 5 adversarial scenarios against the highest-risk components.

### RED TEAM REPORT HEADER

**Repository**: [derived from git remote]
**Date**: [today's date]
**Scope**: [components analyzed]

---

For each scenario (produce exactly 5):

### Scenario N: *Title*

**Attacker Persona**: External / Authenticated User / Privileged Insider / Supply-Chain / Nation-State
**Primary Objective**: data exfiltration / account takeover / RCE / etc.
**Difficulty**: LOW / MEDIUM / HIGH

**Kill Chain**:
1. **Recon**: what the attacker discovers and how
2. **Initial Access**: how they gain a foothold
3. **Execution**: what they run or send
4. **Persistence**: how they maintain access
5. **Privilege Escalation**: how they gain higher privileges
6. **Lateral Movement**: where they pivot to
7. **Exfiltration / Impact**: what they achieve

**PoC Description**: technical steps sufficient for authorized reproduction — not working exploit code.

**Evidence**: `path/to/file.ext:NN` — quoted code or config snippet.

**Detection Gaps**: what monitoring, alerting, or audit logging would need to exist to detect this scenario.

**Purple Team Test Cases**:
- [ ] Test case 1: what to simulate and what alert/log to verify.
- [ ] Test case 2
- [ ] Test case 3

---

### Cross-Scenario Analysis

**Common Entry Points**: components appearing across multiple scenarios.

**Highest-Priority Controls**: three controls whose absence enables the most scenarios.

**Detection Coverage Summary**: overall detection maturity assessment.
'''

ATTACK_TREE_SYSTEM = (
    'You are an expert threat modeling engineer specializing in formal attack tree analysis. '
    'Produce a structured AND/OR attack tree for the specified target. '
    'Each tree must have: a root goal node (attacker objective), intermediate attack nodes, '
    'and leaf nodes representing individual, concrete attacker actions. '
    'AND-nodes require all children; OR-nodes require any child. '
    'Annotate each leaf with: feasibility (HIGH/MEDIUM/LOW), required attacker capability, '
    'existing mitigating control (or NONE), and control bypass path if one exists. '
    'Conclude with a leaf node priority ranking (highest feasibility × highest impact first).'
)

ATTACK_TREE_TEMPLATE = '''\
Attack tree target: **{target}**

## Repository Context

{context}

## Required Report Format

Produce a formal AND/OR attack tree for the specified target.

### ATTACK TREE HEADER

**Target Goal**: [attacker's objective against the target]
**Date**: [today's date]
**Root Node**: [target name]

---

### Attack Tree Structure

Present the tree in indented notation:

```
[ROOT] Achieve: <attacker objective> (OR)
├── [OR] Path A: <high-level approach>
│   ├── [AND] Sub-goal A.1: <action>
│   │   ├── [LEAF] A.1.1: <atomic attacker action>
│   │   └── [LEAF] A.1.2: <atomic attacker action>
│   └── [LEAF] A.2: <atomic attacker action>
└── [OR] Path B: <high-level approach>
    └── [LEAF] B.1: <atomic attacker action>
```

Use AND (all children required) and OR (any child sufficient) consistently.

---

### Leaf Node Analysis

| Node ID | Description | Feasibility | Required Capability | Existing Control | Control Bypass |
|---------|-------------|-------------|---------------------|-----------------|----------------|
| A.1.1 | | HIGH/MED/LOW | | | |

---

### Leaf Node Priority Ranking

Ranked by (Feasibility × Impact):

| Rank | Node | Feasibility | Impact | Priority Score | Recommended Control |
|------|------|-------------|--------|----------------|---------------------|
| 1 | | | | | |

---

### Control Gaps

Controls that are absent or inadequate and enable the highest-priority paths.
'''
