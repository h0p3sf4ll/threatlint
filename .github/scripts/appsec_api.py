#!/usr/bin/env python3
"""
Run an AppSec analysis via the OpenAI API, GitHub Models API, or a local LM Studio instance.
Used by GitHub Actions workflows and Claude Code local-model slash commands.

Providers
---------
openai        Authenticated with OPENAI_API_KEY. Default model: gpt-4o
github-models Authenticated with GITHUB_TOKEN (no extra secret needed).
              Base URL: https://models.inference.ai.azure.com
              Default model: openai/gpt-4o
lmstudio      Local model served by LM Studio (OpenAI-compatible API).
              Base URL: http://localhost:1234/v1 (override with LMSTUDIO_BASE_URL)
              Model: auto-detected from LM Studio (override with LMSTUDIO_MODEL or --model)
              No API key required.
"""
import argparse
import os
import subprocess
import sys

MAX_DIFF_CHARS = 80_000
MAX_FILE_BYTES = 6_000
MAX_CONTEXT_FILES = 6
MAX_TOTAL_PARTS = 15
# Local models often have smaller context windows; use a tighter cap by default.
MAX_DIFF_CHARS_LOCAL = 40_000
MAX_FILE_BYTES_LOCAL = 4_000


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def get_diff(base, head, max_chars=MAX_DIFF_CHARS):
    diff = run(['git', 'diff', f'{base}..{head}']).stdout
    if len(diff) > max_chars:
        diff = diff[:max_chars] + (
            f'\n\n[diff truncated — {len(diff) - max_chars:,} additional characters omitted]'
        )
    return diff


def get_changed_files(base, head):
    out = run(['git', 'diff', '--name-only', f'{base}..{head}']).stdout.strip()
    return out.split('\n') if out else []


def read_file_safe(path, max_bytes=MAX_FILE_BYTES):
    try:
        size = os.path.getsize(path)
        with open(path, errors='replace') as f:
            content = f.read(max_bytes)
        if size > max_bytes:
            content += f'\n[...truncated at {max_bytes} bytes...]'
        return content
    except OSError:
        return None


def gather_repo_context(max_file_bytes=MAX_FILE_BYTES):
    parts = []

    file_list = run(['git', 'ls-files']).stdout
    parts.append(f'## Repository file listing\n```\n{file_list[:4000]}\n```')

    for fname in [
        'README.md', 'readme.md', 'ARCHITECTURE.md',
        'package.json', 'package-lock.json', 'yarn.lock',
        'go.mod', 'go.sum',
        'requirements.txt', 'Pipfile.lock', 'poetry.lock',
        'Cargo.toml', 'Cargo.lock',
        'pom.xml', 'build.gradle', 'pyproject.toml',
        'Gemfile', 'Gemfile.lock',
        'composer.json', 'composer.lock',
        'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
        '.env.example', '.env.sample',
    ]:
        if len(parts) >= MAX_TOTAL_PARTS:
            break
        if os.path.isfile(fname):
            content = read_file_safe(fname, max_bytes=max_file_bytes)
            if content:
                parts.append(f'## {fname}\n```\n{content}\n```')

    for search_dir in ['infra', 'terraform', 'k8s', 'helm', 'deploy', '.github/workflows']:
        if len(parts) >= MAX_TOTAL_PARTS:
            break
        if not os.path.isdir(search_dir):
            continue
        found = run([
            'find', search_dir,
            '(', '-name', '*.yml', '-o', '-name', '*.yaml', '-o', '-name', '*.tf', ')',
            '-type', 'f',
        ]).stdout.strip().split('\n')
        for fpath in found[:3]:
            if len(parts) >= MAX_TOTAL_PARTS:
                break
            if fpath and os.path.isfile(fpath):
                content = read_file_safe(fpath, max_bytes=max_file_bytes)
                if content:
                    parts.append(f'## {fpath}\n```\n{content}\n```')

    return '\n\n'.join(parts)


# ─── System prompts ──────────────────────────────────────────────────────────

PR_REVIEW_SYSTEM = (
    'You are an expert application security engineer performing a security-focused code review. '
    'Apply an aggressive analysis posture: escalate borderline THEORETICAL/PLAUSIBLE findings to '
    'PLAUSIBLE when preconditions are realistic; enumerate at least one bypass path for every '
    'defensive control touched or removed; chain low-severity findings that together create a '
    'higher-impact scenario; assume full attacker knowledge of the source. '
    'Report only security regressions and missing controls — exclude style, performance, and '
    'maintainability findings.'
)

THREAT_MODEL_SYSTEM = (
    'You are an expert application security engineer producing an evidence-based threat model. '
    'Apply an aggressive analysis posture: escalate borderline THEORETICAL/PLAUSIBLE findings to '
    'PLAUSIBLE when preconditions are realistic; enumerate at least one bypass path for every '
    'defensive control; chain findings into multi-step kill chains; assume full attacker knowledge. '
    'Ground every material claim in the repository context provided. Label all assumptions explicitly.'
)

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

SECRETS_SCAN_SYSTEM = (
    'You are an expert application security engineer specializing in secrets detection and credential management. '
    'Search exhaustively for hardcoded credentials, API keys, private keys, connection strings, and secret management '
    'anti-patterns. Flag any value that would grant access if exfiltrated. '
    'Scan git history hints, environment variable handling, config files, and CI/CD configuration, not just source code. '
    'Label every finding with the exact file and line. Report only security findings — no style or performance issues.'
)

IAC_REVIEW_SYSTEM = (
    'You are an expert cloud and infrastructure security engineer. '
    'Review all Infrastructure as Code for security misconfigurations: overly permissive IAM policies, '
    'open network policies, missing encryption, privileged container settings, insecure default configurations, '
    'and secrets embedded in infrastructure definitions. '
    'Apply an aggressive posture: flag any resource whose misconfiguration could enable lateral movement, '
    'data exfiltration, or privilege escalation, even if a separate compensating control might exist. '
    'Cite the exact resource name, file, and attribute for every finding.'
)

CICD_AUDIT_SYSTEM = (
    'You are an expert CI/CD and DevSecOps security engineer. '
    'Audit all pipeline configuration for security weaknesses: script injection via untrusted context values '
    '(github.head_ref, github.event.pull_request.body, github.event.issue.title, etc.), '
    'pull_request_target misuse, workflow permissions, action pinning, self-hosted runner exposure, '
    'fork PR secret exposure, artifact integrity, and pipeline secret handling. '
    'Be exhaustive: enumerate every untrusted context value interpolated into a run: block. '
    'Cite the workflow file, job name, step name, and line for every finding.'
)

DEPENDENCY_AUDIT_SYSTEM = (
    'You are an expert supply chain security engineer. '
    'Audit package manifests and lockfiles for supply chain risks: '
    'known CVE version ranges, dependency confusion attack surfaces, typosquatting targets, '
    'malicious install hooks (postinstall, prepare), abandoned packages, unpinned version ranges, '
    'missing lockfile integrity (checksums, signatures), and package manager configuration secrets. '
    'Distinguish between direct and transitive dependencies. '
    'Cite the manifest file, package name, and version for every finding.'
)

API_SECURITY_SYSTEM = (
    'You are an expert API security engineer with deep knowledge of the OWASP API Security Top 10 (2023). '
    'Review all API endpoints — REST, GraphQL, gRPC, WebSocket — for: '
    'BOLA (Broken Object Level Authorization), Broken Authentication, BOPLA (Broken Object Property Level Authorization), '
    'Unrestricted Resource Consumption, Broken Function Level Authorization, Unrestricted Business Flow, '
    'Server-Side Request Forgery, Security Misconfiguration, Improper Inventory Management, and Unsafe Consumption. '
    'Also check for mass assignment, excessive data exposure, and weak input validation. '
    'Trace authorization checks from route definitions through to data access. '
    'Cite the endpoint path, HTTP method, and file location for every finding.'
)

AUTH_REVIEW_SYSTEM = (
    'You are an expert authentication and authorization security engineer. '
    'Perform a deep-dive review of all auth/authz code: '
    'OAuth 2.0/OIDC (state parameter, PKCE, redirect URI validation, scope minimization, ID token validation), '
    'JWT (algorithm confusion, claims validation, secret strength, expiry), '
    'session management (entropy, fixation, revocation, cookie flags), '
    'CSRF protection, MFA (TOTP bypass, recovery code entropy), '
    'RBAC/ABAC enforcement, multi-tenancy isolation, password hashing (bcrypt/Argon2id), '
    'brute-force protection, and account enumeration. '
    'Trace every privilege decision from request receipt to data access. '
    'Cite the exact file, function, and line for every finding.'
)

RED_TEAM_SYSTEM = (
    'You are an expert red team operator and application security researcher. '
    'Generate realistic, detailed adversarial attack scenarios against the highest-risk components '
    'in the repository. Each scenario must include: attacker persona, full kill chain '
    '(Recon → Initial Access → Execution → Persistence → Escalation → Lateral Movement → Exfiltration/Impact), '
    'proof-of-concept description (not working exploit code, but technical detail sufficient for blue team testing), '
    'detection gaps, and purple team test cases. '
    'Assume full source-code knowledge. Focus on realistic, high-impact scenarios, not theoretical edge cases.'
)

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

# ─── Prompt templates ────────────────────────────────────────────────────────

PR_REVIEW_TEMPLATE = '''\
## Changed Files
{files}

## Diff
```diff
{diff}
```

## Required Report Format

Produce a two-tier Markdown security code review.

### TIER 1 — EXECUTIVE SUMMARY

**Change Risk Level**: CRITICAL / HIGH / MEDIUM / LOW / CLEAN

One-sentence risk summary.

**Finding Summary**:
| Severity | Count | CONFIRMED | PLAUSIBLE | THEORETICAL |
|----------|-------|-----------|-----------|-------------|
| Critical | | | | |
| High | | | | |
| Medium | | | | |
| Low | | | | |

**Top Issues** (Critical and High only):
- **[CR-NNN]** *Title* — business risk. Required fix.

**Merge Recommendation**: BLOCK / MERGE WITH ACTION / MERGE

---

### TIER 2 — TECHNICAL REVIEW

**Review Scope**: changed files, context, numbered assumptions.

For each finding:

#### [CR-NNN] — *Finding Title*

**Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
**Confidence**: CONFIRMED / PLAUSIBLE / THEORETICAL

| Field | Detail |
|-------|--------|
| OWASP | |
| CWE | |
| Changed File | `path/to/file.ext:NN` |
| Evidence | quoted `+` lines from the diff |
| Exploit Path | 1. → 2. → 3. |
| Impact | |
| Likelihood | |
| Mitigation | |
| Effort | Immediate / Short-term |

**Remediation Guidance**: numbered steps with before/after code snippets.

**Test Case**: concrete reproduction or unit test.

---

**Security-Positive Changes**: controls added or correctly hardened.

**Residual Risk**: THEORETICAL findings needing confirmation, open questions.
'''

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

SECRETS_SCAN_TEMPLATE = '''\
{target_line}

## Repository Context

{context}

## Required Report Format

Produce a two-tier Markdown secrets scan report.

### TIER 1 — EXECUTIVE SUMMARY

**Secrets Exposure Level**: CRITICAL / HIGH / MEDIUM / LOW / CLEAN

One-sentence summary.

**Finding Summary**:
| Severity | Count | CONFIRMED | PLAUSIBLE | THEORETICAL |
|----------|-------|-----------|-----------|-------------|
| Critical | | | | |
| High | | | | |
| Medium | | | | |
| Low | | | | |

**Top Issues** (Critical and High only):
- **[SS-NNN]** *Title* — credential type and exposure risk. Required action.

**Recommended Actions**: rotation priority, gitignore additions, secret manager migration.

---

### TIER 2 — TECHNICAL FINDINGS

For each finding:

#### [SS-NNN] — *Finding Title*

**Severity**: CRITICAL / HIGH / MEDIUM / LOW
**Confidence**: CONFIRMED / PLAUSIBLE / THEORETICAL

| Field | Detail |
|-------|--------|
| Secret Type | e.g. AWS Access Key, GitHub PAT, RSA Private Key |
| Location | `path/to/file.ext:NN` |
| Exposure | committed / env file staged / log output / error response |
| Entropy | high / medium (for unrecognized patterns) |
| Active Risk | credential still valid / unknown / likely rotated |
| Impact | |
| Mitigation | rotation steps + prevention |

---

**Secret Management Assessment**:
| Category | Finding |
|----------|---------|
| Vault / secrets manager in use | |
| .gitignore coverage | |
| CI/CD secret hygiene | |
| Rotation policy evidence | |
| Recommended tooling | |
'''

IAC_REVIEW_TEMPLATE = '''\
{target_line}

## Repository Context

{context}

## Required Report Format

Produce a two-tier Markdown IaC security review.

### TIER 1 — EXECUTIVE SUMMARY

**Infrastructure Risk Level**: CRITICAL / HIGH / MEDIUM / LOW / CLEAN

One-sentence summary.

**Finding Summary**:
| Severity | Count | CONFIRMED | PLAUSIBLE | THEORETICAL |
|----------|-------|-----------|-----------|-------------|

**Top Issues** (Critical and High only):
- **[IC-NNN]** *Title* — misconfiguration and blast radius. Required fix.

---

### TIER 2 — TECHNICAL FINDINGS

**IaC Inventory**:
| Tool | Files Found | Resources Defined | Issues |
|------|-------------|-------------------|--------|

For each finding:

#### [IC-NNN] — *Finding Title*

**Severity**: CRITICAL / HIGH / MEDIUM / LOW
**Confidence**: CONFIRMED / PLAUSIBLE / THEORETICAL

| Field | Detail |
|-------|--------|
| Tool | Terraform / Kubernetes / Helm / Dockerfile / CloudFormation |
| Resource | resource type and name |
| File | `path/to/file.tf:NN` |
| Misconfiguration | what is wrong |
| Evidence | quoted attribute and value |
| Blast Radius | impact if exploited |
| Mitigation | corrected HCL/YAML/Dockerfile snippet |
| Validation | `terraform plan` / `kubectl auth can-i` / etc. |

---

**Prioritized Remediation Roadmap**:
| Priority | ID | Title | Severity | Tool | Effort |
|----------|----|-------|----------|------|--------|
'''

CICD_AUDIT_TEMPLATE = '''\
{target_line}

## Repository Context

{context}

## Required Report Format

Produce a two-tier Markdown CI/CD security audit.

### TIER 1 — EXECUTIVE SUMMARY

**Pipeline Security Level**: CRITICAL / HIGH / MEDIUM / LOW / CLEAN

One-sentence summary.

**Finding Summary**:
| Severity | Count | CONFIRMED | PLAUSIBLE | THEORETICAL |
|----------|-------|-----------|-----------|-------------|

**Top Issues** (Critical and High only):
- **[CI-NNN]** *Title* — injection/exposure risk. Required fix.

---

### TIER 2 — TECHNICAL FINDINGS

**Secret Exposure Map**:
| Secret / Variable | Accessible to Fork PRs? | Exposed in Logs? | Scope |
|-------------------|------------------------|-----------------|-------|

For each finding:

#### [CI-NNN] — *Finding Title*

**Severity**: CRITICAL / HIGH / MEDIUM / LOW
**Confidence**: CONFIRMED / PLAUSIBLE / THEORETICAL

| Field | Detail |
|-------|--------|
| Workflow | `.github/workflows/filename.yml` |
| Job / Step | job name → step name |
| Injection Vector | exact `${{ github.context_value }}` or similar |
| Evidence | quoted workflow snippet |
| Attack Scenario | how an attacker exploits this |
| Impact | |
| Mitigation | corrected workflow YAML snippet |

---

**Action Provenance Audit**:
| Action | Pinned to SHA? | Verified? | Recommendation |
|--------|----------------|-----------|----------------|
'''

DEPENDENCY_AUDIT_TEMPLATE = '''\
{target_line}

## Repository Context

{context}

## Required Report Format

Produce a two-tier Markdown dependency supply chain audit.

### TIER 1 — EXECUTIVE SUMMARY

**Supply Chain Risk Level**: CRITICAL / HIGH / MEDIUM / LOW / CLEAN

One-sentence summary.

**Finding Summary**:
| Severity | Count | CONFIRMED | PLAUSIBLE | THEORETICAL |
|----------|-------|-----------|-----------|-------------|

**Top Issues** (Critical and High only):
- **[DA-NNN]** *Title* — package, risk type, required action.

**Recommended Actions**: update priorities and audit commands.

---

### TIER 2 — TECHNICAL FINDINGS

**Manifests Reviewed**:
| File | Ecosystem | Direct Deps | Lockfile Present | Risk |
|------|-----------|-------------|-----------------|------|

For each finding:

#### [DA-NNN] — *Finding Title*

**Severity**: CRITICAL / HIGH / MEDIUM / LOW
**Confidence**: CONFIRMED / PLAUSIBLE / THEORETICAL

| Field | Detail |
|-------|--------|
| Package | name@version |
| Manifest | `path/to/manifest:NN` |
| Attack Vector | CVE / confusion / typosquat / malicious hook / abandoned |
| Evidence | CVE ID or pattern match |
| Impact | |
| Mitigation | version pin / replacement / removal |

---

**Dependency Inventory**:
| Package | Version | Ecosystem | Direct/Transitive | Risk Flag |
|---------|---------|-----------|-------------------|-----------|

**Recommended Audit Commands**:
```
npm audit / pip-audit / cargo audit / etc.
```
'''

API_SECURITY_TEMPLATE = '''\
{target_line}

## Repository Context

{context}

## Required Report Format

Produce a two-tier Markdown API security review (OWASP API Security Top 10, 2023).

### TIER 1 — EXECUTIVE SUMMARY

**API Security Level**: CRITICAL / HIGH / MEDIUM / LOW / CLEAN

One-sentence summary.

**Finding Summary**:
| Severity | Count | CONFIRMED | PLAUSIBLE | THEORETICAL |
|----------|-------|-----------|-----------|-------------|

**Top Issues** (Critical and High only):
- **[AR-NNN]** *Title* — API category and risk. Required fix.

---

### TIER 2 — TECHNICAL FINDINGS

**API Endpoint Inventory**:
| Endpoint | Method | Auth Required | Auth Type | OWASP Category Risk |
|----------|--------|---------------|-----------|---------------------|

For each finding:

#### [AR-NNN] — *Finding Title*

**Severity**: CRITICAL / HIGH / MEDIUM / LOW
**Confidence**: CONFIRMED / PLAUSIBLE / THEORETICAL

| Field | Detail |
|-------|--------|
| OWASP API Category | API1:2023 – API10:2023 |
| CWE | |
| Endpoint | `METHOD /path/to/endpoint` |
| File | `path/to/file.ext:NN` |
| Evidence | quoted code snippet |
| Exploit Path | 1. → 2. → 3. |
| Impact | |
| Mitigation | corrected code snippet |

---

**OWASP API Security Coverage Matrix**:
| Category | Checked | Findings | Status |
|----------|---------|----------|--------|
| API1:2023 BOLA | ✓ | | |
| API2:2023 Broken Auth | ✓ | | |
| API3:2023 BOPLA | ✓ | | |
| API4:2023 Resource Consumption | ✓ | | |
| API5:2023 Function Auth | ✓ | | |
| API6:2023 Business Flow | ✓ | | |
| API7:2023 SSRF | ✓ | | |
| API8:2023 Misconfiguration | ✓ | | |
| API9:2023 Inventory | ✓ | | |
| API10:2023 Unsafe Consumption | ✓ | | |
'''

AUTH_REVIEW_TEMPLATE = '''\
{target_line}

## Repository Context

{context}

## Required Report Format

Produce a two-tier Markdown authentication and authorization security review.

### TIER 1 — EXECUTIVE SUMMARY

**Auth Security Level**: CRITICAL / HIGH / MEDIUM / LOW / CLEAN

One-sentence summary.

**Finding Summary**:
| Severity | Count | CONFIRMED | PLAUSIBLE | THEORETICAL |
|----------|-------|-----------|-----------|-------------|

**Top Issues** (Critical and High only):
- **[AU-NNN]** *Title* — auth category and risk. Required fix.

---

### TIER 2 — TECHNICAL FINDINGS

**Auth Coverage Matrix**:
| Category | Reviewed | Findings | Library/Pattern Used |
|----------|---------|----------|----------------------|
| OAuth 2.0 / OIDC | | | |
| JWT handling | | | |
| Session management | | | |
| CSRF protection | | | |
| MFA | | | |
| RBAC / ABAC | | | |
| Password hashing | | | |
| Brute-force protection | | | |
| Account enumeration | | | |
| Multi-tenancy isolation | | | |

For each finding:

#### [AU-NNN] — *Finding Title*

**Severity**: CRITICAL / HIGH / MEDIUM / LOW
**Confidence**: CONFIRMED / PLAUSIBLE / THEORETICAL

| Field | Detail |
|-------|--------|
| Auth Category | OAuth / JWT / Session / CSRF / MFA / RBAC / Password / etc. |
| CWE | |
| File | `path/to/file.ext:NN` |
| Evidence | quoted code snippet |
| Exploit Path | 1. → 2. → 3. |
| Impact | |
| Mitigation | corrected code snippet with library reference |

---

**Privilege Escalation Paths**:
| From Role | To Role | Path Found | Feasibility |
|-----------|---------|------------|-------------|
'''

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




def _lmstudio_call(system_prompt, user_prompt, model_override):
    """Call LM Studio using only stdlib — no openai package required."""
    import json
    import urllib.error
    import urllib.request

    base_url = os.environ.get('LMSTUDIO_BASE_URL', 'http://localhost:1234/v1')
    model = model_override or os.environ.get('LMSTUDIO_MODEL', '')

    if not model:
        try:
            with urllib.request.urlopen(f'{base_url}/models', timeout=5) as resp:
                data = json.loads(resp.read())
            loaded = [m['id'] for m in data.get('data', [])]
            if not loaded:
                print('ERROR: No model loaded in LM Studio. '
                      'Open LM Studio, load a model, and start the local server.',
                      file=sys.stderr)
                sys.exit(1)
            model = loaded[0]
            print(f'Auto-detected LM Studio model: {model}', flush=True)
        except (urllib.error.URLError, OSError) as exc:
            print(f'ERROR: Cannot reach LM Studio at {base_url}: {exc}\n'
                  'Make sure LM Studio is running and the local server is started.',
                  file=sys.stderr)
            sys.exit(1)

    payload = json.dumps({
        'model': model,
        'messages': [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user',   'content': user_prompt},
        ],
        'max_tokens': 8_000,
    }).encode()

    req = urllib.request.Request(
        f'{base_url}/chat/completions',
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    print(f'Calling lmstudio with model {model}...', flush=True)
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            result = json.loads(resp.read())
        return result['choices'][0]['message']['content']
    except (urllib.error.URLError, KeyError, json.JSONDecodeError) as exc:
        print(f'ERROR: LM Studio request failed: {exc}', file=sys.stderr)
        sys.exit(1)


def _openai_call(provider, system_prompt, user_prompt, model_override):
    """Call OpenAI or GitHub Models using the openai package."""
    from openai import OpenAI

    if provider == 'github-models':
        token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
        if not token:
            print('ERROR: GH_TOKEN or GITHUB_TOKEN must be set for github-models provider.',
                  file=sys.stderr)
            sys.exit(1)
        client = OpenAI(base_url='https://models.inference.ai.azure.com', api_key=token)
        model = model_override or 'openai/gpt-4o'
    else:
        client = OpenAI()
        model = model_override or 'gpt-4o'

    print(f'Calling {provider} with model {model}...', flush=True)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {'role': 'system', 'content': system_prompt},
            {'role': 'user',   'content': user_prompt},
        ],
        max_tokens=16_000,
    )
    return response.choices[0].message.content


def call_api(provider, system_prompt, user_prompt, model_override):
    if provider == 'lmstudio':
        return _lmstudio_call(system_prompt, user_prompt, model_override)
    return _openai_call(provider, system_prompt, user_prompt, model_override)


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Run AppSec analysis via OpenAI, GitHub Models, or LM Studio'
    )
    parser.add_argument('--mode', choices=[
        'pr-review', 'threat-model', 'secrets-scan', 'iac-review',
        'cicd-audit', 'dependency-audit', 'api-security', 'auth-review',
        'red-team', 'attack-tree',
    ], required=True)
    parser.add_argument('--provider', choices=['openai', 'github-models', 'lmstudio'], required=True)
    parser.add_argument('--base',   default='', help='Base commit SHA (pr-review only)')
    parser.add_argument('--head',   default='', help='Head commit SHA (pr-review only)')
    parser.add_argument('--target', default='', help='Threat model target (threat-model only)')
    parser.add_argument('--deep',   action='store_true',
                        help='Use aggressive deep-dive mode (threat-model only)')
    parser.add_argument('--output', required=True, help='Output path for the Markdown report')
    parser.add_argument('--model',  default='', help='Model override')
    args = parser.parse_args()

    is_local = args.provider == 'lmstudio'
    max_diff  = MAX_DIFF_CHARS_LOCAL  if is_local else MAX_DIFF_CHARS
    max_file  = MAX_FILE_BYTES_LOCAL  if is_local else MAX_FILE_BYTES

    if args.mode == 'pr-review':
        if not args.base or not args.head:
            print('ERROR: --base and --head are required for pr-review mode.', file=sys.stderr)
            sys.exit(1)
        diff    = get_diff(args.base, args.head, max_chars=max_diff)
        changed = get_changed_files(args.base, args.head)
        files_str    = '\n'.join(f'- {f}' for f in changed[:60])
        user_prompt  = PR_REVIEW_TEMPLATE.format(files=files_str, diff=diff)
        system_prompt = PR_REVIEW_SYSTEM

    elif args.mode == 'threat-model':
        context = gather_repo_context(max_file_bytes=max_file)
        target_line = (
            f'Threat model target: **{args.target}**'
            if args.target
            else (
                'No target specified. Autonomously inventory the repository, rank candidate '
                'components by external exposure, privilege level, sensitive-data handling, and '
                'blast radius, then select the highest-risk scope and explain the selection before '
                'producing the full report.'
            )
        )
        if args.deep:
            user_prompt   = THREAT_MODEL_DEEP_TEMPLATE.format(target_line=target_line, context=context)
            system_prompt = THREAT_MODEL_DEEP_SYSTEM
        else:
            user_prompt   = THREAT_MODEL_TEMPLATE.format(target_line=target_line, context=context)
            system_prompt = THREAT_MODEL_SYSTEM

    elif args.mode == 'secrets-scan':
        context = gather_repo_context(max_file_bytes=max_file)
        target_line = (
            f'Secrets scan target: **{args.target}**' if args.target
            else 'Scan the entire repository for hardcoded secrets and credential management issues.'
        )
        user_prompt   = SECRETS_SCAN_TEMPLATE.format(target_line=target_line, context=context)
        system_prompt = SECRETS_SCAN_SYSTEM

    elif args.mode == 'iac-review':
        context = gather_repo_context(max_file_bytes=max_file)
        target_line = (
            f'IaC review target: **{args.target}**' if args.target
            else 'Review all Infrastructure as Code in the repository.'
        )
        user_prompt   = IAC_REVIEW_TEMPLATE.format(target_line=target_line, context=context)
        system_prompt = IAC_REVIEW_SYSTEM

    elif args.mode == 'cicd-audit':
        context = gather_repo_context(max_file_bytes=max_file)
        target_line = (
            f'CI/CD audit target: **{args.target}**' if args.target
            else 'Audit all CI/CD pipeline configuration in the repository.'
        )
        user_prompt   = CICD_AUDIT_TEMPLATE.format(target_line=target_line, context=context)
        system_prompt = CICD_AUDIT_SYSTEM

    elif args.mode == 'dependency-audit':
        context = gather_repo_context(max_file_bytes=max_file)
        target_line = (
            f'Dependency audit target: **{args.target}**' if args.target
            else 'Audit all package manifests and lockfiles in the repository.'
        )
        user_prompt   = DEPENDENCY_AUDIT_TEMPLATE.format(target_line=target_line, context=context)
        system_prompt = DEPENDENCY_AUDIT_SYSTEM

    elif args.mode == 'api-security':
        context = gather_repo_context(max_file_bytes=max_file)
        target_line = (
            f'API security review target: **{args.target}**' if args.target
            else 'Review all API endpoints discovered in the repository.'
        )
        user_prompt   = API_SECURITY_TEMPLATE.format(target_line=target_line, context=context)
        system_prompt = API_SECURITY_SYSTEM

    elif args.mode == 'auth-review':
        context = gather_repo_context(max_file_bytes=max_file)
        target_line = (
            f'Auth review target: **{args.target}**' if args.target
            else 'Review all authentication and authorization code in the repository.'
        )
        user_prompt   = AUTH_REVIEW_TEMPLATE.format(target_line=target_line, context=context)
        system_prompt = AUTH_REVIEW_SYSTEM

    elif args.mode == 'red-team':
        context = gather_repo_context(max_file_bytes=max_file)
        target_line = (
            f'Red team target: **{args.target}**' if args.target
            else 'Select the 5 highest-risk attack surfaces from the repository.'
        )
        user_prompt   = RED_TEAM_TEMPLATE.format(target_line=target_line, context=context)
        system_prompt = RED_TEAM_SYSTEM

    elif args.mode == 'attack-tree':
        context = gather_repo_context(max_file_bytes=max_file)
        target = args.target or 'the highest-risk component in the repository'
        user_prompt   = ATTACK_TREE_TEMPLATE.format(target=target, context=context)
        system_prompt = ATTACK_TREE_SYSTEM

    else:
        print(f'ERROR: Unknown mode: {args.mode}', file=sys.stderr)
        sys.exit(1)

    report = call_api(args.provider, system_prompt, user_prompt, args.model)

    with open(args.output, 'w') as f:
        f.write(report)

    print(f'Report written to {args.output} ({len(report):,} characters).', flush=True)


if __name__ == '__main__':
    main()
