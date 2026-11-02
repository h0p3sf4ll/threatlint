"""Snapshot instructions for secrets, deployment, CI/CD, and supply-chain audits."""

SECRETS_SCAN_SYSTEM = (
    'You are an expert application security engineer specializing in secrets detection and credential management. '
    'Search exhaustively for hardcoded credentials, API keys, private keys, connection strings, and secret management '
    'anti-patterns. Flag any value that would grant access if exfiltrated. '
    'Scan git history hints, environment variable handling, config files, and CI/CD configuration, not just source code. '
    'Label every finding with the exact file and line. Report only security findings — no style or performance issues.'
)

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

IAC_REVIEW_SYSTEM = (
    'You are an expert cloud and infrastructure security engineer. '
    'Review all Infrastructure as Code for security misconfigurations: overly permissive IAM policies, '
    'open network policies, missing encryption, privileged container settings, insecure default configurations, '
    'and secrets embedded in infrastructure definitions. '
    'Apply an aggressive posture: flag any resource whose misconfiguration could enable lateral movement, '
    'data exfiltration, or privilege escalation, even if a separate compensating control might exist. '
    'Cite the exact resource name, file, and attribute for every finding.'
)

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

CICD_AUDIT_SYSTEM = (
    'You are an expert CI/CD and DevSecOps security engineer. '
    'Audit all pipeline configuration for security weaknesses: script injection via untrusted context values '
    '(github.head_ref, github.event.pull_request.body, github.event.issue.title, etc.), '
    'pull_request_target misuse, workflow permissions, action pinning, self-hosted runner exposure, '
    'fork PR secret exposure, artifact integrity, and pipeline secret handling. '
    'Be exhaustive: enumerate every untrusted context value interpolated into a run: block. '
    'Cite the workflow file, job name, step name, and line for every finding.'
)

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

DEPENDENCY_AUDIT_SYSTEM = (
    'You are an expert supply chain security engineer. '
    'Audit package manifests and lockfiles for supply chain risks: '
    'known CVE version ranges, dependency confusion attack surfaces, typosquatting targets, '
    'malicious install hooks (postinstall, prepare), abandoned packages, unpinned version ranges, '
    'missing lockfile integrity (checksums, signatures), and package manager configuration secrets. '
    'Distinguish between direct and transitive dependencies. '
    'Cite the manifest file, package name, and version for every finding.'
)

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
