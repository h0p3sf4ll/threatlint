# Agent Reference

Detailed documentation for all eight threatlint security agents.

---

## Table of Contents

- [appsec-threat-modeler](#appsec-threat-modeler)
- [appsec-code-reviewer](#appsec-code-reviewer)
- [appsec-dependency-auditor](#appsec-dependency-auditor)
- [appsec-secrets-scanner](#appsec-secrets-scanner)
- [appsec-iac-reviewer](#appsec-iac-reviewer)
- [appsec-cicd-auditor](#appsec-cicd-auditor)
- [appsec-api-security-reviewer](#appsec-api-security-reviewer)
- [appsec-auth-reviewer](#appsec-auth-reviewer)

---

## appsec-threat-modeler

**Finding prefix**: `TM-NNN`  
**Slash command**: `/threat-model`, `/threat-model-deep`, `/threat-model-local`, `/threat-model-deep-local`  
**GitHub Copilot Chat**: `@AppSec Threat Modeler`  
**AGENTS.md routing**: "threat model", "analyze security risks", "review security posture"

### Purpose

Produces evidence-based threat models grounded in inspected source code, configuration, and infrastructure. When no target is specified, the agent autonomously inventories the repository, ranks candidate components by external exposure, privilege level, sensitive-data handling, and blast radius, then selects the highest-risk scope.

### What It Reviews

- Application source code and API surface
- Authentication, authorization, session management, and trust boundaries
- IaC, Dockerfile, CI/CD workflows, and dependency manifests
- Secrets handling, encryption, and external service integrations
- HTTP, CLI, queue, event, file, and WebSocket entry points

### Frameworks Applied

- **STRIDE** — Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation
- **OWASP Top 10** (2021)
- **CWE** — weakness classification for each finding
- **MITRE ATT&CK** — tactic and technique for applicable findings
- **DREAD** — Damage, Reproducibility, Exploitability, Affected users, Discoverability (score /10)
- **Compliance exposure** — PCI-DSS v4, HIPAA, SOC 2, ISO 27001, NIST CSF (when evidence supports)

### Attacker Personas

External/Unauthenticated, Authenticated User, Privileged Insider, Supply-Chain, Infrastructure/Cloud, Nation-State/APT

### Report Structure

**Tier 1 — Executive Summary**
- Risk Posture (1–2 sentences)
- Finding Summary table (CONFIRMED / PLAUSIBLE / THEORETICAL per severity)
- Top Immediate Actions (Critical and High only)
- Crown Jewel Analysis (asset → classification → impact → primary threat → control commensurate)
- Regulatory and Compliance Exposure
- Recommended Next Step

**Tier 2 — Technical Threat Model**
- Discovery and Scope Selection (when autonomously selected)
- Scope and Assumptions with numbered assumption list
- System Model: assets, actors, entry points, data flows, trust boundaries
- Data Flow Diagram (Mermaid flowchart)
- Threat Register: per-finding blocks with STRIDE/OWASP/CWE/ATT&CK/DREAD, preconditions, attack steps, evidence, Remediation Guidance, Validation
- Control Bypass Analysis table
- Chained Attack Scenarios (foothold → escalation → impact)
- Prioritized Remediation Roadmap
- Residual Risk and Suggested Focused Follow-Ups

### Deep-Dive Mode

`/threat-model-deep` enables AGGRESSIVE DEEP-DIVE mode:
- Escalates borderline THEORETICAL to PLAUSIBLE when production-realistic
- Requires at least one bypass path per defensive control
- Produces multi-step kill chains combining two or more findings
- Enforces per-category breadth coverage (injection, auth, authz, secrets, crypto, error handling, CI/CD, infrastructure)
- Produces Runtime Blindspot entries for every security decision deferred to runtime

---

## appsec-code-reviewer

**Finding prefix**: `CR-NNN`  
**Slash command**: `/security-review`, `/security-review-local`  
**GitHub Copilot Chat**: `@AppSec Code Reviewer`  
**AGENTS.md routing**: "security review", "review PR", "review diff", "review branch"

### Purpose

Reviews a code change (diff, branch, pull request, or working-tree diff) for security regressions, missing controls, introduced secrets, and new attack surface. Produces a merge recommendation.

### Diff Targeting

| Target | Behavior |
|--------|----------|
| No argument | Working-tree diff (staged + unstaged) |
| `main..feature` | Branch comparison |
| `abc123..def456` | Commit range |
| `42` | Pull request via `gh pr diff` |
| `-- path/` | Path-scoped diff |

### What It Inspects

- Changed entry points, route handlers, middleware, auth logic
- Modified input validation, deserialization, or ORM queries
- New or changed external calls, file I/O, shell commands
- Secrets introduced, new dependencies, version changes
- Modified CI/CD, Dockerfile, IaC, or security configuration
- Removed or weakened security controls

### Frameworks Applied

- **OWASP Top 10** (2021)
- **CWE**
- **MITRE ATT&CK** tactic and technique
- **Compliance** mapping where evidence supports

### Report Structure

**Tier 1 — Executive Summary**
- Change Risk Level: CRITICAL / HIGH / MEDIUM / LOW / CLEAN
- Finding Summary table
- Tech Stack detected (language, framework, ORM, auth library)
- Top Issues (Critical and High only)
- Merge Recommendation: BLOCK / MERGE WITH ACTION / MERGE

**Tier 2 — Technical Review**
- Review Scope with numbered assumptions
- Secrets Introduced section (required; "None detected." if absent)
- New Dependencies section (required; "None added." if absent)
- Per-finding blocks: Severity, Confidence, OWASP/CWE/ATT&CK, evidence from diff, exploit path, Remediation Guidance with before/after snippets, Test Case
- Security-Positive Changes (required)
- Residual Risk

---

## appsec-dependency-auditor

**Finding prefix**: `DA-NNN`  
**Slash command**: `/dependency-audit`, `/dependency-audit-local`  
**GitHub Copilot Chat**: `@AppSec Dependency Auditor`  
**Workflow**: `appsec-dependency-audit.yml` (triggers on manifest/lockfile changes)

### Purpose

Audits package manifests and lockfiles for supply chain security risk. Covers CVE version ranges, dependency confusion attack surfaces, typosquatting, malicious install hooks, abandoned packages, lockfile integrity, and package manager configuration security.

### Ecosystems Supported

npm / yarn, PyPI (pip/poetry/pipenv), Go modules, Cargo (Rust), Maven/Gradle (Java), RubyGems, Composer (PHP)

### What It Reviews

- **CVE exposure** — known vulnerable version ranges
- **Dependency confusion** — internal package names resolvable on public registries at higher versions
- **Typosquatting** — package names within one edit-distance of popular packages
- **Malicious install hooks** — `postinstall`, `prepare`, `install` scripts in npm; Python package hooks
- **Abandoned packages** — no recent releases or maintainer activity indicators
- **Version pinning** — floating ranges (`^`, `~`, `*`, `>=`) vs. exact pins
- **Lockfile integrity** — presence, freshness, and hash coverage
- **Registry configuration** — `.npmrc`, `pip.conf` custom registries that could introduce risk

### Report Structure

**Tier 1 — Executive Summary**
- Supply Chain Risk Level
- Finding Summary table
- Top Issues
- Recommended Actions: rotation/update priorities and audit commands

**Tier 2 — Technical Findings**
- Manifests Reviewed table (ecosystem, lockfile present, risk)
- Per-finding blocks: `DA-NNN`, package@version, manifest location, attack vector, evidence, impact, mitigation
- Dependency Inventory table
- Recommended Audit Commands (ecosystem-specific CLI invocations)

---

## appsec-secrets-scanner

**Finding prefix**: `SS-NNN`  
**Slash command**: `/secrets-scan`, `/secrets-scan-local`  
**GitHub Copilot Chat**: `@AppSec Secrets Scanner`

### Purpose

Scans the repository for hardcoded credentials, API keys, private keys, database connection strings, and secret management anti-patterns. Extends detection beyond source code to git history hints, CI/CD configuration, environment files, and error output patterns.

### Secret Formats Detected

| Type | Pattern |
|------|---------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| AWS Secret Key | 40-char Base64 near "aws_secret" |
| GCP Service Account | JSON with `"private_key"` field |
| Azure credentials | Connection strings, SAS tokens |
| GitHub PAT (classic) | `ghp_[A-Za-z0-9]{36}` |
| GitHub PAT (fine-grained) | `github_pat_[A-Za-z0-9_]{82}` |
| Anthropic API key | `sk-ant-[A-Za-z0-9_-]{90,}` |
| OpenAI API key | `sk-[A-Za-z0-9]{48}` |
| Stripe secret key | `sk_live_[A-Za-z0-9]{24}` |
| SendGrid API key | `SG.[A-Za-z0-9_-]{22}.[A-Za-z0-9_-]{43}` |
| Slack token | `xox[bpas]-[0-9A-Za-z-]+` |
| RSA / EC private key | `-----BEGIN ... PRIVATE KEY-----` |
| Generic high-entropy | configurable entropy threshold |
| DB connection string | credentials in URI format |

### What It Reviews

- All source files (language-agnostic)
- CI/CD workflow YAML (secret references vs. hardcoded values)
- `.env`, `.env.*`, config files
- IaC files (Terraform state, Kubernetes Secrets)
- Build scripts and Makefile
- git history (commit messages and blob scanning hints)

### Report Structure

**Tier 1 — Executive Summary**
- Secrets Exposure Level
- Finding Summary table
- Top Issues (Critical and High only)
- Recommended Actions: rotation steps, `.gitignore` additions, secret manager migration

**Tier 2 — Technical Findings**
- Per-finding blocks: `SS-NNN`, secret type, location with line number, exposure context, active risk assessment, impact, mitigation
- Secret Management Assessment table (vault in use, `.gitignore` coverage, CI/CD hygiene, rotation policy, tooling recommendation)

---

## appsec-iac-reviewer

**Finding prefix**: `IC-NNN`  
**Slash command**: `/iac-review`, `/iac-review-local`  
**GitHub Copilot Chat**: `@AppSec IaC Reviewer`  
**Workflow**: `appsec-iac-review.yml` (triggers on Terraform, Kubernetes, Dockerfile changes)

### Purpose

Reviews Infrastructure as Code for security misconfigurations that could enable privilege escalation, lateral movement, data exfiltration, or availability attacks.

### IaC Tools Supported

Terraform, Kubernetes (manifests and Helm), Dockerfile and docker-compose, AWS CloudFormation and CDK, Pulumi, Ansible (playbooks)

### What It Reviews

**Terraform / CloudFormation:**
- IAM policies: wildcard actions, wildcard resources, overly-permissive trust policies
- Security groups / NACLs: ports open to `0.0.0.0/0` or `::/0`
- Encryption: S3 bucket encryption, RDS storage encryption, KMS key rotation
- Network: public-facing resources without expected justification
- Secrets: hardcoded credentials in resource attributes or variable defaults

**Kubernetes:**
- Pod security: `privileged: true`, `allowPrivilegeEscalation`, `runAsRoot`, `hostPID/hostNetwork`
- RBAC: ClusterRoleBindings to `system:masters`, wildcard verbs in roles
- Network policies: missing ingress/egress policies
- Images: `:latest` tags, missing digest pinning
- Secrets: secret data in ConfigMaps or environment variables in plaintext

**Dockerfile:**
- Base image: `:latest` tag, known-vulnerable base images
- Running as root: missing `USER` instruction
- `ADD` with URLs vs. `COPY`
- Sensitive files (`*.pem`, `id_rsa`) copied into image
- Multi-stage build misuse that leaves build tools in final image

### Report Structure

**Tier 1 — Executive Summary**
- Infrastructure Risk Level
- Finding Summary table
- Top Issues

**Tier 2 — Technical Findings**
- IaC Inventory table (tool, files found, resources defined, issues)
- Per-finding blocks: `IC-NNN`, tool, resource name, file location, misconfiguration, evidence, blast radius, corrected snippet, validation command
- Prioritized Remediation Roadmap

---

## appsec-cicd-auditor

**Finding prefix**: `CI-NNN`  
**Slash command**: `/cicd-audit`, `/cicd-audit-local`  
**GitHub Copilot Chat**: `@AppSec CI/CD Auditor`

### Purpose

Audits CI/CD pipeline configuration — primarily GitHub Actions but also GitLab CI, CircleCI, and Jenkins — for security weaknesses that could enable secret theft, supply chain compromise, or unauthorized code execution.

### What It Reviews

**GitHub Actions — Script Injection:**
Exhaustive check for untrusted context values interpolated into `run:` blocks:
- `github.head_ref`, `github.base_ref`
- `github.event.pull_request.title`, `.body`, `.head.ref`, `.head.label`
- `github.event.issue.title`, `.body`
- `github.event.comment.body`
- `github.event.review.body`
- `github.event.inputs.*`
- `github.event.client_payload.*`

**GitHub Actions — Workflow Risks:**
- `pull_request_target` with checkout of PR head branch (TOCTOU + secret exposure)
- Workflow permissions: `write-all`, missing `permissions:` block
- Action pinning: actions not pinned to a specific commit SHA
- `continue-on-error: true` on security-critical steps
- `if: always()` without permission guards

**Fork PR Exposure:**
- Secrets accessible to fork-triggered workflows
- `GITHUB_TOKEN` write permissions on fork PRs

**Self-Hosted Runners:**
- Runners shared across security boundaries
- No ephemeral runner configuration

**Artifact Integrity:**
- Unsigned artifacts consumed by later steps
- Missing attestation (SLSA)

### Report Structure

**Tier 1 — Executive Summary**
- Pipeline Security Level
- Finding Summary table
- Top Issues

**Tier 2 — Technical Findings**
- Secret Exposure Map table (secret/variable, fork-accessible, logged, scope)
- Per-finding blocks: `CI-NNN`, workflow file, job/step, injection vector with exact context expression, evidence, attack scenario, impact, corrected YAML snippet
- Action Provenance Audit table (action, SHA-pinned, verified, recommendation)

---

## appsec-api-security-reviewer

**Finding prefix**: `AR-NNN`  
**Slash command**: `/api-security-review`, `/api-security-review-local`  
**GitHub Copilot Chat**: `@AppSec API Security Reviewer`

### Purpose

Reviews all API endpoints — REST, GraphQL, gRPC, and WebSocket — for the OWASP API Security Top 10 (2023) and related weaknesses. Traces authorization checks from route definitions through to data access layers.

### OWASP API Security Top 10 Coverage

| Category | Key Questions |
|----------|---------------|
| API1:2023 BOLA | Does every object access verify the caller owns the requested ID? |
| API2:2023 Broken Auth | Are tokens validated server-side? Are defaults and weak algorithms excluded? |
| API3:2023 BOPLA | Can callers read/write object properties they shouldn't? Mass assignment? |
| API4:2023 Resource Consumption | Are rate limits, pagination caps, and query depth limits enforced? |
| API5:2023 Function Auth | Do admin and privileged endpoints verify the caller's role? |
| API6:2023 Business Flow | Can legitimate flows be abused (e.g., purchase bypasses, enumeration)? |
| API7:2023 SSRF | Do URL parameters or webhook targets reach internal services? |
| API8:2023 Misconfiguration | Are CORS policies, headers, and TLS configured correctly? |
| API9:2023 Inventory | Are all endpoints documented? Any shadow or undocumented endpoints? |
| API10:2023 Unsafe Consumption | Are third-party API responses validated before use? |

### Additional Checks

- Mass assignment: request body fields bound directly to ORM models
- Excessive data exposure: response bodies including fields beyond what the caller needs
- Input validation: type coercion, schema validation, injection into downstream services
- GraphQL introspection enabled in production; unbounded query depth/complexity

### Report Structure

**Tier 1 — Executive Summary**
- API Security Level
- Finding Summary table
- Top Issues

**Tier 2 — Technical Findings**
- API Endpoint Inventory table (path, method, auth required, auth type, risk flags)
- Per-finding blocks: `AR-NNN`, OWASP API category, CWE, endpoint, file location, evidence, exploit path, impact, corrected code snippet
- OWASP API Security Coverage Matrix (all 10 categories, checked/findings/status)

---

## appsec-auth-reviewer

**Finding prefix**: `AU-NNN`  
**Slash command**: `/auth-review`, `/auth-review-local`  
**GitHub Copilot Chat**: `@AppSec Auth Reviewer`

### Purpose

Performs a deep-dive security review of all authentication and authorization code, tracing every privilege decision from request receipt to data access.

### Coverage Areas

**OAuth 2.0 / OIDC:**
- Missing `state` parameter (CSRF against OAuth flow)
- Missing PKCE for public clients
- Redirect URI validation (open redirect, prefix matching bypass)
- Scope minimization and principle of least privilege
- ID token signature and claims validation

**JWT:**
- Algorithm confusion (`none`, RS256→HS256 downgrade)
- Required claims validation (`iss`, `aud`, `exp`, `nbf`, `sub`)
- Secret strength and rotation
- Token storage (localStorage vs. httpOnly cookie)
- JTI blacklisting for revocation

**Session Management:**
- Token entropy (minimum 128 bits)
- Session fixation (regenerate on privilege change)
- Revocation on logout and password change
- Cookie flags: `HttpOnly`, `Secure`, `SameSite=Strict/Lax`
- Absolute and sliding expiry

**CSRF:**
- Double-submit cookie or synchronizer token pattern
- `SameSite` cookie attribute as defense-in-depth
- Custom request header patterns

**MFA:**
- TOTP window size (1–2 steps max)
- Backup code entropy and single-use enforcement
- MFA bypass paths: account recovery, password reset, trusted-device bypass

**RBAC / ABAC:**
- Middleware order: auth before authz
- Per-object permission checks (IDOR / BOLA)
- Privilege escalation via role parameter manipulation
- Multi-tenancy isolation: tenant scoping in all queries

**Password Security:**
- Hashing algorithm: `bcrypt` (cost ≥ 12) or `Argon2id`
- No reversible encoding (Base64, AES-ECB) for password storage
- Timing-safe comparison

**Brute-Force / Account Enumeration:**
- Rate limiting on login, password reset, and OTP endpoints
- Consistent error messages (no user enumeration)
- Account lockout and exponential backoff

### Report Structure

**Tier 1 — Executive Summary**
- Auth Security Level
- Finding Summary table
- Top Issues

**Tier 2 — Technical Findings**
- Auth Coverage Matrix table (category, reviewed, findings, library/pattern used)
- Per-finding blocks: `AU-NNN`, auth category, CWE, file/line, evidence, exploit path, impact, corrected code snippet with library reference
- Privilege Escalation Paths table (from role → to role → path → feasibility)

---

*All agents are read-only. They do not modify workspace files, install dependencies, stage changes, or create commits.*
