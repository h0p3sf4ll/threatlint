# <img src="media/logo.svg" alt="" width="28" height="31" align="top"> Agent Reference

Detailed documentation for the registered threatlint security agents.

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
- [appsec-fp-reviewer](#appsec-fp-reviewer)
- [appsec-compliance-checker](#appsec-compliance-checker)
- [appsec-attack-tree](#appsec-attack-tree)
- [appsec-red-team](#appsec-red-team)
- [appsec-threat-delta](#appsec-threat-delta)
- [appsec-verify-fix](#appsec-verify-fix)
- [appsec-runtime-reviewer](#appsec-runtime-reviewer)
- [appsec-business-logic-reviewer](#appsec-business-logic-reviewer)
- [appsec-client-security-reviewer](#appsec-client-security-reviewer)
- [appsec-crypto-reviewer](#appsec-crypto-reviewer)
- [appsec-ai-security-reviewer](#appsec-ai-security-reviewer)
- [appsec-security-test-planner](#appsec-security-test-planner)
- [appsec-secure-codegen-reviewer](#appsec-secure-codegen-reviewer)
- [appsec-privacy-reviewer](#appsec-privacy-reviewer)

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

## appsec-runtime-reviewer

**Finding prefix**: `DX-NNN`  
**CLI / Teams mode**: `runtime-review`  
**Slash commands**: `/runtime-review`, `/runtime-review-local`

### Purpose

Correlates explicitly supplied, redacted runtime observations with source code, build/revision, authentication role/tenant, and capture provenance. It reviews evidence; it does not collect captures, browse targets, issue requests, log in, or automate SSO/MFA.

### What It Reviews

- Capture/check provenance, redirect context, identity state, and deployment drift
- Route, middleware, proxy/configuration, sensitive operation, and effective defenses
- Observation versus hardening note, blocked/inconclusive check, or supported vulnerability
- Supplied authentication evidence and manual prerequisites through the runtime-auth-workflows skill

### Report Structure

Evidence-supported executive summary, source/capture coverage matrix, DX findings with observed versus inferred impact, anchored advisory fixes, owners/effort, acceptance criteria, and evidence gaps. Missing headers/statuses alone are not verified vulnerabilities. Additional collection and validation are proposals **NOT RUN**.

---

## appsec-business-logic-reviewer

**Finding prefix**: `BL-NNN`  
**CLI / Teams mode**: `business-logic-review`  
**Slash commands**: `/business-logic-review`, `/business-logic-review-local`

### Purpose

Reviews source-backed invariants and sensitive state transitions for workflow, entitlement, transactional, and asynchronous abuse. It states unknown policy explicitly rather than inventing business rules or financial impact.

### What It Reviews

- Authoritative values, approval/entitlement checks, transitions, and durable side effects
- Idempotency scope, replay, retries, duplicate/out-of-order jobs, and webhook provenance
- Transaction/isolation/constraint semantics and concrete bounded race interleavings
- Role/tenant binding through queues, caches, exports, delegated operations, and compensation

### Report Structure

Executive risk summary, invariant/transition coverage matrix, BL findings with quoted check and side-effect locations, advisory fixes with retry/rollout implications, owners/effort, and synthetic acceptance cases **NOT RUN**. The agent never executes races, replays webhooks, places orders, or transfers value.

---

## appsec-client-security-reviewer

**Finding prefix**: `CL-NNN`  
**CLI / Teams mode**: `client-security-review`  
**Slash commands**: `/client-security-review`, `/client-security-review-local`

### Purpose

Reviews actual browser, SPA, Electron, and mobile-client trust boundaries from untrusted input to rendering, navigation, messaging, privileged bridges, and server enforcement. It does not launch browsers/apps, invoke IPC/deep links, or use sessions.

### What It Reviews

- Context-specific encoding/sanitization and DOM/HTML/script/navigation flows
- Origins, frames, postMessage, opener behavior, service workers, and account switching
- Electron/native sandbox, bridge/IPC validation, sender identity, and privileged sinks
- Sensitive storage, URLs/logs/analytics, logout lifecycle, and backend authorization

### Report Structure

Executive summary, client-boundary coverage matrix, CL findings with source-to-sink evidence and actual privilege effects, framework-native advisory fixes, owners/effort, compatibility notes, and isolation acceptance cases **NOT RUN**. Sink names, missing headers, or screenshots alone do not prove compromise.

---

## appsec-crypto-reviewer

**Finding prefix**: `CY-NNN`  
**CLI / Teams mode**: `crypto-review`  
**Slash commands**: `/crypto-review`, `/crypto-review-local`

### Purpose

Reviews cryptographic implementation and key lifecycles against the security property actually required by callers. It never uses real keys, decrypts/cracks data, probes TLS, or performs cryptographic experiments.

### What It Reviews

- Primitive/mode/library semantics, authenticated encryption, MAC/signature verification, and context binding
- Entropy, KDF parameters, salt/domain separation, nonce uniqueness, concurrency, and restart behavior
- Key-generation/access/storage references, rotation, revocation, version selection, and backup
- Certificate/hostname verification and storage/wire-format migration compatibility

### Report Structure

Executive summary, cryptographic-use inventory, CY findings tied to a supported security property and reachable use, established-library/KMS advisory fixes, migration/rotation/rollback guidance, owners/effort, and synthetic-key acceptance cases **NOT RUN**. Non-security checksums are not vulnerabilities solely because of algorithm names.

---

## appsec-ai-security-reviewer

**Finding prefix**: `AI-NNN`  
**CLI / Teams mode**: `ai-security-review`  
**Slash commands**: `/ai-security-review`, `/ai-security-review-local`

### Purpose

Reviews AI/LLM trust and authority boundaries without equating prompt influence with authorization. It does not call reviewed providers/tools, submit adversarial prompts, poison indexes, or execute evaluations.

### What It Reviews

- Direct/indirect inputs through prompts, retrieval, memory, tool results, and agent handoffs
- Deterministic tool dispatch, validation, per-action approval, identity/tenant binding, and least privilege
- Ingestion/retrieval provenance, document ACLs, cache/vector/memory isolation, and consumption-time enforcement
- Generated-output sinks, observable provider data flows, secrets handling, and resource budgets

### Report Structure

Executive summary, AI trust/authority coverage matrix, AI findings with input-to-sensitive-operation evidence, deterministic advisory controls, owners/effort, compatibility notes, and synthetic injection/tool/RAG/output/tenant acceptance cases **NOT RUN**. Model behavior and provider-policy unknowns remain explicit limitations.

---

## appsec-security-test-planner

**Plan-item prefix**: `ST-NNN`  
**CLI / Teams mode**: `security-test-plan`  
**Slash commands**: `/security-test-plan`, `/security-test-plan-local`

### Purpose

Designs implementable, source-grounded security regression and acceptance plans without writing or executing tests. It preserves upstream finding IDs; ST identifiers are plan cases, not newly verified vulnerabilities. A plan is not proof of remediation.

### What It Plans

- Finding/invariant-to-control-to-case traceability and synthetic fixtures
- Allowed/denied, boundary/bypass, replay/race, role/tenant, and rollback cases where supported
- State/data/side-effect oracles, owners/effort, deterministic reset, budgets, and cleanup
- Separate runtime action approval, manual SSO/MFA prerequisites, redaction, and stop conditions through runtime-auth-workflows

### Report Structure

Executive coverage summary and traceable acceptance matrix; per-ST-case provenance, prerequisites, fixture, action description, observable oracle, expected result, budgets, owner, and must-pass gate. Proposed cases remain **NOT RUN**; absent authorization/auth state is **BLOCKED**. Supplied results require artifact provenance and do not imply independent reproduction.

---

*All agents are read-only. They do not modify workspace files, install dependencies, stage changes, or create commits. Report persistence is host-owned. The new specialists do not control runtime engines or perform live validation; Teams and snapshot modes analyze supplied evidence only.*

---

## appsec-secure-codegen-reviewer

**Finding prefix**: `SG-NNN`  
**CLI / Teams mode**: `secure-codegen-review`  
**Slash commands**: `/secure-codegen-review`, `/secure-codegen-review-local`

### Purpose

Reviews AI/model-generated and newly written code for insecure-by-default patterns before merge, and proposes drop-in secure rewrites that use the project's existing helpers. Defaults to the working-tree diff. It never executes code, payloads, or tests.

### What It Reviews

- Source-to-sink paths into SQL/NoSQL, command, template/HTML, `eval`, deserialization, filesystem, redirect, and outbound-URL (SSRF) sinks
- Insecure defaults: disabled TLS verification, weak crypto/randomness, hardcoded secrets, permissive CORS, debug errors, disabled CSRF
- New routes or handlers missing the authentication/authorization guard used by neighboring code
- Unpinned or nonexistent (hallucinated) dependencies and missing size/rate limits

### Report Structure

Executive summary, generated-code pattern inventory, SG findings with quoted source/sink lines, before/after secure-by-default rewrites (**NOT APPLIED**), reusable IDE/assistant guardrails, owners/effort, and regression assertions **NOT RUN**.

---

## appsec-privacy-reviewer

**Finding prefix**: `PD-NNN`  
**CLI / Teams mode**: `privacy-review`  
**Slash commands**: `/privacy-review`, `/privacy-review-local`

### Purpose

Inventories personal and sensitive data and traces it through storage, logs, analytics, AI providers, and third parties. It never prints or queries real personal data and does not provide legal or regulatory opinions.

### What It Reviews

- Data inventory: category, location, source, purpose, storage, recipients, retention, and protection
- Outbound flows to logs, error trackers, analytics/session-replay SDKs, LLM providers, webhooks, and messaging services
- Minimization, over-broad serializers, retention/purge and deletion handling, consent gating, and sensitive-record access control
- Encryption/tokenization at rest and TLS in transit for sensitive categories

### Report Structure

Executive summary, data inventory and flow summary, PD findings with quoted collection/flow/storage lines, framework-native advisory fixes, owners/effort, obligations for privacy/legal confirmation, and synthetic-data acceptance cases **NOT RUN**.

---

## appsec-fp-reviewer

**Finding prefix**: `FP-NNN`  
**Slash command**: `/fp-review`  
**GitHub Copilot Chat**: `@AppSec False Positive Reviewer`  
**AGENTS.md routing**: "triage findings", "false positive", "semgrep tuning"

### Purpose

Produces a professionally written findings and remediation report from SARIF 2.1.0, Semgrep JSON, Threatlint Markdown, or pasted findings. The reviewer separates source-supported TRUE POSITIVE, FALSE POSITIVE, and AMBIGUOUS verdicts from severity/confidence, proposes concrete fixes, and evaluates scanner-tuning risk independently. It never applies proposals.

### Required Skills

The reviewer loads evidence analysis, actionable reporting, finding triage, and Semgrep tuning. All other agents load the shared evidence/reporting workflows plus their own specialist skill. See [the registry](../src/threatlint/data/agent-skills.json) and [the workbench guide](workbench.md).

### What It Reviews

- Scanner findings: rule ID, matched file, line, snippet
- Surrounding code context (±30 lines) for each flagged location
- Whether the pattern is reachable by attacker-controlled input
- Whether safe sinks, sanitizers, or allowlists are in scope
- Alternative Semgrep patterns to narrow or widen the rule

### Frameworks Applied

- **Semgrep** rule syntax (pattern, pattern-not, pattern-inside, focus-metavariable, taint mode)
- **SARIF 2.1.0** for structured input parsing

### Report Structure

- **Tier 1 — Executive Summary**: input/unique/duplicate/unreviewed accounting, risk decision, prioritized actions, suggested owners/effort, and acceptance.
- **Tier 2 — Detailed Findings**: original IDs and source/scan provenance, path/line evidence, source-to-control-to-sink reasoning, verdict/severity/confidence, and alternative interpretations.
- **True positives**: concrete proposed before/after or patch, implementation/compatibility notes, regression assertions, and closure criteria. Proposed changes are NOT APPLIED; proposed tests are NOT RUN.
- **False positives**: verified contextual reason, narrow rule proposal only when the original rule is known, ruleid/ok fixtures, coverage/blast radius, approval and rollback. Missing rule details block exact tuning, not necessarily the FP verdict.
- **Ambiguous findings**: remain open, with exact blocking evidence, a suggested owner, a safe resolution plan, and an interim action.
- **Tier 3 — Engineering Action Plan**: suppression impact, systemic root causes, remediation roadmap, acceptance matrix, limitations, and unresolved questions. No blanket suppressions or unsupported zero-false-negative promises.

---

## appsec-compliance-checker

**Finding prefix**: `CC-NNN`  
**Slash command**: `/compliance-check`  
**GitHub Copilot Chat**: `@AppSec Compliance Checker`  
**AGENTS.md routing**: "compliance", "ASVS", "PCI-DSS", "HIPAA", "SOC 2", "ISO 27001", "NIST CSF"

### Purpose

Maps concrete technical security findings to specific control requirements in OWASP ASVS 4.0, PCI-DSS v4, HIPAA, SOC 2 Type II, ISO 27001:2022, NIST CSF 2.0, and CIS Controls v8. Detects applicable frameworks from repository evidence and labels only the controls that apply to the codebase under review.

### What It Reviews

- Prior findings from threat model, code review, or other agents (accepted via chain context)
- Repository evidence for framework scope detection (payment code, health data, multi-tenancy, IaC, policies)
- Per-finding control mapping with gap type: Missing / Partial / Met
- Compliance roadmap to reach each framework's baseline

### Frameworks Applied

- **OWASP ASVS 4.0** — always applicable for web applications
- **PCI-DSS v4** — when payment card data or payment SDKs are detected
- **HIPAA** — when health records, ePHI, or medical terminology is detected
- **SOC 2 Type II** — when SaaS/cloud service, customer data, or uptime SLAs are detected
- **ISO 27001:2022** — when formal information asset registers or policy references are detected
- **NIST CSF 2.0** — when critical infrastructure signals or government context is detected
- **CIS Controls v8** — always applicable as a foundational baseline

### Report Structure

**Tier 1 — Framework Readiness Summary**
- Applicable frameworks with scope rationale
- Readiness table (Controls Evaluated, Gaps Identified, Critical Gaps, Readiness status)
- Top compliance gaps (Critical only)

**Tier 2 — Per-Finding Control Mapping**
- Control mapping table per finding: Framework, Section, Control ID, Control Title, Gap Type
- Remediation steps targeting the specific control requirement

**Tier 3 — Remediation Priority Matrix**
- Prioritized gap table by framework
- Compliance roadmap grouped by framework
- Residual gaps requiring runtime or policy evidence

---

## appsec-attack-tree

**Finding prefix**: `AT-NNN`  
**Slash command**: `/attack-tree`, `/attack-tree-local`  
**GitHub Copilot Chat**: `@AppSec Attack Tree`  
**AGENTS.md routing**: "attack tree", "attack paths", "formal threat tree", "AND/OR tree"

### Purpose

Constructs a formal AND/OR attack tree for the most critical threat in the repository. Produces a Mermaid-rendered tree, bypass analysis for each defense node, a ranked leaf node table by exploitability and impact, and purple-team test cases. Best used after `appsec-threat-modeler` has identified the primary target.

### Node Types

- **OR** — attacker needs to succeed at ONE child (any path works)
- **AND** — attacker needs to succeed at ALL children (all must be overcome)
- **LEAF** — atomic attack step with direct code evidence
- **DEFENSE** — existing control that must be bypassed

### Frameworks Applied

- **MITRE ATT&CK** — techniques mapped to each LEAF node
- **CVSS v3.1** — exploitability score informing Difficulty ratings

### Report Structure

**Tier 1 — Attack Tree (Mermaid)**
- Complete `graph TD` tree with OR/AND/LEAF/DEF node styling

**Tier 2 — Leaf Node Ranking**
- Ranking table: Difficulty (1–5), Impact (1–5), Risk = Impact × (6 − Difficulty)
- Top 3 highest-risk complete paths

**Tier 3 — Defense Bypass Analysis**
- Per DEFENSE node: implementation, bypass status (BYPASSABLE / ROBUST / UNVERIFIABLE), bypass path with evidence, hardening recommendation

**Tier 4 — Purple-Team Test Cases**
- Per top-3 path: prerequisites, steps, expected result, detection opportunity

---

## appsec-red-team

**Finding prefix**: `RT-NNN`  
**Slash command**: `/red-team`, `/red-team-local`  
**GitHub Copilot Chat**: `@AppSec Red Team`  
**AGENTS.md routing**: "red team", "adversarial scenarios", "kill chains", "attacker simulation"

### Purpose

Generates exactly 5 adversarial attack scenarios against the repository, each grounded in actual codebase evidence. Each scenario covers a distinct attacker profile and includes a complete ATT&CK-mapped kill chain, IoCs, detection gaps, and a purple-team test case.

### Attacker Profiles

Each of the 5 scenarios covers exactly one profile:
1. **Opportunistic** — automated / script-kiddie
2. **Motivated External** — skilled targeted attacker
3. **Malicious Insider** — authenticated employee/contractor
4. **Nation-State / APT** — persistent, high-capability
5. **Supply-Chain** — compromised dependency, Action, or image

### Frameworks Applied

- **MITRE ATT&CK** — technique IDs for every kill chain step
- **OWASP Top 10** — for web-layer initial access techniques
- **Cyber Kill Chain** — for structuring scenario phases

### Report Structure

- **Scenario Overview Table**: profile, entry point, objective, highest ATT&CK tactic, severity
- **Per Scenario**: kill chain table (Phase, ATT&CK Technique, Action, Evidence), narrative, IoCs table, Detection Gaps, Purple-Team Test Case
- **Consolidated Findings**: detection coverage summary, top 5 hardening recommendations, ATT&CK coverage heat map

---

## appsec-threat-delta

**Finding prefix**: `TD-NNN`  
**Slash command**: `/threat-delta`  
**GitHub Copilot Chat**: `@AppSec Threat Delta`  
**AGENTS.md routing**: "compare reports", "what changed", "resolved findings", "regressions"

### Purpose

Compares a previous threat model or security report to the current repository state. Classifies each prior finding with a verdict and surfaces new attack surfaces introduced since the prior report.

### Verdict Taxonomy

- **RESOLVED** — fix present and verifiable; no equivalent bypass
- **PARTIALLY FIXED** — specific variant patched; underlying class still exploitable
- **STILL PRESENT** — no material change; finding carries over unchanged
- **REGRESSED** — was fixed; reintroduced in current code
- **NEW** — not in prior report; discovered during current inspection
- **WONT FIX / ACCEPTED** — documented acceptance in codebase
- **CANT ASSESS** — insufficient evidence (runtime-only, infrastructure-only)

### What It Reviews

- All finding IDs, titles, severity, and evidence locations from the prior report
- Current code at each cited location
- Git history for intentional fixes and reverts
- Changed files since the prior report date for new attack surfaces

### Report Structure

**Tier 1 — Delta Summary**
- Net risk change (IMPROVED / UNCHANGED / DEGRADED)
- Verdict counts by severity
- Regressions list (highest priority)
- New findings list

**Tier 2 — Finding-by-Finding Delta**
- Per finding: prior evidence, verdict, current code quote, rationale, residual risk (PARTIALLY FIXED), regression source (REGRESSED)
- New findings as full finding blocks

**Tier 3 — Remediation Roadmap Update**
- Close/reopen/open ticket recommendations
- Updated priority matrix

---

## appsec-verify-fix

**Finding prefix**: `VF-NNN`  
**Slash command**: `/verify-fix`  
**GitHub Copilot Chat**: `@AppSec Verify Fix`  
**AGENTS.md routing**: "was this fixed", "confirm remediation", "verify finding", "check if patched"

### Purpose

Verifies with precision whether a specific security finding has been remediated in the current codebase. Accepts a finding ID, title, or description and returns a verdict with code-level proof. Strictly single-finding scope — does not expand to report other observations.

### Verdict Taxonomy

- **REMEDIATED** — fix present and correct; no equivalent bypass in same component
- **PARTIALLY FIXED** — specific variant patched; underlying class still exploitable via different path/input
- **STILL PRESENT** — no material change; vulnerability exploitable as described
- **REGRESSED** — the fix was applied but subsequently removed or overwritten

### What It Verifies

- Vulnerable code location (file and line) from the original finding
- Current code at that location versus the vulnerable pattern
- All input paths and caller-supplied parameters in the same component
- Git history for intentional fix and any subsequent reverts

### Report Structure

- **Verdict block**: verdict, confidence (HIGH / MEDIUM / LOW)
- **Evidence section**: original finding details, current code quote, fix assessment table (5 checks)
- **Verdict rationale**: 2–3 sentences with specific code evidence
- **Residual Risk** (if not REMEDIATED): remaining attack surface and completion steps
- **Validation**: concrete test to confirm REMEDIATED status once remaining steps are complete

---

*All agents are read-only. They do not modify workspace files, install dependencies, stage changes, or create commits.*
