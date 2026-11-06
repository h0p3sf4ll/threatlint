# <img src="media/logo.svg" alt="" width="28" height="31" align="top"> Agent Reference

Choose the decision you need to make, then ask the matching agent for evidence.
“Can another tenant download this invoice?” gives a reviewer a sharper target than
“check security.”

For the architecture and data flow diagrams, a one-page sheet per agent, and a summary of
every skill, see [Threatlint architecture](architecture.md).

## Choose by outcome

| I need to… | Agent / reference |
| --- | --- |
| Find the highest-risk component or model a feature | [Threat modeler](#appsec-threat-modeler) |
| Decide whether a change is safe to merge | [Code reviewer](#appsec-code-reviewer) |
| Review AI-generated or newly written code | [Secure codegen reviewer](#appsec-secure-codegen-reviewer) |
| Assess packages, credentials, infrastructure, or pipelines | [Dependencies](#appsec-dependency-auditor) · [Secrets](#appsec-secrets-scanner) · [IaC](#appsec-iac-reviewer) · [CI/CD](#appsec-cicd-auditor) |
| Trace endpoint access or identity decisions | [API reviewer](#appsec-api-security-reviewer) · [Auth reviewer](#appsec-auth-reviewer) |
| Check workflows, clients, cryptography, or AI boundaries | [Business logic](#appsec-business-logic-reviewer) · [Client](#appsec-client-security-reviewer) · [Crypto](#appsec-crypto-reviewer) · [AI](#appsec-ai-security-reviewer) |
| Trace sensitive data or map technical controls | [Privacy](#appsec-privacy-reviewer) · [Compliance](#appsec-compliance-checker) |
| Decide whether scanner findings need action | [Finding triager](#appsec-fp-reviewer) |
| Turn a threat into attack paths or defensive exercises | [Attack tree](#appsec-attack-tree) · [Red team](#appsec-red-team) |
| Compare reports or check one claimed fix | [Threat delta](#appsec-threat-delta) · [Verify fix](#appsec-verify-fix) |
| Interpret supplied runtime captures or plan regression tests | [Runtime reviewer](#appsec-runtime-reviewer) · [Security test planner](#appsec-security-test-planner) |

## Define the assignment before choosing more agents

A specialist is a scoped review contract, not a permanently running worker. In Workbench and
CLI API runs, it is a model invocation with a role, required skills, evidence, and restricted
tools. The same provider can execute several specialists. Different prompts do not guarantee
independent reasoning or eliminate correlated errors.

Use these boundaries to avoid asking several agents to repeat the same audit:

| Specialist | Minimum useful input and concrete decision | Stop or hand off when… |
| --- | --- | --- |
| Code reviewer | Exact diff/range plus surrounding source → identify security regressions and recommend a scoped merge decision | No diff exists, or the question is whole-system design; use the threat modeler |
| Secure codegen reviewer | New/generated code plus project helpers → propose a secure rewrite and reusable guardrail | The task is to apply or run the rewrite; that belongs to an authorized development workflow |
| API reviewer | Routes, schemas, authorization middleware → determine which role can perform which operation on whose object | Identity issuance/recovery is the root cause; involve the auth reviewer |
| Auth reviewer | Login/session/token/recovery and policy code → assess identity and authorization lifecycles | A domain state transition breaks an entitlement despite correct identity checks; use business logic |
| Business logic reviewer | A workflow, invariants, state transitions, jobs/webhooks → assess races, replay, and invalid transitions | There is no source-backed invariant; state the missing requirement rather than invent a business rule |
| Client reviewer | Browser/mobile/Electron entry points and privileged bridges → assess client trust boundaries | The defect is enforced wholly on the server; route it to API/auth review |
| Crypto reviewer | Security purpose, primitive use, key/nonce lifecycle → propose a compatible cryptographic correction | Keys, certificates, or deployed TLS settings cannot be inspected; keep those runtime facts unknown |
| AI security reviewer | Model calls, retrieval, tools, memory, output sinks → locate an attacker-controlled path across an authority boundary | Only suspicious prompt wording is visible; instruction influence alone is not proof of security impact |
| Privacy reviewer | Data collection, storage, retention, logs, recipients → identify unnecessary or unprotected data flows | Legal basis or organizational policy needs a decision; refer it to privacy/legal owners |
| Dependency auditor | Manifests/lockfiles and available advisory evidence → prioritize applicable dependency risk and compatible upgrades | Advisory applicability or the resolved version is unknown; do not invent a CVE or safe version |
| Secrets scanner | Source/config/history in scope → report redacted exposure and a rotation sequence | The next step would use a credential; testing or rotation needs a separate authorized workflow |
| IaC reviewer | Terraform/Kubernetes/container/cloud configuration → assess resource-specific exposure and privileges | Live deployed state differs or is unavailable; report the drift/verification gap |
| CI/CD auditor | Workflow triggers, permissions, runners, artifacts, deployment steps → identify build/release trust failures | Application code needs a deeper analysis; keep pipeline authority separate from application findings |
| Compliance checker | Technical findings and scope evidence → map verified gaps to applicable controls | Certification, legal interpretation, or policy attestation is required; the report cannot provide those |
| Attack tree | A target asset or prior threat → model AND/OR prerequisites and defensive cuts | Leaves lack source evidence; show the gap rather than a fictional attack chain |
| Red team | Source and optional prior findings → propose bounded adversarial scenarios and detection tests | A request would execute an attack; this specialist plans only |
| Threat delta | Prior report, current source, relevant history → preserve original IDs and classify risk change | A prior finding cannot be aligned to current evidence; mark the assessment limit rather than assume resolution |
| Verify fix | One original finding and current code/history → assess root-cause repair and equivalent bypasses | Proof depends on execution or unavailable state; distinguish source remediation from runtime validation |
| Runtime reviewer | Redacted authorized captures, identity/role/time provenance, source → explain observed behavior and source correlation | Capture provenance, effective role, or session validity is unknown; a status code alone is not an identity proof |
| Security test planner | Findings or invariants, fixtures, permitted environment → produce executable-in-principle cases and observable oracles | Authorization or setup is missing; mark BLOCKED. Proposed cases remain NOT RUN |

Threat modeling defines the system and prioritizes attack paths. Findings triage starts from a
scanner claim and determines its disposition. Neither is a substitute for every specialist
above, and selecting all agents is not automatically a better review.

### Make handoffs reviewable

Pass the original finding ID, source revision, scope, evidence locations, assumptions, severity,
confidence, proposed action, and **actual** validation status. Include the upstream report when
it is available, but remember that context budgets may omit or truncate material. These are
reporting requirements, not a claim that every runtime serializes one universal JSON envelope.

A downstream agent should be able to answer: “Which input supports this conclusion, and what
must I check myself?” Repeating an earlier claim is not independent verification.

**Definition of done for any specialist:** the requested decision is answered; coverage and
excluded areas are stated; every material finding cites inspected evidence; advisory changes
and unrun tests are labeled; remaining decisions have a concrete owner or next step. If the
available evidence cannot support a finding, a qualified negative result is useful work.

## Start with one question

In a client with Threatlint commands installed:

```text
/threat-model src/payments — trace webhook input to payment-state changes
/security-review — review the staged and unstaged changes
/fp-review findings.sarif — verify reachability before proposing a suppression
/verify-fix CR-001 — check the original evidence at src/invoices.py:84
```

Give the agent the target, relevant finding/report, and decision you need. With no
target, the threat modeler discovers and ranks candidate components; the code
reviewer defaults to the working-tree diff. See [installation and clients](../README.md)
and [CI callers](ci-templates.md) for other entry points.

## Shared contract

- **Analysis, not execution.** Agents do not edit source, install dependencies, stage
  changes, or commit. Report persistence belongs to the host. Resolution and auto-fix
  workflows are separate, explicitly authorized write paths—not permissions granted
  by asking a reviewer for a fix.
- **Evidence before conclusions.** Material claims need inspected `file:line` evidence.
  Findings distinguish CONFIRMED, PLAUSIBLE, and THEORETICAL confidence; unknowns
  remain explicit. A clean scoped report is not proof that the application is secure.
- **Advice that engineers can use.** Reports include proposed fixes, implementation
  notes, owner/effort, regression assertions, acceptance criteria, and limitations.
  Proposed changes are **NOT APPLIED**; proposed tests are **NOT RUN** without actual
  execution evidence. A false-positive verdict does not authorize suppression.
- **No live validation by implication.** Runtime review analyzes supplied redacted
  evidence. Test planning does not run tests, log in, bypass SSO/MFA, or authorize a
  runtime engine.

The [agent definitions](../src/threatlint/data/agents/) specify full protocols and
report formats; the [agent-skill registry](../src/threatlint/data/agent-skills.json)
assigns required shared and specialist skills. The [execution contracts](../src/threatlint/data/agent-contracts.json)
declare inputs, outputs, boundaries, and source/upstream evidence mode for the owned Python and
Workbench runners. Installers include the contracts in generated Claude, Copilot, Codex, and
local-model bundles; reinstall to refresh an existing installation. Previously copied Markdown
is not updated automatically, and native clients still enforce their own permissions. The
summaries below are a selection guide, not a replacement for those contracts. See [the workbench](workbench.md)
for evidence handoffs.

Most reports separate an executive decision from technical findings. The technical
section preserves finding IDs, severity/confidence, source evidence, attack path,
impact, advisory mitigation, and proposed validation. Specialist formats below
add inventories, verdicts, or test plans; their canonical definitions remain authoritative.

---

## appsec-threat-modeler

> **Design inputs:** give it diagrams, design documents, OpenAPI specs, or whiteboard images (Workbench **Add supporting docs**, or `threatlint run threat-model --design PATH`). It uses them to learn the intended architecture, verifies each claim against the code, and reports design drift. See [Design inputs](workbench.md#design-inputs).

**Finding prefix**: `TM-NNN`  
**Slash command**: `/threat-model`, `/threat-model-deep`, `/threat-model-local`, `/threat-model-deep-local`  
**GitHub Copilot Chat**: `@AppSec Threat Modeler`  
**AGENTS.md routing**: "threat model", "analyze security risks", "review security posture"

### Purpose

Find the attack paths worth fixing first. The agent models inspected source,
configuration, and infrastructure. Without a target, it inventories and ranks
components by exposure, privilege, sensitive data, and blast radius, then explains
its selected scope.

**Scope:** source, API/CLI/queue/event/file/WebSocket entry points, identity and
trust boundaries, IaC/containers, CI/CD, dependencies, secrets, encryption, and
external integrations.

### Frameworks Applied

STRIDE, OWASP Top 10 (2021), CWE, applicable MITRE ATT&CK, DREAD (/10), and
evidence-supported compliance exposure.

**Personas:** external/unauthenticated, authenticated user, privileged insider,
supply-chain, infrastructure/cloud, and nation-state/APT.

### Report Structure

**Tier 1 — Executive Summary:** risk posture, severity/confidence counts,
Critical/High actions, crown jewels (asset/classification/impact/threat/control),
supported compliance exposure, and one recommended next step.

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

Make a merge decision from the change—not a generic checklist. The reviewer traces
security-relevant changed code and adjacent controls, then recommends BLOCK,
MERGE WITH ACTION, or MERGE.

### Diff Targeting

| Target | Behavior |
|--------|----------|
| No argument | Working-tree diff (staged + unstaged) |
| `main..feature` | Branch comparison |
| `abc123..def456` | Commit range |
| `42` | Pull request via `gh pr diff` |
| `-- path/` | Path-scoped diff |

**Scope:** changed routes, middleware, auth, validation/deserialization/queries,
external calls, file/shell I/O, secrets, dependencies, CI/CD, containers, IaC, and
removed or weakened controls. Adjacent callers and defenses provide context.

**Mappings:** OWASP Top 10 (2021), CWE, MITRE ATT&CK, and evidence-supported
compliance controls.

### Report Structure

**Tier 1 — Executive Summary:** change risk (CRITICAL / HIGH / MEDIUM / LOW /
CLEAN), finding counts, detected tech stack, Critical/High issues, and merge
recommendation (BLOCK / MERGE WITH ACTION / MERGE).

**Tier 2 — Technical Review**
- Review Scope with numbered assumptions
- Per-finding blocks: Severity, Confidence, OWASP/CWE/ATT&CK, evidence from diff, exploit path, Remediation Guidance with before/after snippets, Test Case
- Security-Positive Changes (required)
- Residual Risk

**Required report disclosures:** Secrets Introduced (“None detected.” if absent)
and New Dependencies (“None added.” if absent).

---

## appsec-dependency-auditor

**Finding prefix**: `DA-NNN`  
**Slash command**: `/dependency-audit`, `/dependency-audit-local`  
**GitHub Copilot Chat**: `@AppSec Dependency Auditor`  
**Workflow**: `appsec-dependency-audit.yml` (triggers on manifest/lockfile changes)

### Purpose

Decide which dependency changes reduce real supply-chain risk. The reviewer
checks manifests, lockfiles, hooks, and registry configuration; advisory
applicability needs version and reachability evidence, not a package-name match.

### Ecosystems Supported

npm / yarn, PyPI (pip/poetry/pipenv), Go modules, Cargo (Rust), Maven/Gradle (Java), RubyGems, Composer (PHP)

**Review focus:** CVE version ranges and applicability; confusion/typosquatting;
install hooks (`postinstall`, `prepare`, `install`, Python hooks); maintenance
signals; floating versions, lockfile freshness/hashes; and `.npmrc`/`pip.conf`
registry configuration. Unverified advisory or maintenance data stays uncertain.

### Report Structure

**Tier 1 — Executive Summary:** supply-chain risk, finding counts, top issues,
rotation/update priorities, and recommended audit commands.

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

Locate credential exposure and plan revocation or rotation. The reviewer inspects
source, configuration, history hints, and error-output patterns; it does not test
whether credentials work or print complete secrets.

### Secret Pattern Examples

These are inspection cues, not an exhaustive detector or a guarantee of current
provider formats. Context and entropy help distinguish credentials from fixtures.

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
| Generic high-entropy | entropy and assignment context |
| DB connection string | credentials in URI format |

**Scope:** source, CI/CD, `.env*`, configuration, Terraform state/Kubernetes
Secrets, build scripts/Makefiles, and git history hints.

### Report Structure

**Tier 1 — Executive Summary:** exposure level, finding counts, Critical/High
issues, and rotation, ignore-file, or secret-manager actions.

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

Find configuration paths that expose infrastructure or widen a compromised
identity's reach. Recommendations target the affected resource and its blast radius.

### IaC Tools Supported

Terraform, Kubernetes (manifests and Helm), Dockerfile and docker-compose, AWS CloudFormation and CDK, Pulumi, Ansible (playbooks)

### Review Focus

- **Terraform/CloudFormation:** IAM actions/resources/trust, public network
  exposure (`0.0.0.0/0`, `::/0`), S3/RDS encryption, KMS rotation, and secrets.
- **Kubernetes:** pod privileges and host access, RBAC including `system:masters`,
  network policies, image tags/digests, and plaintext secret placement.
- **Containers:** base-image provenance, `USER`, remote `ADD`, copied credentials,
  and build-stage contents retained in the final image.

### Report Structure

**Tier 1 — Executive Summary:** infrastructure risk, finding counts, and top issues.

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

Find where pipeline inputs can reach credentials, runners, or release artifacts.
The reviewer inspects GitHub Actions, GitLab CI, CircleCI, and Jenkins configuration.

### Review Focus

- **Injection:** untrusted `github.head_ref`/`base_ref`, PR/issue titles and
  bodies, comment/review bodies, dispatch inputs, and `client_payload` in `run:`.
- **Workflow trust:** `pull_request_target` plus PR-head checkout, token
  permissions/inherited defaults, action SHA pins, `continue-on-error`, and
  unguarded `if: always()` steps.
- **Execution and release boundaries:** fork secrets/write tokens, shared or
  persistent runners, unsigned downstream artifacts, and attestations.

### Report Structure

**Tier 1 — Executive Summary:** pipeline risk, finding counts, and top issues.

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

Trace who can reach sensitive data through REST, GraphQL, gRPC, and WebSocket
handlers. For example, “Does `GET /invoices/:id` bind the query to the caller's
tenant?” focuses the review on enforcement, not the route name.

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

Also traces mass assignment, response overexposure, coercion/schema validation,
downstream injection, and GraphQL introspection/depth/complexity in context.

### Report Structure

**Tier 1 — Executive Summary:** API risk, finding counts, and top issues.

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

Check whether identity and privilege survive the whole request path. The reviewer
traces authentication, session, and authorization decisions through to data access.

### Coverage Areas

- **OAuth/OIDC:** state, public-client PKCE, exact redirect validation, scope,
  and ID-token signatures/claims.
- **JWT:** algorithm confusion (`none`, RS256→HS256), `iss`/`aud`/`exp`/`nbf`/`sub`,
  signing-key strength/rotation, storage, and revocation.
- **Sessions/CSRF:** entropy, privilege-change rotation, logout/password-change
  revocation, secure cookie flags/expiry, synchronizer or double-submit tokens,
  SameSite defense-in-depth, and header-based controls.
- **MFA/recovery:** TOTP windows, single-use backup codes, reset/account-recovery
  and trusted-device bypasses.
- **RBAC/ABAC:** auth-before-authz ordering, object/tenant query scope, and
  role-parameter escalation.
- **Passwords and abuse:** nonreversible hashing/KDF parameters, safe comparisons,
  login/reset/OTP throttling, enumeration, lockout, and backoff.

### Report Structure

**Tier 1 — Executive Summary:** auth risk, finding counts, and top issues.

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
**GitHub Copilot Chat**: `@AppSec Finding Triager`  
**AGENTS.md routing**: "triage findings", "false positive", "semgrep tuning"

### Purpose

Produces a professionally written **Finding Review** from SARIF 2.1.0, Semgrep JSON, Threatlint Markdown, or pasted findings. The reviewer separates binary TRUE POSITIVE and FALSE POSITIVE verdicts from severity/confidence, proposes concrete fixes, and evaluates scanner-tuning risk independently. The reviewer does not apply proposals; the authorized executor validates and applies eligible rule tuning.

### Required Skills

The reviewer loads evidence analysis, actionable reporting, finding triage, Semgrep
tuning, and runtime validation. Required skills for every agent are assigned in
[the registry](../src/threatlint/data/agent-skills.json).

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
- **Conservative true positives**: when FP cannot be proven beyond reasonable doubt, remain open with actual confidence, missing evidence, an owner, and a resolution plan. This classification does not assert verified exploitation.
- **Tier 3 — Engineering Action Plan**: suppression impact, systemic root causes, remediation roadmap, acceptance matrix, limitations, and unresolved questions. No blanket suppressions or unsupported zero-false-negative promises.

---

## appsec-compliance-checker

**Finding prefix**: `CC-NNN`  
**Slash command**: `/compliance-check`  
**GitHub Copilot Chat**: `@AppSec Compliance Checker`  
**AGENTS.md routing**: "compliance", "ASVS", "PCI-DSS", "HIPAA", "SOC 2", "ISO 27001", "NIST CSF"

### Purpose

Turn technical findings into control-gap work, not a certification claim. The
reviewer maps evidence to applicable requirements and flags scope or policy
decisions that need organizational confirmation.

### What It Reviews

- Prior findings from threat model, code review, or other agents (accepted via chain context)
- Repository evidence for framework scope detection (payment code, health data, multi-tenancy, IaC, policies)
- Per-finding control mapping with gap type: Missing / Partial / Met
- Technical remediation roadmap; policy and audit evidence remain separate

### Frameworks Applied

- **OWASP ASVS 4.0** — always applicable for web applications
- **PCI-DSS v4**, **HIPAA**, **SOC 2 Type II**, **ISO 27001:2022**, and
  **NIST CSF 2.0** — assess relevance from payment, health-data, SaaS,
  policy/asset-register, infrastructure, or government-context evidence.
  A payment SDK or medical term alone does not establish regulatory scope.
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

Identify which defensive change breaks an attack path. Use this after a threat
model identifies the primary asset: the agent builds an evidence-backed AND/OR
tree, examines defense bypasses, ranks leaves, and proposes purple-team cases.

### Node Types

- **OR** — attacker needs to succeed at ONE child (any path works)
- **AND** — attacker needs to succeed at ALL children (all must be overcome)
- **LEAF** — atomic attack step with direct code evidence
- **DEFENSE** — existing control that must be bypassed

### Frameworks Applied

- Evidence-grounded difficulty and impact ranking; the canonical protocol uses
  a CVSS-like ranking, not a formal CVSS v3.1 score.

### Report Structure

**Tier 1 — Overview**
- Root goal, selection rationale, path/defense/bypass counts, and critical path

**Tier 2 — Full Attack Tree**
- Mermaid `graph TD` tree with OR/AND/LEAF/DEFENSE nodes and branch narrative
- Keep diagrams to 4–5 levels; expand deeper subtrees separately

**Tier 3 — Leaf Node Analysis**
- Rank by difficulty (TRIVIAL / LOW / MEDIUM / HIGH / EXPERT), impact,
  precondition, and evidence; detail the top three leaves and mitigations

**Tier 4 — Defense Bypass Analysis**
- Per defense: protected asset, bypass difficulty/evidence/feasibility, and
  explicitly reasoned BLOCKED paths

**Tier 5 — Purple-Team Test Cases**
- Supported confirmed/high-probability paths, proposed steps, detection signals,
  and remediation validation; tests remain NOT RUN

---

## appsec-red-team

**Finding prefix**: `RT-NNN`  
**Slash command**: `/red-team`, `/red-team-local`  
**GitHub Copilot Chat**: `@AppSec Red Team`  
**AGENTS.md routing**: "red team", "adversarial scenarios", "kill chains", "attacker simulation"

### Purpose

Explore how five attacker profiles could pursue source-supported paths. Each
scenario includes an ATT&CK-mapped chain, indicators, detection gaps, and a proposed
purple-team case. Unsupported kill-chain phases stay out; no attacks are executed.

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

See whether risk improved since the last report. The agent aligns prior findings
with current source and history, classifies each result, and identifies new
source-supported attack surfaces.

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

Decide whether one finding can be closed. Supply its ID, title or description,
original evidence, and attack path. The reviewer checks current code, equivalent
bypasses, and history without expanding into an unrelated audit.

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

For execution or publication choices, see [reusable CI templates](ci-templates.md)
and [GitHub workflows](github-actions.md). Neither a proposed fix nor a passing
severity gate grants permission to apply changes.
