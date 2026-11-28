---
title: Choose a specialist
description: Choose from 23 security specialists by the question, source evidence, and outcome you need.
---

# Choose a specialist

Choose the specialist that answers your question. The 23 roles use different review instructions and evidence; they are not 23 independently trained models. Start with one role, then add another when its input or decision is needed.

## Choose by outcome

| Your task | Start with |
| --- | --- |
| Understand a system or feature | [Threat modeler](#appsec-threat-modeler) |
| Review a code change | [Code reviewer](#appsec-code-reviewer) |
| Assess a scanner finding | [Finding triager](#appsec-fp-reviewer) |
| Check a proposed repair | [Verify fix](#appsec-verify-fix) |
| Plan regression coverage | [Security test planner](#appsec-security-test-planner) |
| Compare earlier and current findings | [Threat delta](#appsec-threat-delta) |
| Check \*-Shell exposures: \*-2Shell (React2Shell, Next.js, PHP2Shell, WP2Shell, Node2Shell) and \*-4Shell (Log4Shell, Spring4Shell, Text4Shell, Java4Shell) | [\*-Shell detector](#appsec-xshell-detector) |

<a name="define-the-assignment-before-choosing-more-agents"></a>

## Describe the assignment {#define-the-assignment-before-choosing-more-agents}

Provide the repository or finding, the relevant revision, and the decision you need. For example: “Review invoice downloads for access between customer accounts; identify the ownership check and propose denial and allowed-case tests.”

In **Review code**, use **Add a specialist** or choose a workflow. Select a model before running. See [Use the Workbench](workbench.md) and [Model providers](model-providers.md).

Analysis is read-only. Suggested changes, tests, and tracker actions need separate approval and execution. Treat missing evidence and context truncation as limits, not as a clean result.

## System design and attack paths

<a name="appsec-threat-modeler"></a>

### Threat modeler {#appsec-threat-modeler}

Provide source, configuration, a component or system question, and optional design documents. Get a system model, trust boundaries, prioritized threats, and design/source disagreements. Without a target, it discovers and prioritizes components. See [Threat modeling](threat-modeling.md).

<a name="appsec-attack-tree"></a>

### Attack tree {#appsec-attack-tree}

Provide an attacker goal, relevant assets, source, and available threat findings. Get an AND/OR tree of prerequisites, defensive controls, and candidate validation steps. Use it to investigate one path rather than repeat a broad system review.

<a name="appsec-red-team"></a>

### Red team {#appsec-red-team}

Provide the authorized system scope, an attacker objective, and supporting source or findings. Get adversarial scenarios and detection hypotheses. This specialist plans exercises; it does not execute attacks against the application.

## Code and domain reviews

<a name="appsec-code-reviewer"></a>

### Code reviewer {#appsec-code-reviewer}

Provide a working-tree diff, commit range, or specific change with its surrounding code. Get security regressions, proposed corrections, and a scoped merge recommendation. Use the threat modeler when your question concerns the whole system rather than a change.

<a name="appsec-secure-codegen-reviewer"></a>

### Secure code generation reviewer {#appsec-secure-codegen-reviewer}

Provide new or AI-generated code and the project's relevant helpers and conventions. Get proposed secure rewrites, safer defaults, and reusable guardrails. Applying the rewrite belongs to your development workflow.

<a name="appsec-api-security-reviewer"></a>

### API security reviewer {#appsec-api-security-reviewer}

Provide routes, request/response contracts, handlers, and data-access code. Get endpoint-specific abuse paths, role and tenant checks, and contract-aware regression assertions. Use the auth reviewer for identity issuance, sessions, or recovery.

<a name="appsec-auth-reviewer"></a>

### Authentication reviewer {#appsec-auth-reviewer}

Provide login, token, session, recovery, and authorization-policy code. Get identity-lifecycle findings, bypass analysis, and proposed fixes. Include the roles and resource ownership rules the implementation is expected to enforce.

<a name="appsec-business-logic-reviewer"></a>

### Business logic reviewer {#appsec-business-logic-reviewer}

Provide a workflow, its rules, state transitions, jobs, and webhooks. Get source-backed race, replay, and invalid-transition scenarios. State the business requirement when the source alone cannot establish whether an action is allowed.

<a name="appsec-client-security-reviewer"></a>

### Client security reviewer {#appsec-client-security-reviewer}

Provide browser, mobile, or Electron entry points and privileged interfaces. Get findings about rendering, client storage, navigation, and trust boundaries. Server-enforced access decisions may also need API or authentication review.

<a name="appsec-crypto-reviewer"></a>

### Cryptography reviewer {#appsec-crypto-reviewer}

Provide the security purpose, cryptographic calls, and key, nonce, or certificate lifecycle. Get implementation-specific misuse findings and compatible corrections. Supply deployment evidence when the question depends on actual TLS or key configuration.

<a name="appsec-ai-security-reviewer"></a>

### AI security reviewer {#appsec-ai-security-reviewer}

Provide model calls, retrieved content, tools, memory, and output destinations. Get paths where untrusted instructions or data could influence a privileged action. Include the permissions of the tool or operation whose behavior matters.

<a name="appsec-privacy-reviewer"></a>

### Privacy reviewer {#appsec-privacy-reviewer}

Provide data flows, collection, storage, retention, logging, and recipient details. Get unnecessary or insufficiently protected data handling and proposed minimization steps. Legal interpretation and organizational policy decisions remain with the responsible owners.

## Dependencies, secrets, and delivery

<a name="appsec-dependency-auditor"></a>

### Dependency auditor {#appsec-dependency-auditor}

Provide manifests, resolved lockfiles, package provenance, and available advisory evidence. Get applicability and reachability assessments plus a compatible upgrade sequence. A package version alone does not establish exploitability in your application.

<a name="appsec-secrets-scanner"></a>

### Secrets scanner {#appsec-secrets-scanner}

Provide source, configuration, and authorized history in scope. Get redacted exposure locations and a containment or rotation plan. The specialist does not test credentials or rotate them; use a separately authorized operational process.

<a name="appsec-xshell-detector"></a>

### \*-Shell detector {#appsec-xshell-detector}

Provide a repository, branch, or deterministic detector output. Get every package root with a \*-2Shell or \*-4Shell exposure: a vulnerable React Server Components or Next.js version (React2Shell, CVE-2025-55182 and CVE-2025-66478, plus the follow-up DoS and source-exposure CVEs), or a vulnerable Log4j (Log4Shell, CVE-2021-44228 and follow-ups), Spring Framework (Spring4Shell, CVE-2022-22965) or Commons Text (Text4Shell, CVE-2022-42889) from Maven, Gradle or vendored jars. You also get whether the deployment exposes it (App Router, WAR on a servlet container, StringSubstitutor interpolation), the smallest same-line upgrade, log-hunting guidance, and whether secrets should be rotated. Run `threatlint detect-xshell fleet` (alias `detect-4shell`) to scan many repositories and branches across your GitHub and Azure DevOps connections. The specialist never probes live hosts or installs packages. It also covers the 2026 additions: PHP2Shell (CVE-2026-109618/109619, PHP runtime), WP2Shell (CVE-2026-63030/60137, WordPress core), Node2Shell (CVE-2026-111497, Node.js and PyPI Brotli), Java4Shell (CVE-2026-114938, JDK runtime) and the RSC follow-up CVE-2026-126187, using runtime pins such as Dockerfile `FROM` tags, `.nvmrc`, `.tool-versions` and `wp-includes/version.php`. Impacted release lines with no fix are still reported as "No fix on this line" with the supported line to move to. Run it with `threatlint detect-xshell` (aliases `detect-2shell`, `detect-4shell`).

<a name="appsec-iac-reviewer"></a>

### Infrastructure reviewer {#appsec-iac-reviewer}

Provide Terraform, Kubernetes, container, or cloud configuration and the expected deployment boundary. Get resource-specific exposure and privilege findings, with proposed rollout and rollback checks. Identify any differences between declarations and deployed state.

<a name="appsec-cicd-auditor"></a>

### CI/CD auditor {#appsec-cicd-auditor}

Provide workflow triggers, token permissions, runner trust, artifacts, and deployment gates. Get build and release trust failures plus proposed pipeline changes. Configured checks are assessed separately from evidence that those checks actually ran.

## Findings and remediation

<a name="appsec-fp-reviewer"></a>

### Finding triager {#appsec-fp-reviewer}

Provide the original scanner findings, identifiers, rule provenance, matching source, and validation evidence. Get a Finding Review with dispositions, decision basis, proposed corrections, and applicable tuning proposals. A false-positive verdict alone does not suppress a rule or close a ticket.

<a name="appsec-verify-fix"></a>

### Verify fix {#appsec-verify-fix}

Provide one original finding and the current code or relevant history. Get an assessment of the root-cause repair and equivalent bypasses. The report distinguishes source-level remediation from behavior that still needs an executed test.

<a name="appsec-threat-delta"></a>

### Threat delta {#appsec-threat-delta}

Provide a prior report, current source, and relevant change history. Get original finding IDs mapped to resolved, partial, still-present, regressed, or new risks. Unalignable findings remain an explicit comparison limit.

<a name="appsec-compliance-checker"></a>

### Compliance checker {#appsec-compliance-checker}

Provide applicable framework scope, technical findings, and implementation evidence. Get a control-gap matrix, remediation priorities, and the evidence needed for closure. This is technical mapping, not certification or an audit opinion.

## Runtime evidence and testing

<a name="appsec-runtime-reviewer"></a>

### Runtime reviewer {#appsec-runtime-reviewer}

Provide redacted, authorized captures with the target revision, identity, role, action, and time, plus matching source. Get observed behavior correlated with implementation. Missing identity or capture provenance limits what a response can establish.

<a name="appsec-security-test-planner"></a>

### Security test planner {#appsec-security-test-planner}

Provide findings or security requirements, fixtures, and the permitted test environment. Get test cases, setup requirements, and observable pass/fail outcomes. Proposed cases remain unrun until a separate test workflow executes them.

## Use the result

Read the scope, evidence, proposed action, and verification status before acting. Pass the original finding ID and revision to a follow-up specialist so the next review can trace the same issue.

Use [Reports and exports](reports.md) for report interpretation, [Review orchestration](review-orchestration.md) for multi-specialist work, or the [Quickstart](learning.md) for a first run.
