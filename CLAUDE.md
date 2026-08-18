# threatlint

This project provides read-only application-security subagents for Claude Code.

## Routing

- Delegate application threat-modeling requests to `appsec-threat-modeler`.
- Delegate security reviews of pull requests, diffs, and risky configuration changes to `appsec-code-reviewer`.
- Delegate dependency and supply chain security audits to `appsec-dependency-auditor`.
- Delegate secrets and credential scanning requests to `appsec-secrets-scanner`.
- Delegate Infrastructure as Code security reviews (Terraform, Kubernetes, Dockerfile, CloudFormation) to `appsec-iac-reviewer`.
- Delegate CI/CD pipeline security audits (GitHub Actions, Jenkins, GitLab CI, CircleCI) to `appsec-cicd-auditor`.
- Delegate API security reviews (REST, GraphQL, gRPC, WebSocket) to `appsec-api-security-reviewer`.
- Delegate authentication and authorization reviews (OAuth, JWT, RBAC, session management, MFA) to `appsec-auth-reviewer`.
- Delegate false positive triage and Semgrep rule tuning to `appsec-fp-reviewer`.
- Delegate compliance mapping (OWASP ASVS, PCI-DSS v4, HIPAA, SOC 2, ISO 27001, NIST CSF, CIS Controls) to `appsec-compliance-checker`.
- Delegate formal attack tree construction with bypass analysis and leaf node ranking to `appsec-attack-tree`.
- Delegate adversarial red-team scenario generation with kill chains and purple-team test cases to `appsec-red-team`.
- Delegate comparison of a prior security report to the current repository state (New/Resolved/Regressed/Unchanged) to `appsec-threat-delta`.
- Delegate verification of whether a specific finding has been remediated to `appsec-verify-fix`.
- When a threat-modeling request has no target or application context, use `appsec-threat-modeler` anyway. It must autonomously discover the repository, select an evidence-supported initial scope, and explain that choice.

## Boundaries

- All AppSec subagents are analysis-only. They must not modify the workspace, install dependencies, stage files, or create commits.
- The threat-modeler uses repository evidence and labels assumptions, unknowns, and residual risk explicitly.
- The code reviewer treats the current working-tree diff as its default scope when the user supplies no change set.
