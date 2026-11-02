# Threatlint for Azure Pipelines

See security findings before making them a build requirement. Start with one
analysis agent in **warn** mode, download its report, and triage the evidence.
Comments, work items, blocking, and source fixes are separate choices.

## Generic templates (recommended)

| Template | Use it to… |
| --- | --- |
| [`templates/threatlint-job.yml`](templates/threatlint-job.yml) | Create one job per agent, including both repository checkouts |
| [`templates/threatlint-steps.yml`](templates/threatlint-steps.yml) | Run one agent inside an existing job with your own checkout paths |

These templates publish reports and propose fixes; they do not commit or push
source changes. See the [full parameter reference](../docs/ci-templates.md#azure-pipelines)
and [complete caller example](../docs/examples/azure-caller.yml).

## Quick start

1. Create a GitHub service connection that can read Threatlint.
2. Add `ANTHROPIC_API_KEY` as a **secret** pipeline variable.
3. Add this to your host pipeline, replacing the resource ref and connection:

```yaml
resources:
  repositories:
    - repository: threatlint
      type: github
      name: InfoSec-Actions/threatlint
      ref: <reviewed-commit-sha>
      endpoint: <your-github-service-connection>

jobs:
  - template: azure-pipelines/templates/threatlint-job.yml@threatlint
    parameters:
      agents: [appsec-code-reviewer]
      anthropicApiKey: $(ANTHROPIC_API_KEY)
      gateMode: warn
      commentOnPr: false
      uploadSarif: false
```

The job checks out your source at `$(Pipeline.Workspace)/s/source` and Threatlint
at `$(Pipeline.Workspace)/s/.threatlint`. Download the Markdown pipeline artifact
after the run. Configure your host's triggers/build-validation policy for the
repository provider; importing a template does not enable PR validation.

## Gating

The generic templates default to `failOnSeverity: high` and `gateMode: warn`.
A HIGH/PLAUSIBLE finding warns and marks the gate **SucceededWithIssues**; it does
not fail it. THEORETICAL findings remain report-only. Setup/provider errors can
still fail a warn-mode job.

After triaging results, set `gateMode: fail` and make the job required by branch
policy to block on qualifying findings. `failOnSeverity: none` disables the gate.
The generic gate warns on a missing report in warn mode and fails in fail mode;
a passing gate is not proof of complete coverage.

## Opt into publication

- **PR comments:** set `commentOnPr: true` and grant the project's build service
  **Contribute to pull requests**. Comments use `System.AccessToken` and only
  support Azure Repos PR builds.
- **SARIF:** set `uploadSarif: true` to publish `CodeAnalysisLogs`; viewing it
  needs an appropriate SARIF viewer or Advanced Security configuration.
- **GitHub Models:** set `provider: github-models` and pass a GitHub credential
  as `githubToken`. `System.AccessToken` is an Azure DevOps token, not a GitHub token.

Comments and SARIF default to **true** in the generic templates; the starter
explicitly turns them off.

## Existing per-agent templates

Files such as [`pr-review.yml`](pr-review.yml) remain available for existing callers.
Their parameters differ from the generic templates:

| Per-agent parameter | Default | Generic equivalent / purpose |
| --- | --- | --- |
| `gateSeverity` | `CRITICAL` | `failOnSeverity` defaults to `high`; per-agent empty string disables gating |
| `gateMode` | `warn` | Same warn/fail choice |
| `createWorkItems` | `false` | No generic equivalent; explicitly enable work-item creation |
| `minIssueSeverity` | `HIGH` | Work-item threshold, independent of gating |
| `githubToken` | `$(System.AccessToken)` | Generic default is empty; override with a real GitHub token for GitHub Models |

Analysis templates accept `provider` (`claude`, `openai`, `github-models`),
`model`, and provider credentials (`anthropicApiKey`, `openaiApiKey`, `githubToken`).
Check the chosen YAML for its additional inputs; these are not auto-fix parameters.

## PR conversations

Ask `/threatlint why is CR-002 high?` to discuss a report without applying a fix.
Setup requires an Incoming WebHook/service hook and PR-comment permission:
[chat setup and author restrictions](../docs/ci-templates.md#azure-devops) ·
[steps template](templates/threatlint-pr-chat.yml) ·
[caller example](../docs/examples/azure-pr-chat-caller.yml).

## Auto-fix

[`auto-fix.yml`](auto-fix.yml) is **write-enabled**: it saves the model response
to `CHANGES.md`, stages changes, commits and pushes a branch, and opens a PR.
The current template does not apply the response as source patches; a generated
PR is not proof of remediation. Review its inputs/credentials separately,
authorize writes explicitly, and require human review. Keep it out of the
minimal report-only setup.
