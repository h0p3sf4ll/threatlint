# GitHub Actions

`threatlint` provides two GitHub Actions workflows for automated security analysis. Both support three AI providers — Claude, OpenAI, and GitHub Models (Copilot-aligned) — and automatically open GitHub issues for qualifying findings.

## Included Workflows

| Workflow | File | Trigger | Provider | Output |
| --- | --- | --- | --- | --- |
| AppSec PR Review | [.github/workflows/appsec-pr-review.yml](../.github/workflows/appsec-pr-review.yml) | Non-draft pull requests from branches in the same repository | Controlled by the `APPSEC_PROVIDER` repository variable (default: `claude`) | Workflow run log + GitHub issues |
| AppSec Threat Model | [.github/workflows/appsec-threat-model.yml](../.github/workflows/appsec-threat-model.yml) | Manual `workflow_dispatch` run | Selected per-run via dispatch input (default: `claude`) | Workflow run log + GitHub issues |

The workflows are analysis-only. They never commit, push, or modify source files. When findings meet the configured severity threshold, they are opened as GitHub issues with `security` and `severity:*` labels.

## Supported Providers

| Provider | How it authenticates | Capability |
| --- | --- | --- |
| `claude` | `ANTHROPIC_API_KEY` repository secret (or `CLAUDE_CODE_OAUTH_TOKEN`) | Full agentic loop — reads files, runs git commands, walks the codebase interactively |
| `openai` | `OPENAI_API_KEY` repository secret | Prompt-based — diff and key context files are bundled into the request |
| `github-models` | `GITHUB_TOKEN` (automatic — no extra secret needed) | Same prompt-based approach; uses the GitHub Models API endpoint |

The `claude` provider is the most thorough — it runs an interactive agent that can follow call chains, read arbitrary files, and inspect configuration. The `openai` and `github-models` providers receive the diff (for PR review) or a curated file snapshot (for threat modeling) as static context; they cannot browse the codebase interactively.

## Before Enabling

You need repository administrator access to complete this setup.

### 1. Install required services

**For `claude` (default):**
1. Install the [Claude GitHub App](https://github.com/apps/claude) on the repository or organization.
2. Create an Anthropic API key in the [Claude Console](https://console.anthropic.com), or generate a subscription token with `claude setup-token`.
3. Add the secret to GitHub under **Settings** > **Secrets and variables** > **Actions**:

   | Authentication method | Secret name |
   | --- | --- |
   | Anthropic API key | `ANTHROPIC_API_KEY` |
   | Claude subscription token | `CLAUDE_CODE_OAUTH_TOKEN` |

   When using `CLAUDE_CODE_OAUTH_TOKEN`, replace the `anthropic_api_key` input with `claude_code_oauth_token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}` in both workflow files.

**For `openai`:**
1. Create an API key at [platform.openai.com/api-keys](https://platform.openai.com/api-keys).
2. Add `OPENAI_API_KEY` as a repository or organization secret.

**For `github-models`:**
No additional secret is required. The workflow uses the built-in `GITHUB_TOKEN`.

### 2. Configure the provider (PR review only)

The PR review workflow reads the provider from a repository variable:

1. Open **Settings** > **Secrets and variables** > **Actions** > **Variables**.
2. Create `APPSEC_PROVIDER` and set it to `claude`, `openai`, or `github-models`.

Leave the variable unset to use the default (`claude`). To control the minimum finding severity that triggers issue creation, create `APPSEC_MIN_ISSUE_SEVERITY` (default: `HIGH`; valid values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).

### 3. Ensure the Python scripts are present

The `create_issues.py` and `appsec_api.py` scripts must be committed to the repository at `.github/scripts/`. They are included in this repository. Copy them when installing into a target repo:

```bash
mkdir -p /path/to/your-repo/.github/scripts
cp .github/scripts/appsec_api.py /path/to/your-repo/.github/scripts/
cp .github/scripts/create_issues.py /path/to/your-repo/.github/scripts/
```

## Enable the Workflows

1. Review and merge the workflow files and the `.github/scripts/` files into the repository's default branch.
2. Add the required authentication secret(s).
3. Confirm that Actions are enabled for the repository.
4. Open the **Actions** tab. You should see **AppSec PR Review** and **AppSec Threat Model**.

## GitHub Issues for Findings

After each analysis, `create_issues.py` reads the report, identifies findings at or above the minimum severity, and creates one GitHub issue per qualifying finding that does not already have an open issue.

**What gets filed:**
- Severity at or above the configured threshold (default: HIGH)
- Confidence is CONFIRMED or PLAUSIBLE (THEORETICAL skipped by default)
- No existing open issue with the same finding ID in its title

**Labels applied to each issue:**
- `security` — applied to all findings
- `severity:critical`, `severity:high`, `severity:medium`, or `severity:low` — applied by severity

Both labels are created automatically if they do not already exist. The issue body includes the full finding block from the report — preconditions, attack steps, evidence references, Remediation Guidance, and Test Case (code review) or Validation (threat model) — plus a metadata table that links back to the triggering PR and workflow run.

**Deduplication:** the script searches for open issues whose title contains the finding ID (e.g., `[CR-001]`). If one is found, the finding is skipped. This prevents duplicate issues when the same finding appears across multiple PR updates or re-runs.

## Run an Initial Threat Model

1. Open the repository's **Actions** tab.
2. Select **AppSec Threat Model**.
3. Select **Run workflow** and choose the branch to inspect.
4. Choose a **provider** (default: `claude`).
5. Optionally enter a **target** such as `src/auth`, `payments webhook`, or `Terraform production infrastructure`.
6. Choose whether to **create issues** for findings (default: true) and set a **minimum severity**.
7. Leave `target` blank to make the agent inventory the repository and select an evidence-supported initial scope.
8. Open the completed run and expand the analysis step to read the Markdown report in the log.

## Automatic Pull-Request Review

**AppSec PR Review** runs when a non-draft pull request is opened, reopened, synchronized, or marked ready for review. The provider is set by the `APPSEC_PROVIDER` repository variable (default: `claude`).

The report appears in the workflow run log. Any findings at or above `APPSEC_MIN_ISSUE_SEVERITY` (default: `HIGH`) that are not already tracked by an open issue are filed automatically.

The workflow skips pull requests from forks. GitHub does not expose repository secrets to fork-triggered `pull_request` workflows, and running an AI agent with credentials against untrusted fork code is an unnecessary risk. Review fork contributions manually.

## Security Controls

The included workflows use these safeguards:

- `pull_request`, not `pull_request_target`, for PR review.
- A same-repository branch guard before the PR job runs.
- Read-only `contents` and `pull-requests` permissions; `issues: write` scoped to issue creation only.
- `id-token: write`, required by the Claude Code Action's GitHub App authentication flow.
- Immutable SHA pins for `actions/checkout` and `anthropics/claude-code-action`.
- Job timeouts and per-PR concurrency cancellation.
- Read-only Claude agent tools and project-level agent guardrails.
- Fork PR skipping to prevent secret exposure.

The official Claude GitHub App has broader permissions than these workflow jobs. Review its permission request with your organization before installation. Organizations that need a narrower integration can follow the official Claude Code Action guidance for a custom GitHub App.

## Customize Safely

### Switch Provider for PR Review

Set the `APPSEC_PROVIDER` repository variable to `openai` or `github-models` without editing the workflow file.

### Change the Provider Model

Pass `--model <model-id>` to `appsec_api.py` in the workflow step to override the default:
- OpenAI: `gpt-4o`, `gpt-4o-mini`, `o3`, etc.
- GitHub Models: `openai/gpt-4o`, `Meta-Llama-3.1-405B-Instruct`, etc.

### Change Triggering Paths

To run the PR review only when risk-bearing files change, add a `paths` filter under `on.pull_request` in [appsec-pr-review.yml](../.github/workflows/appsec-pr-review.yml):

```yaml
on:
  pull_request:
    paths:
      - "src/**"
      - "infra/**"
      - ".github/workflows/**"
```

### Suppress Issue Creation for PR Review

Remove or comment out the **Create GitHub issues for findings** step in the workflow if you want reports without automatic issue filing.

### Update Action Pins

The `# v6` and `# v1` comments identify the release each SHA was resolved from. When upgrading, resolve the intended release tag to a full commit SHA, update the `uses:` line, and review the upstream release notes before merging.

## Troubleshooting

| Symptom | Likely cause and action |
| --- | --- |
| Workflow is absent from the Actions tab | Confirm the workflow file is on the default branch and Actions are enabled. |
| Authentication failure (Claude) | Confirm `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` exists, is valid, and is accessible to the workflow. |
| Authentication failure (OpenAI) | Confirm `OPENAI_API_KEY` is set as a repository or organization secret. |
| GitHub Models API returns 401 | Confirm `GITHUB_TOKEN` has access to GitHub Models in your plan. |
| Claude Code Action cannot authenticate to GitHub | Confirm the Claude GitHub App is installed and `id-token: write` remains granted. |
| PR review did not run | Check whether the PR is draft, from a fork, or did not match a configured trigger. |
| Report is not visible on the pull request | Reports write to the workflow run log, not a PR comment. Open the run in the Actions tab. |
| No issues created after analysis | Check that the report file was written. The **Create GitHub issues for findings** step logs the count of parsed findings and skipped reasons. |
| Issues not labeled correctly | Confirm `GH_TOKEN` / `GITHUB_TOKEN` has `issues: write`. The script auto-creates labels if they are absent. |
| Agent does not find project instructions | Confirm `.claude/agents/` and `CLAUDE.md` are present on the branch checked out by the workflow. |
| OpenAI/GitHub Models report is less detailed | These providers receive static diff context rather than an interactive agent. For maximum depth, use `claude`. |
| Run takes too long or costs too much | Narrow the workflow trigger, reduce `--max-turns` in the Claude step, or give the manual workflow a precise target. |

## References

- [Claude Code GitHub Actions](https://code.claude.com/docs/en/github-actions)
- [Claude Code Action repository](https://github.com/anthropics/claude-code-action)
- [GitHub Models documentation](https://docs.github.com/en/github-models)
- [OpenAI API reference](https://platform.openai.com/docs/api-reference)
- [GitHub Actions security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
