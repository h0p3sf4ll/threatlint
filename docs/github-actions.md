# GitHub Actions

Put evidence beside a change, then decide what should block a merge. Start with
the [warn-mode, report-only caller](ci-templates.md#60-second-setup). It disables
PR comments and Code Scanning and needs only `contents: read` with the OpenAI
provider. Add publication permissions and blocking only after reviewing results.

For another repository, prefer [pinned reusable callers](ci-templates.md) over
copied workflows.

## Included Workflows

The two workflows below are the main entry points. Other
[`appsec-*.yml` workflows](../.github/workflows/) cover individual specialists and
scheduled analysis; [`appsec-auto-fix.yml`](#auto-fix-is-a-separate-write-path) is
a separate write path.

| Workflow | File | Trigger | Provider | Output |
| --- | --- | --- | --- | --- |
| AppSec PR Review | [.github/workflows/appsec-pr-review.yml](../.github/workflows/appsec-pr-review.yml) | Non-draft, same-repository PR | `APPSEC_PROVIDER` variable (default: `claude`) | Report artifact (30 days), PR summary, SARIF, qualifying issues |
| AppSec Threat Model | [.github/workflows/appsec-threat-model.yml](../.github/workflows/appsec-threat-model.yml) | Manual `workflow_dispatch` | Dispatch input (default: `claude`) | Report artifact (90 days), SARIF, optional issues |

Their agents propose changes rather than edit source. **Publication is not read-only:**
these workflows upload artifacts/SARIF, the PR workflow posts a comment, and both
can create issues and labels. They request write permissions for those actions.
The generic [composite action](ci-templates.md) gives you finer opt-in control.

## Supported Providers

| Provider | How it authenticates | Capability |
| --- | --- | --- |
| `claude` | `ANTHROPIC_API_KEY` repository secret (or `CLAUDE_CODE_OAUTH_TOKEN`) | Full agentic loop — reads files, runs git commands, walks the codebase interactively |
| `openai` | `OPENAI_API_KEY` repository secret | Prompt-based — diff and key context files are bundled into the request |
| `github-models` | `GITHUB_TOKEN` (automatic — no extra secret needed) | Same prompt-based approach; uses the GitHub Models API endpoint |

A larger tool surface is not a coverage guarantee. Review provider data handling
and allowed tools before enabling analysis.

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

**Push-triggered scans:** secrets, CI/CD, and IaC workflows use the standalone
`claude-code-action/base-action`. The PR/issue wrapper does not accept `push`
events; changing its version or supplying a prompt does not fix that mismatch.
These scans need the Anthropic API key, not a Claude GitHub App installation.
Their credential preflight fails explicitly if the secret is unavailable.
For an organization secret, grant access to this repository. A successful test
or desktop build is not evidence that a model-backed scan ran.

**For `openai`:**
1. Create an API key at [platform.openai.com/api-keys](https://platform.openai.com/api-keys).
2. Add `OPENAI_API_KEY` as a repository or organization secret.

**For `github-models`:**
No additional provider secret is required. The workflow uses `GITHUB_TOKEN`;
confirm that your organization and token can access GitHub Models.

### 2. Configure the provider (PR review only)

Under **Settings → Secrets and variables → Actions → Variables**, set
`APPSEC_PROVIDER` to `claude` (default), `openai`, or `github-models`.
`APPSEC_MIN_ISSUE_SEVERITY` controls issue filing: `HIGH` by default; valid values
are `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW`.

### 3. Keep the workflow's support files together

Prefer a pinned reusable caller instead of copying workflows. If you maintain a
copied per-agent workflow, carry its matching scripts and agent/skill definitions
from the **same revision**. Copying only `appsec_api.py` is insufficient: it imports
sibling prompt/helper modules.

```bash
mkdir -p /path/to/your-repo/.github/scripts
cp .github/scripts/*.py /path/to/your-repo/.github/scripts/
```

For Claude, also retain the required `.claude/agents/` and `.claude/skills/`
definitions and applicable project instructions. Publication uses
`post_pr_comment.py`, `to_sarif.py`, `gate_report.py`, and `create_issues.py`;
the API provider uses `appsec_api.py` and its sibling modules.

## Enable the Workflows

1. Review triggers, source data sent to providers, scripts, agent definitions, and token permissions.
2. Before enabling automatic PR runs, remove unwanted issue/comment/SARIF steps and their write permissions. The shipped PR workflow enables them.
3. Merge the reviewed workflow/support files to the default branch and add provider secrets.
4. Confirm Actions are enabled, then run a scoped manual threat model with `create_issues: false`.

## GitHub Issues for Findings

`create_issues.py` files one issue per qualifying report finding:

**What gets filed:**
- Severity at or above the configured threshold (default: HIGH)
- THEORETICAL skipped unless `--include-theoretical` is passed. The script does
  not reject UNKNOWN confidence, so check report fields before trusting issue counts.
- No existing open issue with the same finding ID in its title

It creates missing `security` and `severity:<level>` labels
(`critical`, `high`, `medium`, or `low`).
The body includes the full finding block and metadata for the report date,
severity/confidence, triggering PR (if supplied), and workflow run.

**Deduplication is ID-based, not root-cause-based.** An open issue with `[CR-001]`
in its title suppresses another `CR-001`, even if a later report uses that ID for a
different bug. Review skips; do not treat issue counts as finding coverage.

## Run an Initial Threat Model

1. Open **Actions → AppSec Threat Model → Run workflow**; select branch and provider.
2. Set `target`, for example `src/auth` or `payments webhook`. Blank means autonomous
   discovery and evidence-supported scope selection.
3. Set **create issues** to `false` for the first run (default: `true`); choose a
   minimum severity when enabling filing.
4. Download the Markdown report from the run's **Artifacts** section.

## Automatic Pull-Request Review

**AppSec PR Review** runs on non-draft PR open, reopen, synchronize, and ready-for-review
events. It publishes the full report artifact, comments a summary, and automatically
files qualifying issues unless you remove that step.

Fork PRs are skipped. Same-repository changes are still untrusted input; review
allowed agent tools and runner isolation rather than treating this guard as a sandbox.

## Warn vs fail

The per-agent workflows read two repository variables
(**Settings → Secrets and variables → Actions → Variables**):

| Variable | Default | Meaning |
| --- | --- | --- |
| `APPSEC_GATE_SEVERITY` | `CRITICAL` | CONFIRMED/PLAUSIBLE findings at or above this level hit the gate. Empty/unset falls back to `CRITICAL`. |
| `APPSEC_GATE_MODE` | `warn` | `warn` adds a `::warning::` annotation per finding and keeps the check green. `fail` fails the check so branch protection can block the merge. |

For example, `HIGH` + `warn` annotates a HIGH/PLAUSIBLE finding without failing the
gate. Change mode to `fail` and make the job required in branch protection to block.
Other setup or provider failures can fail a warn-mode run.

The two workflows above explicitly warn and skip the gate when the report is
missing—even in `fail` mode. This differs from the generic templates, which pass
missing reports to `gate_report.py` and fail in fail mode. An empty
`APPSEC_GATE_SEVERITY` does **not** disable gating because the workflow expression
uses `|| 'CRITICAL'`; remove/condition the gate step if maintaining a report-only
copy, or use the generic template's `fail-on-severity: none`.

## Conversing on pull requests

Comment `/threatlint <question>` on a pull request, for example `/threatlint why is CR-002 high?`, and
[`threatlint-pr-chat.yml`](../.github/workflows/threatlint-pr-chat.yml) replies in the same
conversation using the configured model, the PR diff, and the latest Threatlint report comment.
Only owners, members, and collaborators can invoke it, and PR code is never checked out. See
[Conversing with Threatlint on pull requests](ci-templates.md#conversing-with-threatlint-on-pull-requests).

## Security Controls

The included workflows use these safeguards:

- `pull_request`, not `pull_request_target`, for PR review.
- A same-repository branch guard before the PR job runs.
- `contents: read`; PR review also requests `pull-requests: write` for comments,
  `issues: write` for filing, and `security-events: write` for SARIF.
- `id-token: write`, required by the Claude Code Action's GitHub App authentication flow.
- Full SHA pins for `actions/checkout` and `anthropics/claude-code-action`
  (not every action in these per-agent workflows is SHA-pinned).
- Job timeouts and per-PR concurrency cancellation.
- Agent instructions prohibit source modification; the allowed Bash tool is not
  itself a read-only execution sandbox.
- Fork PR skipping to prevent secret exposure.

The official Claude GitHub App has broader permissions than these workflow jobs. Review its permission request with your organization before installation. Organizations that need a narrower integration can follow the official Claude Code Action guidance for a custom GitHub App.

## Customize Safely

### Switch Provider for PR Review

Set the `APPSEC_PROVIDER` repository variable to `openai` or `github-models` without editing the workflow file.

### Change the Provider Model

For Claude, set `THREATLINT_SCAN_MODEL` (default: `claude-opus-5-5`).
For API providers, add `--model <model-id>` to `appsec_api.py`; defaults are
`gpt-4o` (OpenAI) and `openai/gpt-4o` (GitHub Models). Confirm model access
with your provider before changing it.

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

Remove the **Create GitHub issues for findings** step and its `issues: write`
permission for reports without issue filing. For manual threat models, choose
`create_issues: false`; that input does not narrow the workflow's declared permissions.

### Auto-fix is a separate write path

[`appsec-auto-fix.yml`](../.github/workflows/appsec-auto-fix.yml) enables editing,
committing, pushing a fix branch, and opening a PR. It is not a read-only reviewer.
Do not install it as part of the minimal analysis setup. Review its dispatch and
`/appsec-fix` comment triggers, enforce caller authorization, approve its write
credentials, and require human review of any resulting PR. A request to “suggest
a fix” in [PR chat](ci-templates.md#conversing-with-threatlint-on-pull-requests)
does not enable this workflow.

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
| Full report is not visible on the pull request | PR review posts a summary; download the full Markdown artifact from the Actions run. Manual threat models do not post PR summaries. |
| No issues created after analysis | Check that the report file was written. The **Create GitHub issues for findings** step logs the count of parsed findings and skipped reasons. |
| Issues not labeled correctly | Confirm `GH_TOKEN` / `GITHUB_TOKEN` has `issues: write`. The script auto-creates labels if they are absent. |
| Agent does not find project instructions | Confirm `.claude/agents/` and `CLAUDE.md` are present on the branch checked out by the workflow. |
| Report misses relevant context | Check the scoped inputs and snapshot limits; narrow the question or use Claude for repository traversal. No provider guarantees full coverage. |
| Run takes too long or costs too much | Narrow the workflow trigger, reduce `--max-turns` in the Claude step, or give the manual workflow a precise target. |

## References

- [Claude Code GitHub Actions](https://code.claude.com/docs/en/github-actions)
- [Claude Code Action repository](https://github.com/anthropics/claude-code-action)
- [GitHub Models documentation](https://docs.github.com/en/github-models)
- [OpenAI API reference](https://platform.openai.com/docs/api-reference)
- [GitHub Actions security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
