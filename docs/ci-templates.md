# <img src="media/logo.svg" alt="" width="28" height="31" align="top"> Reusable CI templates

Threatlint ships reusable CI building blocks so any repository can run its agents without copying
workflow files. Every template is **analysis-only**: it reads source, writes a Markdown report and
SARIF, optionally comments on the pull request, and can fail the build on a severity threshold. It
never commits, pushes, or edits source.

| Platform | File | Kind | Use when |
| --- | --- | --- | --- |
| GitHub Actions | [`.github/workflows/threatlint-reusable.yml`](../.github/workflows/threatlint-reusable.yml) | Reusable workflow (`workflow_call`) | You want one line per repository; each agent runs as its own matrix job |
| GitHub Actions | [`.github/actions/threatlint/action.yml`](../.github/actions/threatlint/action.yml) | Composite action | You want a Threatlint step inside an existing job |
| Azure Pipelines | [`azure-pipelines/templates/threatlint-job.yml`](../azure-pipelines/templates/threatlint-job.yml) | Job template | One job per agent, checkouts handled for you |
| Azure Pipelines | [`azure-pipelines/templates/threatlint-steps.yml`](../azure-pipelines/templates/threatlint-steps.yml) | Steps template | Embed Threatlint in an existing job |

Copy-ready callers: [GitHub](examples/github-caller.yml) · [Azure DevOps](examples/azure-caller.yml).

## GitHub Actions

### 60-second setup

1. Add `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY`) under **Settings → Secrets and variables → Actions**.
2. Create `.github/workflows/security.yml`:

```yaml
name: Security
on:
  pull_request:
permissions:
  contents: read
jobs:
  threatlint:
    permissions:
      contents: read
      pull-requests: write     # PR comment
      security-events: write   # SARIF upload
      id-token: write          # claude-code-action
    uses: InfoSec-Actions/threatlint/.github/workflows/threatlint-reusable.yml@<full-commit-sha>
    with:
      agents: appsec-code-reviewer,appsec-secrets-scanner
      threatlint-ref: <full-commit-sha>
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Pin `uses:` **and** `threatlint-ref` to the same 40-character commit SHA. The reusable workflow checks
Threatlint out a second time (into `.threatlint/`) to load the composite action, scripts, and the
canonical agent/skill definitions; `threatlint-ref` keeps both checkouts on the same revision.

### Composite action inside your own job

```yaml
steps:
  - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
    with: { fetch-depth: 0, persist-credentials: false }
  - uses: InfoSec-Actions/threatlint/.github/actions/threatlint@<full-commit-sha>
    with:
      agent: appsec-api-security-reviewer
      target: src/api
      fail-on-severity: high
      anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

Outputs: `report-path`, `sarif-path`, `mode`.

### Inputs

| Reusable workflow | Composite action | Default | Description |
| --- | --- | --- | --- |
| `agents` | `agent` | `appsec-code-reviewer` | Comma-separated agent IDs (workflow, max 20) or a single ID (action). Any agent in the [agent catalogue](agents.md). |
| `provider` | `provider` | `claude` | `claude` (agentic, reads the repo), `openai`, or `github-models` (prompt-based, uses `github.token`). |
| `model` | `model` | provider default (`claude-opus-5-5` for `claude`) | Model override, e.g. `claude-opus-5-5` or `gpt-4o`. |
| `target` | `target` | `''` | Component, path, or objective. Passed as scope, never as instructions. |
| — | `findings-file` | `''` | SARIF/JSON/Markdown evidence for `appsec-fp-reviewer` and specialist agents. |
| — | `base` / `head` | PR base/head, push `before`/`GITHUB_SHA`, else `HEAD~1` | Diff range for diff-scoped agents. |
| `fail-on-severity` | `fail-on-severity` | `high` | Gate threshold: `none`, `low`, `medium`, `high`, `critical`. |
| `gate-mode` | `gate-mode` | `warn` | `warn` annotates findings at or above the threshold and keeps the job green; `fail` fails the job. |
| `upload-sarif` | `upload-sarif` | `true` | Upload to GitHub Code Scanning (category `threatlint-<agent>`). |
| `comment-on-pr` | `comment-on-pr` | `true` | Post the executive summary on the pull request. |
| `python-version` | `python-version` | `3.12` | Python used by the bundled scripts. |
| `max-turns` | `max-turns` | `25` | Claude Code turn budget per agent. |
| `timeout-minutes` | — | `30` | Per-agent job timeout. |
| `runs-on` | — | `ubuntu-latest` | Runner label. |
| `threatlint-repository` / `threatlint-ref` | — | `InfoSec-Actions/threatlint` / `main` | Where to load Threatlint from (set this for forks/mirrors). |

### Secrets and permissions

| Secret | Needed for |
| --- | --- |
| `ANTHROPIC_API_KEY` | `provider: claude` |
| `OPENAI_API_KEY` | `provider: openai` |
| _(none)_ | `provider: github-models` uses the job's `github.token` |

A called workflow can never receive more permissions than its caller grants. Grant
`pull-requests: write` only if `comment-on-pr` is on, `security-events: write` only if
`upload-sarif` is on, and `id-token: write` for the Claude provider. Analysis jobs are skipped for
pull requests from forks so provider secrets are not exposed to untrusted code.

## Azure Pipelines

### Setup

1. Create a GitHub service connection that can read the Threatlint repository (or import
   Threatlint into Azure Repos and use `type: git`).
2. Add `ANTHROPIC_API_KEY` and/or `OPENAI_API_KEY` as **secret** pipeline variables.
3. For PR comments on Azure Repos, grant the project's build service **Contribute to pull requests**.

```yaml
resources:
  repositories:
    - repository: threatlint            # alias used by the job template
      type: github
      name: InfoSec-Actions/threatlint
      ref: refs/tags/<version>          # or a commit SHA
      endpoint: github-threatlint

jobs:
  - template: azure-pipelines/templates/threatlint-job.yml@threatlint
    parameters:
      agents: [appsec-code-reviewer, appsec-secrets-scanner]
      failOnSeverity: high
      anthropicApiKey: $(ANTHROPIC_API_KEY)
```

`threatlint-job.yml` creates one job per agent, checks out `self` to `$(Pipeline.Workspace)/s/source`
and Threatlint to `$(Pipeline.Workspace)/s/.threatlint`, then runs `threatlint-steps.yml`. If your
resource alias is not `threatlint`, set `threatlintRepository`.

### Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `agents` (job) / `agent` (steps) | `[appsec-code-reviewer]` / `appsec-code-reviewer` | Agent IDs to run. |
| `provider` | `claude` | `claude` runs the Claude Code CLI headlessly with read-only tools; `openai` / `github-models` use `appsec_api.py`. |
| `model` | `''` | Model override. |
| `target` | `''` | Scope passed to every agent. |
| `findingsFile` | `''` | Evidence file for triage/specialist agents. |
| `failOnSeverity` | `high` | Gate threshold: `none`, `low`, `medium`, `high`, `critical`. |
| `gateMode` | `warn` | `warn` logs warnings and marks the job **SucceededWithIssues**; `fail` fails the job. |
| `uploadSarif` | `true` | Publishes SARIF as the `CodeAnalysisLogs` artifact (SARIF SAST Scans Tab / Advanced Security). |
| `commentOnPr` | `true` | Creates an Azure Repos PR thread with the executive summary. Skipped for non-PR builds and GitHub-hosted repos. |
| `pythonVersion` | `3.12` | `UsePythonVersion@0` spec. |
| `maxTurns` | `25` | Claude turn budget. |
| `claudeCodeVersion` | pinned | Exact `@anthropic-ai/claude-code` version run through `npx`. |
| `anthropicApiKey` / `openaiApiKey` / `githubToken` | `''` | Provider credentials — pass secret variables, never literals. |
| `pool`, `timeoutInMinutes`, `dependsOn` (job only) | `ubuntu-latest`, `30`, `[]` | Job placement. |
| `threatlintPath`, `sourcePath` (steps only) | `$(Build.SourcesDirectory)/.threatlint`, `$(Build.SourcesDirectory)` | Where the two checkouts live when you embed the steps yourself. |

## Gating

The gate step runs [`gate_report.py`](../.github/scripts/gate_report.py) on findings at or above
`fail-on-severity` that are **CONFIRMED** or **PLAUSIBLE** (THEORETICAL findings never gate).
`none` disables the gate. What happens next depends on the gate mode:

| Mode | Findings at or above the threshold | No report produced | Job result |
| --- | --- | --- | --- |
| `warn` (default) | One `::warning::` (GitHub) or `##vso[task.logissue type=warning]` (Azure) per finding | Warning | Green / **SucceededWithIssues** |
| `fail` | One error annotation per finding | Error | Failed |

Start in `warn` so developers see findings on every PR without being blocked, then switch high-value
repositories to `fail` once the findings are trusted. The per-agent workflows read the same setting
from the `APPSEC_GATE_MODE` repository variable (GitHub) or the `gateMode` parameter (Azure).

| Threshold | Typical use |
| --- | --- |
| `critical` | Introduce Threatlint without disrupting merges |
| `high` | Recommended steady state for pull requests |
| `medium` | Regulated or high-value services |
| `none` | Scheduled deep reviews and report-only runs |

A pass is a statement about the scoped analysis, not a security approval; review the report and
its residual-risk section.

## Conversing with Threatlint on pull requests

Every Threatlint PR comment ends with an invitation to ask follow-up questions. Comment on the pull
request (or reply to a review comment) starting with `/threatlint`, or mention `@threatlint`:

```text
/threatlint why is CR-002 high?
/threatlint suggest a fix for the SQL finding
/threatlint is this new upload endpoint safe from path traversal?
@threatlint write a regression test for SG-001
```

Threatlint replies in the same conversation. It answers from four bounded sources: your question,
the earlier messages in that conversation, the PR metadata and diff (GitHub) or changed files at the
PR source commit (Azure DevOps), and the latest Threatlint report comment on the PR (found by its
hidden `<!-- threatlint:report -->` marker). Each reply is marked `<!-- threatlint:chat -->`, so it
never answers itself. The script is [`threatlint_chat.py`](../.github/scripts/threatlint_chat.py)
and uses only the Python standard library.

| Provider | Credential | Default model |
| --- | --- | --- |
| `claude` | `ANTHROPIC_API_KEY` | `claude-opus-5-5` (`THREATLINT_GENERAL_MODEL` overrides) |
| `openai` | `OPENAI_API_KEY` | `gpt-4o` |
| `github-models` | `GH_TOKEN` (the workflow token) | `openai/gpt-4o` |
| `lmstudio` | none (`LMSTUDIO_BASE_URL`, self-hosted agents only) | the loaded model |

### GitHub

Copy [`docs/examples/github-pr-chat-caller.yml`](examples/github-pr-chat-caller.yml) to
`.github/workflows/threatlint-chat.yml` and add the provider secret. Or copy
[`.github/workflows/threatlint-pr-chat.yml`](../.github/workflows/threatlint-pr-chat.yml) as is;
set the `THREATLINT_CHAT_PROVIDER` / `THREATLINT_CHAT_MODEL` repository variables to change the model.

- Triggers: `issue_comment` (pull requests only) and `pull_request_review_comment`, when the comment
  starts with `/threatlint` or mentions `@threatlint`.
- Only `OWNER`, `MEMBER`, and `COLLABORATOR` authors are answered. Bots are ignored.
- Permissions: `contents: read`, `pull-requests: write`, `issues: write`.
- A reply to a review comment goes into that review thread; otherwise a PR comment is added.

### Azure DevOps

Azure Pipelines has no comment trigger, so a service hook sends each new PR comment to an
**Incoming WebHook** pipeline resource:

1. **Project settings → Service connections → New → Incoming WebHook.** WebHook name and
   connection name: `threatlint-comments`. Set a secret so deliveries are HMAC-verified.
2. **Project settings → Service hooks → + → Web Hooks → "Pull request commented on"**, filtered to
   the repository. URL:
   `https://dev.azure.com/<org>/_apis/public/distributedtask/webhooks/threatlint-comments?api-version=6.0-preview`,
   with the same secret.
3. Create a pipeline from [`docs/examples/azure-pr-chat-caller.yml`](examples/azure-pr-chat-caller.yml)
   and add `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY`) as a secret variable.
4. **Repos → Security → "\<Project\> Build Service (\<org\>)" → Contribute to pull requests: Allow.**
   Replies are posted with `System.AccessToken` into the same thread as the question.
5. Optional: set `allowedAuthors` to restrict who can invoke Threatlint, because Azure service
   hooks do not report the commenter's repository role.

The template is [`azure-pipelines/templates/threatlint-pr-chat.yml`](../azure-pipelines/templates/threatlint-pr-chat.yml).
Comments by the build service, system comments, and Threatlint's own replies are ignored.

### Security model

- **Untrusted input stays data.** The question, conversation, PR description, diff, and report are
  wrapped in blocks with a random per-request tag. The model is told never to follow instructions
  inside them, and a forged closing tag cannot end a block early.
- **No PR code runs.** The workflows check out only Threatlint (GitHub: the base repository's default
  branch or the pinned Threatlint ref; Azure: the Threatlint repository). The diff and files are read
  through the REST API.
- **No injection through expressions.** Event text reaches the script through the event payload file
  (GitHub) or a JSON env variable (Azure), never through `${{ }}` inside a script body.
- **Bounded and redacted.** Diff, report, conversation, and reply sizes are capped. Replies are
  scanned for tokens, keys, and private keys, which are replaced with `[REDACTED]`.
- **Advisory only.** Threatlint never pushes, approves, or resolves threads. If the model call fails,
  it posts a short apology without any error details.

## Security notes

- Every caller value reaches shell through environment variables; no `${{ }}` interpolation is placed
  inside `run`/`bash` bodies (agent and model names are additionally restricted to plain tokens).
- Checkouts use `persist-credentials: false` / `persistCredentials: false`.
- Third-party GitHub actions are pinned to full commit SHAs.
- The Claude provider copies Threatlint's canonical agent and skill files into the workspace
  `.claude/` directory only when the repository does not already define them, so repo-local
  customizations win. These copies exist only on the ephemeral runner.
