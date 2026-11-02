# <img src="media/logo.svg" alt="" width="28" height="31" align="top"> Reusable CI templates

Review evidence before blocking merges. Start with one agent in **warn** mode,
then opt into comments, Code Scanning, or blocking. These generic analysis
templates publish reports, not source commits.
[Auto-fix is separate](github-actions.md#auto-fix-is-a-separate-write-path).

| Platform | File | Kind | Use when |
| --- | --- | --- | --- |
| GitHub Actions | [`.github/workflows/threatlint-reusable.yml`](../.github/workflows/threatlint-reusable.yml) | Reusable workflow (`workflow_call`) | One matrix job per agent; accepts the workflow's fixed write-permission set |
| GitHub Actions | [`.github/actions/threatlint/action.yml`](../.github/actions/threatlint/action.yml) | Composite action | Control job permissions and embed one agent in a job |
| Azure Pipelines | [`azure-pipelines/templates/threatlint-job.yml`](../azure-pipelines/templates/threatlint-job.yml) | Job template | One job per agent, checkouts handled for you |
| Azure Pipelines | [`azure-pipelines/templates/threatlint-steps.yml`](../azure-pipelines/templates/threatlint-steps.yml) | Steps template | Embed Threatlint in an existing job |

Copy-ready callers: [GitHub](examples/github-caller.yml) · [Azure DevOps](examples/azure-caller.yml).

## GitHub Actions

### 60-second setup

1. Add `OPENAI_API_KEY` under **Settings → Secrets and variables → Actions**.
2. Create `.github/workflows/security.yml`:

```yaml
name: Security
on:
  pull_request:
permissions:
  contents: read
jobs:
  threatlint:
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with: { fetch-depth: 0, persist-credentials: false }
      - uses: InfoSec-Actions/threatlint/.github/actions/threatlint@<full-commit-sha>
        with:
          provider: openai
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          gate-mode: warn
          comment-on-pr: 'false'
          upload-sarif: 'false'
```

Replace `<full-commit-sha>` with a reviewed 40-character Threatlint commit SHA.
The default agent is `appsec-code-reviewer`, and the default threshold is `high`.
Download the Markdown artifact from the completed run. Warn mode keeps **findings**
from failing the severity gate; setup, authentication, and analysis errors can
still fail the job.

### Composite action inside your own job

Use the step above in an existing job. Outputs are `report-path`, `sarif-path`,
and `mode`. To use Claude instead, set `provider: claude`, pass
`anthropic-api-key`, and grant `id-token: write` for the Claude Code Action's
authentication flow. Review the [GitHub setup prerequisites](github-actions.md#before-enabling).

### Opt into publication and multiple agents

For the composite action, enable each feature deliberately:

| Feature | Input | Additional job permission |
| --- | --- | --- |
| PR summary comment | `comment-on-pr: 'true'` | `pull-requests: write` |
| GitHub Code Scanning | `upload-sarif: 'true'` | `security-events: write` |
| Claude provider | `provider: claude` + API secret | `id-token: write` |

Code Scanning must be available for the repository. Generic templates do **not**
create issues; use the [per-agent workflows](github-actions.md) for issue filing.

The reusable workflow creates one job per agent, but **currently declares all three
write permissions unconditionally**. Its caller must grant them even with publication
disabled. Choose the composite action for narrower permissions.

```yaml
jobs:
  threatlint:
    permissions:
      contents: read
      pull-requests: write
      security-events: write
      id-token: write
    uses: InfoSec-Actions/threatlint/.github/workflows/threatlint-reusable.yml@<full-commit-sha>
    with:
      agents: appsec-code-reviewer,appsec-secrets-scanner
      threatlint-ref: <full-commit-sha>
      gate-mode: warn
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Pin `uses:` and `threatlint-ref` to the **same SHA**. The second checkout, at
`.threatlint/`, supplies the action, scripts, and canonical agent/skill definitions.

### Inputs

| Reusable workflow | Composite action | Default | Description |
| --- | --- | --- | --- |
| `agents` | `agent` | `appsec-code-reviewer` | Comma-separated agent IDs (workflow, max 20) or a single ID (action). Any agent in the [agent catalogue](agents.md). |
| `provider` | `provider` | `claude` | `claude` (agentic, reads the repo), `openai`, or `github-models` (prompt-based, uses `github.token`). |
| `model` | `model` | provider default (`claude-opus-5-5` for `claude`) | Model override, e.g. `claude-opus-5-5` or `gpt-4o`. |
| `target` | `target` | `''` | Component, path, or objective; intended as analysis scope, not overriding instructions. |
| — | `findings-file` | `''` | SARIF/JSON/Markdown evidence for `appsec-fp-reviewer` and specialist agents. |
| — | `base` / `head` | PR base/head; push `before`/`GITHUB_SHA`; otherwise `HEAD~1`/`GITHUB_SHA` | Diff range; base falls back to `HEAD` if no parent exists. |
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

The reusable workflow skips fork PR analysis. For the composite, add the
same-repository guard shown in the quick start; it is not built into the action.

## Azure Pipelines

### Setup

Use the [warn-mode Azure quick start](../azure-pipelines/README.md#quick-start)
or [complete caller](examples/azure-caller.yml). Pin the repository resource to a
reviewed revision, pass provider keys as secret variables, and explicitly disable
`commentOnPr`/`uploadSarif` for the first run. For an Azure Repos mirror, use
`type: git` instead of `type: github`.

`threatlint-job.yml` creates one job per agent, checks out `self` to `$(Pipeline.Workspace)/s/source`
and Threatlint to `$(Pipeline.Workspace)/s/.threatlint`, then runs `threatlint-steps.yml`. If your
resource alias is not `threatlint`, set `threatlintRepository`.

### Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `agents` (job) / `agent` (steps) | `[appsec-code-reviewer]` / `appsec-code-reviewer` | Agent IDs to run. |
| `provider` | `claude` | `claude` runs the headless CLI with analysis-only agent instructions; `openai` / `github-models` use `appsec_api.py`. |
| `model` | `''` | Model override. |
| `target` | `''` | Scope passed to every agent. |
| `findingsFile` | `''` | Evidence file for triage/specialist agents. |
| `failOnSeverity` | `high` | Gate threshold: `none`, `low`, `medium`, `high`, `critical`. |
| `gateMode` | `warn` | On a gate hit, `warn` logs warnings and marks **SucceededWithIssues**; `fail` fails the job. |
| `uploadSarif` | `true` | Publishes SARIF as the `CodeAnalysisLogs` artifact (SARIF SAST Scans Tab / Advanced Security). |
| `commentOnPr` | `true` | Creates an Azure Repos PR thread with the executive summary. Skipped for non-PR builds and GitHub-hosted repos. |
| `pythonVersion` | `3.12` | `UsePythonVersion@0` spec. |
| `maxTurns` | `25` | Claude turn budget. |
| `claudeCodeVersion` | `2.1.302` | Exact `@anthropic-ai/claude-code` version run through `npx`. |
| `anthropicApiKey` / `openaiApiKey` / `githubToken` | `''` | Provider credentials — pass secret variables, never literals. |
| `pool`, `timeoutInMinutes`, `dependsOn` (job only) | `ubuntu-latest`, `30`, `[]` | Job placement. |
| `threatlintRepository` (job only) | `threatlint` | Repository resource alias to check out. |
| `threatlintPath`, `sourcePath` (steps only) | `$(Build.SourcesDirectory)/.threatlint`, `$(Build.SourcesDirectory)` | Where the two checkouts live when you embed the steps yourself. |

To publish Azure Repos comments, set `commentOnPr: true` and grant the project's
build service **Contribute to pull requests**; the template uses `System.AccessToken`.
Set `uploadSarif: true` to publish `CodeAnalysisLogs`; viewing it requires the
appropriate SARIF viewer or Advanced Security setup. These options default to
**true** in the generic templates, so the starter explicitly disables them.
For GitHub Models, pass a GitHub token in `githubToken`, not an Azure DevOps token.

## Gating

The gate step runs [`gate_report.py`](../.github/scripts/gate_report.py) on findings at or above
`fail-on-severity` that are **CONFIRMED** or **PLAUSIBLE** (the templates exclude THEORETICAL).
`none` disables the gate. What happens next depends on the gate mode:

| Mode | Findings at or above the threshold | No report produced | Job result |
| --- | --- | --- | --- |
| `warn` (default) | One `::warning::` (GitHub) or `##vso[task.logissue type=warning]` (Azure) per finding | Warning | Green / **SucceededWithIssues** |
| `fail` | One error annotation per finding | Error | Failed |

For example, a **HIGH / PLAUSIBLE** finding at a `high` threshold warns in `warn`
mode and fails in `fail` mode. A **HIGH / THEORETICAL** finding stays in the report
but does not hit this gate. A report that parses no eligible findings also passes;
inspect report completeness before making the check required.

After triaging representative PRs, set `gate-mode: fail` (GitHub) or `gateMode: fail`
(Azure) and configure branch protection/build policy to require that job. Per-agent
GitHub workflows use `APPSEC_GATE_MODE`; see their [different defaults and
missing-report behavior](github-actions.md#warn-vs-fail).

A pass is not security approval. Choose a threshold that fits your review process,
then read the report and its residual risks.

## Conversing with Threatlint on pull requests

Report comments invite follow-up questions. Comment on the pull
request (or reply to a review comment) starting with `/threatlint`, or mention `@threatlint`:

```text
/threatlint why is CR-002 high?
/threatlint suggest a fix for the SQL finding
@threatlint propose a regression assertion for SG-001
```

Replies use bounded question/thread history, PR metadata, diff (GitHub) or changed
files at the source commit (Azure), and the latest report comment. Report markers
start with `<!-- threatlint:report`; replies carry `<!-- threatlint:chat -->` to
avoid self-replies. [`threatlint_chat.py`](../.github/scripts/threatlint_chat.py)
and its sibling `_chat_*.py` modules use the standard library. Replies advise;
they do not apply patches or execute tests.

| Provider | Credential | Default model |
| --- | --- | --- |
| `claude` | `ANTHROPIC_API_KEY` | `claude-opus-5-5` (`THREATLINT_GENERAL_MODEL` overrides) |
| `openai` | `OPENAI_API_KEY` | `gpt-4o` |
| `github-models` | `GH_TOKEN` (the workflow token) | `openai/gpt-4o` |
| `lmstudio` | none (`LMSTUDIO_BASE_URL`, self-hosted agents only) | the loaded model |

### GitHub

Copy [the caller example](examples/github-pr-chat-caller.yml) to
`.github/workflows/threatlint-chat.yml`; pin `uses:` and `threatlint-ref` to the same
reviewed SHA and add the provider secret. If copying
[`threatlint-pr-chat.yml`](../.github/workflows/threatlint-pr-chat.yml) instead,
include `threatlint_chat.py` and every sibling `_chat_*.py` module in
`.github/scripts/` on the default branch. That copied workflow reads
`THREATLINT_CHAT_PROVIDER` / `THREATLINT_CHAT_MODEL` repository variables.

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
5. Set `allowedAuthors` to the permitted commenters' comma-separated `uniqueName`
   values when access should be restricted. Its default is empty: anyone who can
   comment can invoke the chat. Azure hooks do not supply a repository-role check.

The template is [`azure-pipelines/templates/threatlint-pr-chat.yml`](../azure-pipelines/templates/threatlint-pr-chat.yml).
Comments by the build service, system comments, and Threatlint's own replies are ignored.

### Security model

- **Untrusted input is delimited.** Question, conversation, description, diff, and report
  use random per-request tags and instructions to treat them as data. This reduces
  delimiter spoofing; it does not guarantee resistance to model prompt injection.
- **No PR code runs.** The workflows check out only Threatlint (GitHub: the base repository's default
  branch or the pinned Threatlint ref; Azure: the Threatlint repository). The diff and files are read
  through the REST API.
- **No injection through expressions.** Event text reaches the script through the event payload file
  (GitHub) or a JSON env variable (Azure), never through `${{ }}` inside a script body.
- **Bounded, with pattern-based redaction.** Context and replies have size caps.
  Recognized token/key patterns are replaced with redaction markers; unknown secret
  formats may remain. Do not send sensitive material on the assumption it will be removed.
- **Advisory only.** Threatlint never pushes, approves, or resolves threads. If the model call fails,
  it posts a short apology without any error details.

## Security notes

- In the generic analysis templates, caller inputs reach shell steps through
  environment variables; agent/model tokens are validated. This is not a claim
  about every legacy or auto-fix workflow.
- Generic analysis checkouts disable credential persistence. Their third-party
  GitHub actions use full commit SHA pins.
- The Claude provider copies Threatlint's canonical agent and skill files into the workspace
  `.claude/` directory only when the repository does not already define them, so repo-local
  customizations win. The setup writes runner-local support files, not source fixes;
  persistent/self-hosted workspaces need their own cleanup and isolation policy.
- Review which source/report content the selected provider receives. Claude can
  inspect repository files; prompt-based providers receive a bounded snapshot.
  Read-only agent instructions are not an execution sandbox.
