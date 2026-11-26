---
title: Choose a model provider
description: Connect a local model, API provider, or signed-in CLI for security reviews.
---

Choose one provider for your first review. Sample reports and the built-in [security scanner](security-scanner.md) do not need a model.

## Before you start

You need access to the model you select and permission to send it the repository's source and supporting evidence. A hosted web profile needs its own server-side configuration; it cannot use your laptop's CLI login. See [Profiles](profiles.md).

## Configure the Workbench

1. Open **Settings → Model provider**.
2. Select a provider from the table below.
3. Use **Load models** where available, or enter the exact model ID manually. Bedrock model IDs are entered manually.
4. Enter a session key if needed, or leave it empty to use an already configured credential.
5. Choose **Save model settings**, then start a small review from the [Quickstart](learning.md).

Saving settings does not start a model request. Starting a review or chat sends its prompts, supporting documents, and inspected source to the selected provider. Non-secret selections are saved with your profile. Typed session keys remain in memory; they are not saved as model preferences.

| Workbench provider | Connection |
| --- | --- |
| LM Studio / compatible | A loaded model supporting streamed tool calls; default server `http://localhost:1234/v1`. HTTP is accepted only for loopback; remote servers require HTTPS. |
| Anthropic | An Anthropic API key, such as `ANTHROPIC_API_KEY`. |
| Claude Code | Install [Claude Code](https://claude.com/claude-code) and run `claude` once to sign in. No API key is required. |
| OpenAI | An OpenAI API key. A ChatGPT-account sign-in does not provide this API key. |
| Codex | A signed-in Codex CLI: run `codex login` first. Leaving the model blank uses Codex's built-in default. |
| GitHub Copilot | A supported GitHub token or `gh auth login`; available models and quotas depend on your account. |
| Amazon Bedrock | A Bedrock API key, its region, and an exact Claude model or inference profile ID. |
| Daybreak Blue · OpenAI | Approved Daybreak access plus an API key, or the Workbench's eligible signed-in Codex CLI fallback. |
| Daybreak Blue · Amazon Bedrock | Approved access to `openai.gpt-daybreak-blue-5.6-sol` in `us-east-2`, with a Bedrock API key. |

## Run from the CLI

For a local model, install [LM Studio](https://lmstudio.ai), load a suitable model, and start its local server:

```bash
curl -fsS http://localhost:1234/v1/models
threatlint run threat-model --provider lmstudio
```

The model listing should contain your loaded model. Use `--model MODEL_ID` or `--base-url URL` to override the defaults. Installed Claude Code `*-local` slash commands also accept `LMSTUDIO_BASE_URL` and `LMSTUDIO_MODEL`; run `threatlint install -y` before using them.

Examples for other providers:

```bash
threatlint run threat-model --provider claude-code
threatlint run threat-model --provider codex
threatlint run security-review --provider claude --base main --head HEAD
threatlint run threat-model --provider openai --output-dir ./reports
threatlint run threat-model --provider bedrock --bedrock-region us-east-1 --model YOUR_BEDROCK_MODEL_ID
```

The direct CLI's `claude` and `openai` providers read `ANTHROPIC_API_KEY` and `OPENAI_API_KEY`. Supply secrets through your approved environment or secret store rather than command history. Although `--api-key` exists, it can expose a key in shell history or process arguments.

Native CLI providers use their own sign-in: Claude Code uses `claude`, Codex uses `codex login`, and `--provider copilot` requires the signed-in Copilot CLI. Threatlint restricts these review runs to source inspection. Claude Code settings and hooks are excluded; Codex uses an ephemeral read-only sandbox but still loads the target repository's `AGENTS.md`. Threatlint does not extract their OAuth credentials. Claude Code runs default to a one-hour limit (`THREATLINT_CLAUDE_CODE_TIMEOUT_S` for the CLI, `THREATLINT_CLAUDE_CODE_TIMEOUT_MS` for the Workbench). A run that produces no output for 15 minutes is treated as stalled and stopped early (`THREATLINT_CLAUDE_CODE_IDLE_S` / `THREATLINT_CLAUDE_CODE_IDLE_MS`); this usually means API rate limiting or overload. The stop message includes Claude Code's last error line, and an AVIT review that stalls or times out is retried once with a fresh run before it is reported as an error.

## Credential lookup in the Workbench

A session key takes precedence over configured API credentials. Common fallback locations are:

- Anthropic: `ANTHROPIC_API_KEY`, then the `env` block in `~/.claude/settings.json`, then `ANTHROPIC_AUTH_TOKEN`. `ANTHROPIC_BASE_URL` can select a gateway.
- OpenAI: `OPENAI_API_KEY`, then an API key in `$CODEX_HOME/auth.json` or `~/.codex/auth.json`. A Codex OAuth sign-in is used only through its CLI provider.
- Copilot: `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN`, then `gh auth token`.
- Bedrock: `AWS_BEARER_TOKEN_BEDROCK`, then `BEDROCK_API_KEY`, then those names in Claude settings.

On Windows, `~` means `%USERPROFILE%`. To load session credentials through named AWS references, use [AWS Parameter Store](aws-parameters.md).

## Amazon Bedrock

Use the region where the Bedrock key was created. Region lookup is: the selected region, `AWS_REGION`, `AWS_DEFAULT_REGION`, those settings in `~/.claude/settings.json`, then `us-east-1`.

Threatlint's Claude Bedrock provider uses the key directly with the regional [Messages API](https://docs.aws.amazon.com/bedrock/latest/userguide/inference-messages-api.html). It does not substitute an Anthropic key, Claude Code subscription, IAM access key, or AWS SSO session. Model access is checked when a request runs; entering an ID does not establish access.

## Daybreak Blue

Access must already be approved for the account or API project. Installing Threatlint or enabling a checkbox does not grant it; see [OpenAI's Daybreak overview](https://help.openai.com/en/articles/20001258-openai-daybreak-trusted-access-for-cyber-overview).

For the native Codex CLI route:

```bash
threatlint run threat-model --provider codex --daybreak-blue
```

This enables Daybreak for the run and selects `gpt-6-sol` unless you set `--model`. See the [headless Codex guide](https://help.openai.com/en/articles/20001607-using-daybreak-in-codex-cli). The direct `--provider daybreak` API route requires its own OpenAI API key; it is separate from the native Codex login route.

## Model defaults

The packaged Claude defaults for both security analysis and general assistance are `claude-opus-5-5`. Explicit Workbench or `--model` choices take precedence.

| Purpose | Environment variable | Local `org.json` key |
| --- | --- | --- |
| Security analysis | `THREATLINT_SCAN_MODEL` | `scanModel` |
| General assistance | `THREATLINT_GENERAL_MODEL` | `generalModel` |

The file is `~/.threatlint/org.json`. Environment values override file values. Other providers keep their own defaults; Bedrock requires an explicit model ID.

## Check the result

A successful review returns a report with inspected evidence. If authentication or model access fails, check the selected provider, region, model ID, and account access before retrying. For local models, confirm `/v1/models` is reachable.

You can attach design documents with `--design`:

```bash
threatlint run threat-model --provider claude-code --design docs/architecture/ payments.drawio api.json
```

See [Design inputs](workbench.md#design-inputs) for formats and limits. CLI PDF extraction requires `pdftotext`; install Poppler, for example with `brew install poppler`, or supply text instead.

**Next:** follow the [Quickstart](learning.md), then read your [Reports](reports.md).
