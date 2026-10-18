# threatlint Azure Pipelines Templates
#
# Each .yml file in this directory is a reusable Azure Pipelines template.
# Reference them from your host pipeline using the `template:` keyword.
#
# ## Generic templates (recommended)
#
# templates/threatlint-job.yml   — one job per agent; runs ANY Threatlint agent
# templates/threatlint-steps.yml — the same steps, for embedding in an existing job
#
#      jobs:
#        - template: azure-pipelines/templates/threatlint-job.yml@threatlint
#          parameters:
#            agents: [appsec-code-reviewer, appsec-secrets-scanner]
#            failOnSeverity: high
#            anthropicApiKey: $(ANTHROPIC_API_KEY)
#
# Full parameter reference: docs/ci-templates.md · example: docs/examples/azure-caller.yml
# The per-agent templates below remain available for existing pipelines.
#
# ## Quick start
#
# 1. Add threatlint as a repository resource in your azure-pipelines.yml:
#
#      resources:
#        repositories:
#          - repository: threatlint
#            type: github
#            name: h0p3sf4ll/threatlint
#            ref: refs/heads/main
#            endpoint: <your-github-service-connection>
#
# 2. Reference the template you want:
#
#      stages:
#        - stage: Security
#          jobs:
#            - template: azure-pipelines/pr-review.yml@threatlint
#              parameters:
#                anthropicApiKey: $(ANTHROPIC_API_KEY)
#
# ## Common parameters (all templates)
#
# | Parameter          | Default       | Description                                     |
# |--------------------|---------------|-------------------------------------------------|
# | provider           | claude        | claude / openai / github-models                 |
# | anthropicApiKey    | (required if provider=claude) | Anthropic API key secret variable  |
# | openaiApiKey       | ''            | OpenAI API key (provider=openai only)           |
# | githubToken        | $(System.AccessToken) | GitHub token for github-models provider |
# | model              | ''            | Model override (empty = provider default)       |
# | gateSeverity       | CRITICAL      | Gate threshold (findings at or above this level) |
# | gateMode           | warn          | warn = warnings + SucceededWithIssues; fail = fail |
# | minIssueSeverity   | HIGH          | Minimum severity to create work items for       |
# | createWorkItems    | false         | Create Azure DevOps work items for findings     |
#
# ## Gating
#
# Set `gateSeverity` to choose which findings the gate reports:
# - `CRITICAL`  — critical findings only (default)
# - `HIGH`       — high or critical findings
# - `MEDIUM`     — medium, high, or critical findings
# - `''`         — disables the gate
#
# Set `gateMode` to choose what happens when the gate is hit:
# - `warn` (default) — each finding is logged as a warning and the job ends SucceededWithIssues
# - `fail`           — the job fails (use once findings are trusted, to block merges)
# A missing report warns in `warn` mode and fails in `fail` mode.
#
# ## PR conversations
#
# Developers can reply `/threatlint <question>` on a PR to discuss findings with the configured
# model. See `templates/threatlint-pr-chat.yml`, `docs/examples/azure-pr-chat-caller.yml`, and
# docs/ci-templates.md → "Conversing with Threatlint on pull requests".
#
# ## Auto-fix
#
# Use `azure-pipelines/auto-fix.yml` to automatically implement remediations
# and open a pull request. See that template for parameters.
