# threatlint Azure Pipelines Templates
#
# Each .yml file in this directory is a reusable Azure Pipelines template.
# Reference them from your host pipeline using the `template:` keyword.
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
# | gateSeverity       | CRITICAL      | Fail pipeline if finding at or above this level |
# | minIssueSeverity   | HIGH          | Minimum severity to create work items for       |
# | createWorkItems    | false         | Create Azure DevOps work items for findings     |
#
# ## Gating
#
# Set `gateSeverity` to control when the pipeline step fails:
# - `CRITICAL`  — fails only on critical findings (default; least disruptive)
# - `HIGH`       — fails on high or critical findings (recommended for gated pipelines)
# - `MEDIUM`     — fails on medium, high, or critical findings
# - `''`         — disables gating (never fails the pipeline)
#
# ## Auto-fix
#
# Use `azure-pipelines/auto-fix.yml` to automatically implement remediations
# and open a pull request. See that template for parameters.
