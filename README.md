```
TTTTT H   H RRRR  EEEEE  AAA  TTTTT L     IIIII N   N TTTTT
  T   H   H R   R E     A   A   T   L       I   NN  N   T
  T   HHHHH RRRR  EEEE  AAAAA   T   L       I   N N N   T
  T   H   H R R   E     A   A   T   L       I   N  NN   T
  T   H   H R  RR EEEEE A   A   T   LLLLL IIIII N   N   T
```

![Microsoft Teams](https://img.shields.io/badge/Microsoft%20Teams-supported-6264A7?style=flat-square)
![Claude Code](https://img.shields.io/badge/Claude%20Code-supported-D97706?style=flat-square)
![GitHub Copilot](https://img.shields.io/badge/GitHub%20Copilot-supported-1F883D?style=flat-square)
![OpenAI](https://img.shields.io/badge/OpenAI-supported-412991?style=flat-square)
![LM Studio](https://img.shields.io/badge/LM%20Studio-local%20models-6D28D9?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-0284C7?style=flat-square)

# threatlint

`threatlint` provides application security agents for threat modeling and security code review. It supports Claude Code (via subagents and slash commands), Codex CLI and other AGENTS.md-compatible tools (via `AGENTS.md`), GitHub Copilot Chat (via `.github/` customizations), Microsoft Teams (via the Claude API Teams bot), and local models via LM Studio — with no API key required. Reports are saved as Word documents in the repository being analyzed.

Analysis is grounded in the inspected source and local configuration. Assumptions and unknowns are labeled explicitly rather than hidden behind generic findings.

---

## Table of Contents

- [What Is Included](#what-is-included)
- [Requirements](#requirements)
- [Quick Start With Claude Code](#quick-start-with-claude-code)
- [Quick Start With Local Models (LM Studio)](#quick-start-with-local-models-lm-studio)
- [Quick Start With Codex / AGENTS.md Tools](#quick-start-with-codex--agentsmd-tools)
- [Quick Start With GitHub Copilot Chat](#quick-start-with-github-copilot-chat)
- [Quick Start With Microsoft Teams](#quick-start-with-microsoft-teams)
- [Installing on Another Repository](#installing-on-another-repository)
  - [Claude Code — Global](#claude-code--global-no-per-repo-import-required)
  - [Claude Code — Per-Repository](#claude-code--per-repository-team-use)
  - [Local Models (LM Studio)](#local-models-lm-studio)
  - [Codex / AGENTS.md — Global](#codex--agentsmd--global-no-per-repo-import-required)
  - [Codex / AGENTS.md — Per-Repository](#codex--agentsmd--per-repository-team-use)
  - [GitHub Copilot Chat](#installing-copilot-chat-agents-in-another-repository)
  - [Microsoft Teams](#installing-the-teams-bot)
  - [Verifying Any Installation](#verifying-any-installation)
- [Word Document Output](#word-document-output)
- [Analysis Posture](#analysis-posture)
- [Start Without Application Context](#start-without-application-context)
- [Agents](#agents)
- [Slash Commands](#slash-commands)
- [Read-Only Safety Boundaries](#read-only-safety-boundaries)
- [GitHub Actions](#github-actions)
- [Suggested Team Workflows](#suggested-team-workflows)
- [Customization](#customization)
- [Repository Layout](#repository-layout)
- [Troubleshooting](#troubleshooting)
- [Building the Business Case](#building-the-business-case)

---

## Building the Business Case

Selling an AppSec tooling investment to leadership often requires a concise, visual summary of what the tool does and why it matters. [`build_pptx.py`](build_pptx.py) generates a 6-slide executive overview deck covering capabilities, integrations, compatibility, usage, and how to get started.

```bash
pip3 install python-pptx
python3 build_pptx.py
# → threatlint-executive-overview.pptx (excluded from git via .gitignore)
```

The generated deck is designed for:

- **Pitching to security leadership** — a single slide per audience concern: the problem, the agents, where it runs, how teams invoke it, and how to roll it out.
- **Onboarding engineering managers** — shows the 14 agents and their domains so teams understand coverage before asking "does it do X?"
- **Procurement and compliance reviews** — platform breadth (Claude, OpenAI, local LLMs, Teams, CI/CD), read-only safety boundary, and compliance framework coverage (ASVS, PCI-DSS, HIPAA, SOC 2, ISO 27001) are all on one slide.
- **Demonstrating ROI** — the problem/answer slide maps each manual security pain point directly to the agent that removes it.

---

## What Is Included

| File | Use it for |
| --- | --- |
| [`AGENTS.md`](AGENTS.md) | Cross-platform agent instructions for OpenAI Codex CLI, GitHub Copilot Coding Agent, Cursor, and any tool that reads `AGENTS.md`. Covers all 14 security agents with routing, protocols, and report formats. |
| [`.claude/agents/appsec-threat-modeler.md`](.claude/agents/appsec-threat-modeler.md) | Claude Code subagent — evidence-based threat modeling with autonomous repository discovery, crown jewel analysis, attack chains, and MITRE ATT&CK/DREAD scoring. |
| [`.claude/agents/appsec-code-reviewer.md`](.claude/agents/appsec-code-reviewer.md) | Claude Code subagent — security review of a diff or pull request with merge recommendation. |
| [`.claude/agents/appsec-dependency-auditor.md`](.claude/agents/appsec-dependency-auditor.md) | Claude Code subagent — supply chain security: CVEs, dependency confusion, typosquatting, malicious install hooks, abandoned packages, lockfile integrity. |
| [`.claude/agents/appsec-secrets-scanner.md`](.claude/agents/appsec-secrets-scanner.md) | Claude Code subagent — secrets detection: API keys, private keys, connection strings, high-entropy patterns, git history scanning. |
| [`.claude/agents/appsec-iac-reviewer.md`](.claude/agents/appsec-iac-reviewer.md) | Claude Code subagent — IaC security: Terraform, Kubernetes, Helm, Dockerfile, CloudFormation. |
| [`.claude/agents/appsec-cicd-auditor.md`](.claude/agents/appsec-cicd-auditor.md) | Claude Code subagent — CI/CD security: script injection, workflow permissions, action pinning, fork secret exposure, artifact integrity. |
| [`.claude/agents/appsec-api-security-reviewer.md`](.claude/agents/appsec-api-security-reviewer.md) | Claude Code subagent — OWASP API Security Top 10 (2023): BOLA, broken auth, mass assignment, SSRF, resource consumption, and more. |
| [`.claude/agents/appsec-auth-reviewer.md`](.claude/agents/appsec-auth-reviewer.md) | Claude Code subagent — auth/authz deep-dive: OAuth 2.0/OIDC, JWT, sessions, CSRF, MFA, RBAC, multi-tenancy, password hashing, brute-force protection. |
| [`.claude/agents/appsec-fp-reviewer.md`](.claude/agents/appsec-fp-reviewer.md) | Claude Code subagent — false positive triage and Semgrep rule tuning. Accepts SARIF, Semgrep JSON, or pasted findings. |
| [`.claude/agents/appsec-compliance-checker.md`](.claude/agents/appsec-compliance-checker.md) | Claude Code subagent — maps findings to OWASP ASVS 4.0, PCI-DSS v4, HIPAA, SOC 2 Type II, ISO 27001:2022, NIST CSF 2.0, CIS Controls v8. |
| [`.claude/agents/appsec-attack-tree.md`](.claude/agents/appsec-attack-tree.md) | Claude Code subagent — formal AND/OR attack tree with Mermaid rendering, bypass analysis per defense node, and leaf node ranking. |
| [`.claude/agents/appsec-red-team.md`](.claude/agents/appsec-red-team.md) | Claude Code subagent — 5 adversarial scenarios with ATT&CK-mapped kill chains, IoCs, detection gaps, and purple-team test cases. |
| [`.claude/agents/appsec-threat-delta.md`](.claude/agents/appsec-threat-delta.md) | Claude Code subagent — compares a prior report to the current codebase: RESOLVED / PARTIALLY FIXED / STILL PRESENT / REGRESSED / NEW. |
| [`.claude/agents/appsec-verify-fix.md`](.claude/agents/appsec-verify-fix.md) | Claude Code subagent — verifies a specific finding: REMEDIATED / PARTIALLY FIXED / STILL PRESENT / REGRESSED. |
| [`web/`](web/) | Web UI with streaming terminal, chat panel, and multi-agent pipeline runner. Supports Claude, OpenAI, and local LLMs via LM Studio. |
| [`teams-app/`](teams-app/) | Microsoft Teams bot (Node.js + Bot Framework) that routes security commands to Claude AI agents via the Anthropic API. |
| [`docs/agents.md`](docs/agents.md) | Comprehensive per-agent documentation: protocols, coverage areas, frameworks applied, and complete report format for all 14 agents. |

### Slash Commands

| Command | Description |
| --- | --- |
| `/threat-model` | Threat model (cloud, + Word doc) |
| `/threat-model-deep` | Deep-dive threat model with bypass chains and kill chains (cloud) |
| `/threat-model-local` | Threat model via LM Studio (local, no API key) |
| `/threat-model-deep-local` | Deep-dive threat model via LM Studio (local) |
| `/security-review` | Security code review of a diff/branch/PR (cloud, + Word doc) |
| `/security-review-local` | Security code review via LM Studio (local) |
| `/dependency-audit` | Supply chain dependency audit (cloud, + Word doc) |
| `/dependency-audit-local` | Dependency audit via LM Studio (local) |
| `/secrets-scan` | Secrets and credential detection scan (cloud, + Word doc) |
| `/secrets-scan-local` | Secrets scan via LM Studio (local) |
| `/iac-review` | IaC security review — Terraform, K8s, Dockerfile (cloud, + Word doc) |
| `/iac-review-local` | IaC review via LM Studio (local) |
| `/cicd-audit` | CI/CD pipeline security audit (cloud, + Word doc) |
| `/cicd-audit-local` | CI/CD audit via LM Studio (local) |
| `/api-security-review` | OWASP API Security Top 10 review (cloud, + Word doc) |
| `/api-security-review-local` | API security review via LM Studio (local) |
| `/auth-review` | Auth/authz deep-dive review (cloud, + Word doc) |
| `/auth-review-local` | Auth review via LM Studio (local) |
| `/compliance-check` | Map findings to OWASP ASVS, PCI-DSS v4, HIPAA, SOC 2, ISO 27001, NIST CSF, CIS (cloud) |
| `/attack-tree` | Formal AND/OR attack tree with bypass analysis and leaf node ranking (cloud) |
| `/attack-tree-local` | Attack tree via LM Studio (local) |
| `/red-team` | 5 adversarial scenarios with full kill chains and purple-team test cases (cloud) |
| `/red-team-local` | Red team scenarios via LM Studio (local) |
| `/threat-delta` | Compare previous report to current state: New/Resolved/Regressed/Unchanged (cloud) |
| `/verify-fix` | Verify a specific finding was remediated: REMEDIATED/PARTIALLY FIXED/STILL PRESENT/REGRESSED (cloud) |

### GitHub Integrations

| File | Purpose |
| --- | --- |
| [`.github/agents/`](.github/agents/) | 14 Copilot Chat agents — one per security domain |
| [`.github/workflows/appsec-pr-review.yml`](.github/workflows/appsec-pr-review.yml) | Runs on every non-draft PR: security review + PR comment + SARIF upload + issues |
| [`.github/workflows/appsec-threat-model.yml`](.github/workflows/appsec-threat-model.yml) | Manual: threat model + SARIF upload + issues |
| [`.github/workflows/appsec-scheduled.yml`](.github/workflows/appsec-scheduled.yml) | Weekly + on IaC/Dockerfile changes: automated threat model + issues |
| [`.github/workflows/appsec-dependency-audit.yml`](.github/workflows/appsec-dependency-audit.yml) | On manifest/lockfile changes: dependency audit + issues |
| [`.github/workflows/appsec-iac-review.yml`](.github/workflows/appsec-iac-review.yml) | On IaC changes: IaC security review + issues |
| [`.github/scripts/appsec_api.py`](.github/scripts/appsec_api.py) | OpenAI / GitHub Models / LM Studio runner (10 modes) |
| [`.github/scripts/create_issues.py`](.github/scripts/create_issues.py) | Parses reports and opens deduplicated GitHub issues |
| [`.github/scripts/to_sarif.py`](.github/scripts/to_sarif.py) | Converts threatlint reports to SARIF 2.1.0 for GitHub Code Scanning |
| [`.github/scripts/post_pr_comment.py`](.github/scripts/post_pr_comment.py) | Posts risk summary as a PR comment with merge recommendation |
| [`.claude/hooks/pre-commit`](.claude/hooks/pre-commit) | Optional git pre-commit hook: blocks secrets staged for commit |
| [`docs/github-actions.md`](docs/github-actions.md) | Provider setup, issue configuration, and GitHub Actions troubleshooting |

### Word Document Converter

`~/.claude/scripts/md_to_docx.py` converts reports to formatted `.docx` files. It is installed to the user's home directory — not checked into target repositories.

---

## Requirements

**For Claude Code (cloud models):**
- Claude Code CLI or IDE extension
- Python 3 + python-docx: `pip3 install python-docx`
- `~/.claude/scripts/md_to_docx.py` installed (see [Word Document Output](#word-document-output))

**For Claude Code (local models via LM Studio):**
- Claude Code CLI or IDE extension
- LM Studio running with a model loaded and the local server started
- Python 3 + openai + python-docx: `pip3 install openai python-docx`
- `~/.claude/scripts/appsec_api.py` and `~/.claude/scripts/md_to_docx.py` installed (see [Local Models (LM Studio)](#local-models-lm-studio))

**For Codex / AGENTS.md tools:**
- OpenAI Codex CLI, GitHub Copilot Coding Agent, Cursor, or any tool that reads `AGENTS.md`
- Python 3 + python-docx: `pip3 install python-docx`
- `~/.claude/scripts/md_to_docx.py` installed

**For GitHub Copilot Chat:**
- VS Code with the GitHub Copilot extension and Copilot Chat enabled
- A trusted workspace containing the `.github/agents/` and `.github/prompts/` files
- No Word document output — Copilot Chat reports remain in the chat window

No project dependency, service account, or external scanner is required. `threatlint` is source-guided analysis — it is not a replacement for SAST, DAST, dependency scanning, penetration testing, or a formal security approval process.

---

## Quick Start With Claude Code

The slash commands are the fastest way to get a report and a Word document.

```text
# Threat modeling
/threat-model                        # auto-discover the repo
/threat-model src/api/auth           # specific component
/threat-model-deep                   # aggressive deep-dive (maximum coverage)

# Code review
/security-review                     # working-tree diff
/security-review main..feature       # branch comparison
/security-review 42                  # PR number

# Specialized audits
/dependency-audit                    # supply chain — all manifests
/secrets-scan                        # credential and API key detection
/iac-review                          # Terraform, Kubernetes, Dockerfile
/cicd-audit                          # GitHub Actions and CI pipeline
/api-security-review                 # OWASP API Security Top 10
/auth-review                         # OAuth, JWT, sessions, MFA, RBAC

# Analysis and scenario tooling
/compliance-check                    # OWASP ASVS, PCI-DSS, HIPAA, SOC 2, ISO 27001
/attack-tree <component>             # formal AND/OR attack tree
/red-team                            # 5 adversarial scenarios with kill chains
/threat-delta <previous-report.docx> # compare to a prior report
/verify-fix CR-042                   # confirm a specific finding was fixed
```

You can also address agents directly via the `@` picker or `--agent` flag — this produces the report in chat but **does not save a Word document**.

---

## Quick Start With Local Models (LM Studio)

Run all analysis entirely on your machine — no API key, no cloud, no data leaving your environment.

**Before running:** open LM Studio, load a model, then go to Developer → Local Server → Start Server.

```text
# Threat modeling
/threat-model-local                  # auto-discover with local model
/threat-model-deep-local             # deep-dive with local model

# Code review
/security-review-local               # working-tree diff
/security-review-local main..feature # branch comparison

# Specialized audits (all local)
/dependency-audit-local
/secrets-scan-local
/iac-review-local
/cicd-audit-local
/api-security-review-local
/auth-review-local
/attack-tree-local <component>
/red-team-local
```

Commands auto-detect the loaded model. No model name needs to be specified.

---

## Quick Start With Codex / AGENTS.md Tools

When `AGENTS.md` is present in the repository (or globally), instruct the agent naturally:

```text
threat model this repository
security review the current diff
review PR #42 for security regressions
threat model src/payments
```

The agent reads `AGENTS.md`, performs the analysis, and saves the report as a Word document using the converter script.

---

## Quick Start With GitHub Copilot Chat

The `.github/agents/` files register fourteen custom agents in Copilot Chat. The `.github/prompts/` files register two slash commands. All are available as soon as the repository is open in a trusted VS Code workspace.

### Agents

Open Copilot Chat and select an agent from the agent picker (the `@` icon or the model selector):

- **AppSec Threat Modeler** — threat model a component, feature, or the entire repository.
- **AppSec Code Reviewer** — security review a pull request, diff, or set of changed files.
- **AppSec Dependency Auditor** — audit third-party dependencies and supply chain risk.
- **AppSec Secrets Scanner** — scan for hardcoded credentials, keys, and high-entropy tokens.
- **AppSec IaC Reviewer** — review Terraform, Kubernetes, Helm, and Dockerfile configurations.
- **AppSec CI/CD Auditor** — audit GitHub Actions, Jenkins, and other pipeline configurations.
- **AppSec API Security Reviewer** — review REST, GraphQL, and gRPC APIs against OWASP API Top 10.
- **AppSec Auth Reviewer** — deep-dive review of authentication and authorization implementations.
- **AppSec False Positive Reviewer** — triage scanner findings and generate Semgrep rule tuning.
- **AppSec Compliance Checker** — map findings to ASVS, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST CSF, CIS.
- **AppSec Attack Tree** — formal AND/OR attack tree with bypass analysis and leaf node ranking.
- **AppSec Red Team** — 5 adversarial scenarios with ATT&CK kill chains and purple-team test cases.
- **AppSec Threat Delta** — compare a prior report to current state: RESOLVED/REGRESSED/NEW/STILL PRESENT.
- **AppSec Verify Fix** — verify a specific finding: REMEDIATED/PARTIALLY FIXED/STILL PRESENT/REGRESSED.

Then describe what to analyze:

```text
@AppSec Threat Modeler threat model the auth service in src/auth

@AppSec Code Reviewer review the changes in this PR for authentication
bypasses and privilege escalation
```

### Slash Prompts

Type `/` in Copilot Chat to open the prompt picker:

- **`/Discover Application Threat Model`** — no target needed; the agent inventories the repository and selects an evidence-supported initial scope automatically.
- **`/Threat Model Report`** — supply a target in the chat after running the prompt to generate a standardized two-tier report.

### Word Document Output

**Copilot Chat does not save Word documents.** The report is returned in the chat window only. To get a `.docx` file, use Claude Code (`/threat-model`, `/threat-model-deep`, `/security-review`) or Codex instead.

---

## Quick Start With Microsoft Teams

The `teams-app/` directory contains a Microsoft Teams bot that routes security analysis commands to Claude AI agents using the Anthropic API.

### Prerequisites

- Microsoft Azure account with a Bot Framework registration
- Node.js 18+
- An Anthropic API key (`ANTHROPIC_API_KEY`)

### Setup

**Step 1 — Register a bot in Azure**

1. Go to [Azure Portal](https://portal.azure.com) → Create a resource → "Azure Bot".
2. Set the messaging endpoint to `https://<your-domain>/api/messages`.
3. Note the **App ID** and generate a **client secret** (App Password).

**Step 2 — Deploy the bot**

```bash
cd /path/to/threatlint/teams-app
npm install

export ANTHROPIC_API_KEY=sk-ant-...
export BOT_APP_ID=<azure-app-id>
export BOT_APP_PASSWORD=<azure-app-password>

node bot.js
```

**Step 3 — Package and sideload into Teams**

1. Edit `teams-app/manifest.json` and replace `{{BOT_APP_ID}}` with your Azure App ID.
2. Add 192×192 `icon-color.png` and 32×32 `icon-outline.png` to `teams-app/`.
3. Zip the three files: `manifest.json`, `icon-color.png`, `icon-outline.png`.
4. In Microsoft Teams → Apps → Manage your apps → Upload an app → Upload the zip.

### Usage

Mention the bot or send commands directly in any Teams channel where it is installed:

```text
@threatlint /threat-model
@threatlint /security-review src/auth
@threatlint /compliance-check
@threatlint /red-team
@threatlint /help
```

All 14 agents are available. The bot uses Claude AI (configurable via `CLAUDE_MODEL`) and returns the full analysis report directly in the Teams conversation. Large reports are automatically split to stay within Teams' message size limit.

### Claude Model

By default the bot uses `claude-sonnet-5`. Override with:

```bash
export CLAUDE_MODEL=claude-opus-5
```

---

## Installing on Another Repository

There are six installation paths depending on tool, scope, and whether you want cloud or local models. **Agents alone are not sufficient for Word document output in Claude Code** — the commands wire up the conversion pipeline.

---

### Claude Code — Global (No Per-Repo Import Required)

Agents and commands installed globally are available in every repository you open. **This is already done** on this machine. For a fresh setup:

```bash
mkdir -p ~/.claude/agents
cp /path/to/threatlint/.claude/agents/*.md ~/.claude/agents/

mkdir -p ~/.claude/commands
cp /path/to/threatlint/.claude/commands/*.md ~/.claude/commands/

mkdir -p ~/.claude/scripts
cp /path/to/threatlint/.claude/scripts/md_to_docx.py ~/.claude/scripts/
pip3 install python-docx
```

Open any repository in Claude Code. All 8 agents and all slash commands are immediately available.

---

### Claude Code — Per-Repository (Team Use)

Check the files into the target repository so every teammate gets the agents and commands when they open the repo.

```bash
cd /path/to/your-repo

mkdir -p .claude/agents .claude/commands

cp /path/to/threatlint/.claude/agents/*.md .claude/agents/
cp /path/to/threatlint/.claude/commands/*.md .claude/commands/

cat >> CLAUDE.md << 'EOF'

## Security Analysis

- Delegate threat-modeling requests to `appsec-threat-modeler`.
- Delegate security reviews of diffs and risky configuration changes to `appsec-code-reviewer`.
- Delegate dependency and supply chain audits to `appsec-dependency-auditor`.
- Delegate secrets and credential scanning to `appsec-secrets-scanner`.
- Delegate IaC security reviews (Terraform, Kubernetes, Dockerfile) to `appsec-iac-reviewer`.
- Delegate CI/CD pipeline audits to `appsec-cicd-auditor`.
- Delegate API security reviews to `appsec-api-security-reviewer`.
- Delegate authentication and authorization reviews to `appsec-auth-reviewer`.
- Delegate false positive triage and Semgrep rule tuning to `appsec-fp-reviewer`.
- Delegate compliance mapping (ASVS, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST CSF, CIS) to `appsec-compliance-checker`.
- Delegate formal attack tree construction to `appsec-attack-tree`.
- Delegate adversarial red-team scenario generation to `appsec-red-team`.
- Delegate comparison of a prior report to current state to `appsec-threat-delta`.
- Delegate verification of whether a specific finding was remediated to `appsec-verify-fix`.
- When no target is given, use `appsec-threat-modeler` — it will discover the repository automatically.
EOF

git add .claude CLAUDE.md
git commit -m "Add threatlint security agents and commands"
```

**Each team member** then does the personal setup once (not committed to the repo):

```bash
mkdir -p ~/.claude/scripts
cp /path/to/threatlint/.claude/scripts/md_to_docx.py ~/.claude/scripts/
pip3 install python-docx
```

The converter script is a local runtime tool — not source code — so it stays out of the repository.

**What each piece does:**

| What you copy | Effect |
| --- | --- |
| `.claude/agents/` only | `@appsec-threat-modeler` etc. appear in the `@` picker; analysis runs; **no Word document is saved** |
| `.claude/agents/` + `.claude/commands/` | Full pipeline: analysis runs and `.docx` is saved to the repo root |
| `CLAUDE.md` routing | Claude Code automatically routes security requests to the right agent without needing `@` |
| Personal: `md_to_docx.py` + `python-docx` | Required for the commands to write the `.docx` file |

---

### Local Models (LM Studio)

All local slash commands call `appsec_api.py` with `--provider lmstudio`. They use the model currently loaded in LM Studio — no API key is required.

**Step 1 — Install LM Studio**

Download and install LM Studio from [https://lmstudio.ai](https://lmstudio.ai). Load a model (models with at least 7B parameters and strong instruction-following capability work best for security analysis). Open LM Studio → Developer → Local Server → Start Server. The API becomes available at `http://localhost:1234/v1`.

**Step 2 — Install the command files and scripts**

```bash
mkdir -p ~/.claude/commands
cp /path/to/threatlint/.claude/commands/*-local.md ~/.claude/commands/

mkdir -p ~/.claude/scripts
cp /path/to/threatlint/.github/scripts/appsec_api.py ~/.claude/scripts/
cp /path/to/threatlint/.claude/scripts/md_to_docx.py ~/.claude/scripts/
pip3 install openai python-docx
```

**Step 3 — Verify**

```bash
curl -s http://localhost:1234/v1/models
```

The response should list the model currently loaded in LM Studio. Then open any repository in Claude Code and run `/threat-model-local` — the command will auto-detect the loaded model and begin the analysis.

**Optional environment variables:**

| Variable | Default | Effect |
| --- | --- | --- |
| `LMSTUDIO_BASE_URL` | `http://localhost:1234/v1` | Override LM Studio server address |
| `LMSTUDIO_MODEL` | auto-detected | Pin a specific model ID instead of using the first loaded model |

---

### Codex / AGENTS.md — Global (No Per-Repo Import Required)

Copy `AGENTS.md` to the Codex user-level location. The agent reads it when working in any repository.

```bash
mkdir -p ~/.codex
cp /path/to/threatlint/AGENTS.md ~/.codex/AGENTS.md
```

Then do the personal converter setup:

```bash
mkdir -p ~/.claude/scripts
cp /path/to/threatlint/.claude/scripts/md_to_docx.py ~/.claude/scripts/
pip3 install python-docx
```

---

### Codex / AGENTS.md — Per-Repository (Team Use)

Copy `AGENTS.md` to the target repository root and commit it.

```bash
cp /path/to/threatlint/AGENTS.md /path/to/your-repo/AGENTS.md
```

Or append to an existing `AGENTS.md`:

```bash
cat /path/to/threatlint/AGENTS.md >> /path/to/your-repo/AGENTS.md
```

Each team member still needs the personal converter setup:

```bash
mkdir -p ~/.claude/scripts
cp /path/to/threatlint/.claude/scripts/md_to_docx.py ~/.claude/scripts/
pip3 install python-docx
```

---

### Installing Copilot Chat Agents in Another Repository

Copy the `.github/` files into the target repository and commit them:

```bash
cd /path/to/your-repo
mkdir -p .github/agents .github/prompts

cp /path/to/threatlint/.github/agents/*.agent.md .github/agents/
cp /path/to/threatlint/.github/prompts/discover-application-threat-model.prompt.md .github/prompts/
cp /path/to/threatlint/.github/prompts/threat-model-report.prompt.md .github/prompts/

git add .github
git commit -m "Add threatlint Copilot Chat security agents and prompts"
```

There is no global equivalent for Copilot Chat agents — the `.github/` files must be present in the repository that VS Code has open as its workspace root. After committing, reload the VS Code window once to pick up the new agents and prompts.

---

### Installing the Teams Bot

The Teams bot runs as a service alongside your existing infrastructure. Deploy it once and connect it to your Microsoft Teams workspace.

```bash
cd /path/to/threatlint/teams-app
npm install

# Edit manifest.json: replace {{BOT_APP_ID}} with your Azure App ID
# Add icon-color.png (192x192) and icon-outline.png (32x32)

# Set required environment variables (in your hosting environment)
ANTHROPIC_API_KEY=sk-ant-...
BOT_APP_ID=<azure-app-id>
BOT_APP_PASSWORD=<azure-app-password>
```

See [Quick Start With Microsoft Teams](#quick-start-with-microsoft-teams) for the full registration and deployment steps.

---

### Verifying Any Installation

1. **Claude Code (cloud)**: type `@` — all 14 agents should appear. Type `/` — all slash commands should appear in the picker.
2. **Claude Code (local)**: type `/` — `threat-model-local`, `security-review-local`, `dependency-audit-local`, `secrets-scan-local`, `iac-review-local`, `cicd-audit-local`, `api-security-review-local`, `auth-review-local`, `attack-tree-local`, `red-team-local` should appear. LM Studio must be running with a model loaded.
3. **Codex**: confirm `AGENTS.md` is present at the repo root or the global path. Ask "threat model this repository" — it should begin discovery immediately.
4. **GitHub Copilot Chat**: type `@` — 14 agents should appear. Type `/` — `Discover Application Threat Model` and `Threat Model Report` should appear.
5. **Microsoft Teams**: send `@threatlint /help` — the bot should respond with the list of 14 available commands.
6. **End-to-end (Claude Code / Codex)**: run `/threat-model` or `/threat-model-local`. A `<repo-name>-<branch>-threat-model-YYYY-MM-DD.docx` should appear in the current directory.

---

## Word Document Output

Every report is saved as a formatted `.docx` file. The document opens with the repository name, date, and scope, then contains both the executive summary and the full technical report.

### Setup

Install the python-docx dependency, then copy the converter script to `~/.claude/scripts/`:

```bash
pip3 install python-docx
mkdir -p ~/.claude/scripts
cp /path/to/threatlint/.claude/scripts/md_to_docx.py ~/.claude/scripts/
```

For local model commands, also install the `openai` package and the API script:

```bash
pip3 install openai
cp /path/to/threatlint/.github/scripts/appsec_api.py ~/.claude/scripts/
```

This is a one-time personal setup. The scripts live in `~/.claude/scripts/` and are referenced by the Claude Code commands and the Codex `AGENTS.md` instructions.

### Output Locations and Filenames

All filenames are prefixed with `<repo-name>-<branch>-`, where `<repo-name>` is the lowercased repository directory name (spaces → hyphens) and `<branch>` is the current git branch name (lowercased, `/` → `-`). For example, running `/threat-model` on the `myapp` repo on branch `main` produces `myapp-main-threat-model-YYYY-MM-DD.docx`.

| Invocation | Filename | Directory |
| --- | --- | --- |
| `/threat-model` | `<repo>-<branch>-threat-model-YYYY-MM-DD.docx` | Current working directory |
| `/threat-model src/auth` | `<repo>-<branch>-threat-model-src-auth-YYYY-MM-DD.docx` | Current working directory |
| `/threat-model-deep` | `<repo>-<branch>-threat-model-deep-YYYY-MM-DD.docx` | Current working directory |
| `/threat-model-local` | `<repo>-<branch>-threat-model-local-YYYY-MM-DD.docx` | Current working directory |
| `/threat-model-deep-local` | `<repo>-<branch>-threat-model-deep-local-YYYY-MM-DD.docx` | Current working directory |
| `/security-review` | `<repo>-<branch>-security-review-YYYY-MM-DD.docx` | Repository root |
| `/security-review main..feature` | `<repo>-<branch>-security-review-main-feature-YYYY-MM-DD.docx` | Repository root |
| `/security-review 42` | `<repo>-<branch>-security-review-pr42-YYYY-MM-DD.docx` | Repository root |
| `/security-review-local` | `<repo>-<branch>-security-review-local-YYYY-MM-DD.docx` | Repository root |
| `/dependency-audit` | `<repo>-<branch>-dependency-audit-YYYY-MM-DD.docx` | Repository root |
| `/dependency-audit-local` | `<repo>-<branch>-dependency-audit-local-YYYY-MM-DD.docx` | Repository root |
| `/secrets-scan` | `<repo>-<branch>-secrets-scan-YYYY-MM-DD.docx` | Repository root |
| `/secrets-scan-local` | `<repo>-<branch>-secrets-scan-local-YYYY-MM-DD.docx` | Repository root |
| `/iac-review` | `<repo>-<branch>-iac-review-YYYY-MM-DD.docx` | Repository root |
| `/iac-review-local` | `<repo>-<branch>-iac-review-local-YYYY-MM-DD.docx` | Repository root |
| `/cicd-audit` | `<repo>-<branch>-cicd-audit-YYYY-MM-DD.docx` | Repository root |
| `/cicd-audit-local` | `<repo>-<branch>-cicd-audit-local-YYYY-MM-DD.docx` | Repository root |
| `/api-security-review` | `<repo>-<branch>-api-security-review-YYYY-MM-DD.docx` | Repository root |
| `/api-security-review-local` | `<repo>-<branch>-api-security-review-local-YYYY-MM-DD.docx` | Repository root |
| `/auth-review` | `<repo>-<branch>-auth-review-YYYY-MM-DD.docx` | Repository root |
| `/auth-review-local` | `<repo>-<branch>-auth-review-local-YYYY-MM-DD.docx` | Repository root |
| `/compliance-check <framework>` | `<repo>-<branch>-compliance-<framework>-YYYY-MM-DD.docx` | Repository root |
| `/attack-tree <asset>` | `<repo>-<branch>-attack-tree-<sanitized>-YYYY-MM-DD.docx` | Current working directory |
| `/attack-tree-local <asset>` | `<repo>-<branch>-attack-tree-local-<sanitized>-YYYY-MM-DD.docx` | Current working directory |
| `/red-team` | `<repo>-<branch>-red-team-YYYY-MM-DD.docx` | Current working directory |
| `/red-team-local` | `<repo>-<branch>-red-team-local-YYYY-MM-DD.docx` | Current working directory |
| `/threat-delta` | `<repo>-<branch>-threat-delta-YYYY-MM-DD.docx` | Current working directory |
| `/verify-fix <ID>` | `<repo>-<branch>-verify-<finding-id>-YYYY-MM-DD.docx` | Current working directory |
| `/fp-review [file]` | `<repo>-<branch>-fp-review-YYYY-MM-DD.docx` | Repository root |

Codex follows the same filename and directory conventions defined in `AGENTS.md`.

**Copilot Chat does not save Word documents.** Reports stay in the chat window. Use Claude Code commands or Codex when a `.docx` file is required.

### What the Converter Handles

The converter (`md_to_docx.py`) renders the full report structure:
- H1–H4 headings with colour coding (navy → blue → green → near-black)
- Finding summary tables and finding detail tables
- Fenced code blocks in monospace (remediation snippets, shell commands)
- Bullet and numbered lists (attack steps, remediation steps)
- Bold, italic, and inline-code runs
- Horizontal rules as styled section separators

If the converter is not installed, the commands fall back to saving the report as a `.md` file and note the missing dependency.

---

## Analysis Posture

All agents use an **aggressive-by-default** posture. The same posture is encoded in `AGENTS.md` for Codex and in `appsec_api.py` for the local-model commands.

- Borderline THEORETICAL/PLAUSIBLE findings are escalated to PLAUSIBLE when the preconditions are realistic for a production deployment.
- Every defensive control — authentication, authorization, input validation, rate limiting — is examined for bypass paths. A clean result is stated explicitly, not silently omitted.
- Low-severity findings that enable higher-severity ones are combined into chained attack scenarios.
- Source code, configuration, and documentation are all treated as known to the attacker. "Requires internals knowledge" is not a downgrade reason.
- An attack path is only excluded if a defensive control is verifiably correct in the reviewed code, or the prerequisite is architecturally impossible.

Use `/threat-model-deep` or `/threat-model-deep-local` for maximum coverage: additionally requires bypass chain analysis per control, multi-step kill chains, per-category breadth coverage, and a runtime blindspot inventory.

---

## Start Without Application Context

Run `/threat-model` or `/threat-model-local` with no arguments, ask "threat model this repository" (Codex), or type `/Discover Application Threat Model` in Copilot Chat. The agent:

1. Inventories documentation, manifests, source roots, Dockerfiles, IaC, and CI/CD workflows.
2. Maps entry points, trust boundaries, identities, sensitive data, and privileged operations.
3. Ranks candidate scopes by external exposure, privilege level, sensitive-data handling, and blast radius.
4. Selects the highest-risk representative scope, explains the selection with evidence, and begins the full threat model immediately.

The report ends with **Suggested Focused Follow-Ups**: three to five ready-to-send prompts naming specific discovered components and asking narrow, high-value security questions.

---

## Agents

threatlint includes 14 specialized security agents. Each is read-only and produces a structured two-tier report saved as a Word document. For full per-agent documentation, see [docs/agents.md](docs/agents.md).

| Agent | Finding Prefix | Coverage |
| --- | --- | --- |
| `appsec-threat-modeler` | `TM-` | Full repository threat model: STRIDE, OWASP, CWE, ATT&CK, DREAD, crown jewel analysis, attack chains |
| `appsec-code-reviewer` | `CR-` | Security review of code changes: regression detection, secrets, dependencies, merge recommendation |
| `appsec-dependency-auditor` | `DA-` | Supply chain: CVEs, dependency confusion, typosquatting, malicious hooks, lockfile integrity |
| `appsec-secrets-scanner` | `SS-` | Credential detection: API keys, private keys, connection strings, entropy analysis |
| `appsec-iac-reviewer` | `IC-` | IaC misconfigurations: Terraform IAM/network, Kubernetes pod security, Dockerfile, CloudFormation |
| `appsec-cicd-auditor` | `CI-` | CI/CD pipeline: script injection, workflow permissions, action pinning, fork secret exposure |
| `appsec-api-security-reviewer` | `AR-` | OWASP API Security Top 10 (2023): BOLA, broken auth, mass assignment, SSRF, resource consumption |
| `appsec-auth-reviewer` | `AU-` | Auth/authz deep-dive: OAuth 2.0/OIDC, JWT, sessions, CSRF, MFA, RBAC, multi-tenancy, brute-force |
| `appsec-fp-reviewer` | `FP-` | False positive triage and Semgrep rule tuning; accepts SARIF, Semgrep JSON, or pasted findings |
| `appsec-compliance-checker` | `CC-` | Compliance mapping: OWASP ASVS 4.0, PCI-DSS v4, HIPAA, SOC 2, ISO 27001:2022, NIST CSF 2.0, CIS v8 |
| `appsec-attack-tree` | `AT-` | Formal AND/OR attack tree with Mermaid rendering, defense bypass analysis, leaf node ranking |
| `appsec-red-team` | `RT-` | 5 adversarial scenarios with ATT&CK kill chains, IoCs, detection gaps, purple-team test cases |
| `appsec-threat-delta` | `TD-` | Prior report vs current state: RESOLVED / PARTIALLY FIXED / STILL PRESENT / REGRESSED / NEW |
| `appsec-verify-fix` | `VF-` | Single-finding verification: REMEDIATED / PARTIALLY FIXED / STILL PRESENT / REGRESSED |

All agents are available in Claude Code (cloud), OpenAI, LM Studio (local), GitHub Copilot Chat, Microsoft Teams, and AGENTS.md-compatible tools.

---

## Read-Only Safety Boundaries

All agents do not alter source files, install dependencies, stage changes, or create commits. Word document output is handled by the calling command (Claude Code) or by the agent itself running the converter script (Codex) — not by modifying any source file.

| Agent | Permitted shell commands |
| --- | --- |
| Threat modeler | `git log`, `git show`, `git ls-files`, `git status`, `find`, `grep`, `cat`, `head`, `wc`, `ls` |
| Code reviewer | Same as above plus `git diff`, `git blame` |
| Dependency auditor | Same as code reviewer |
| Secrets scanner | Same as code reviewer |
| IaC reviewer | Same as code reviewer |
| CI/CD auditor | Same as code reviewer |
| API security reviewer | Same as code reviewer |
| Auth reviewer | Same as code reviewer |
| False positive reviewer | Same as code reviewer |
| Compliance checker | Same as code reviewer |
| Attack tree | Same as code reviewer |
| Red team | Same as code reviewer |
| Threat delta | Same as code reviewer |
| Verify fix | Same as code reviewer |

`Write` and `Edit` are explicitly denied for Claude Code agents. For Codex, the same constraint is stated directly in `AGENTS.md`.

---

## GitHub Actions

All workflows support three AI providers. Choose the one that fits your team.

| Provider | Authentication | Analysis depth |
| --- | --- | --- |
| `claude` (default) | `ANTHROPIC_API_KEY` secret | Fully agentic — reads any file, follows call chains, browses the whole codebase |
| `openai` | `OPENAI_API_KEY` secret | Prompt-based — receives a curated snapshot as static context |
| `github-models` | `GITHUB_TOKEN` (built-in, no extra secret) | Same as OpenAI; uses the GitHub Models API endpoint |

| Workflow | Trigger | Purpose |
| --- | --- | --- |
| `appsec-pr-review.yml` | Non-draft PRs from same-repo branches | Security code review + PR comment + SARIF upload + GitHub issues |
| `appsec-threat-model.yml` | Manual Actions dispatch | Threat model + SARIF upload + GitHub issues |
| `appsec-scheduled.yml` | Weekly (Monday 06:00 UTC) + IaC/Dockerfile push to main | Automated threat model + issues |
| `appsec-dependency-audit.yml` | Push/PR touching manifests or lockfiles | Dependency supply chain audit + issues |
| `appsec-iac-review.yml` | Push/PR touching Terraform, K8s, or Dockerfile | IaC security review + issues |

### PR Comment

On every analyzed PR, the workflow posts a summary comment with: risk level, per-severity finding counts (CONFIRMED / PLAUSIBLE / THEORETICAL), top 5 issues, and merge recommendation (BLOCK / MERGE WITH ACTION / MERGE).

### GitHub Code Scanning (SARIF)

All workflows convert the report to SARIF 2.1.0 and upload to GitHub Code Scanning. Findings appear in the Security tab, inline in PR diffs, and in the repository's code scanning alerts.

### GitHub Issues for Findings

After each analysis, the workflow opens one GitHub issue per qualifying finding:
- Severity at or above the threshold (`APPSEC_MIN_ISSUE_SEVERITY` variable, default: **HIGH**)
- Confidence is **CONFIRMED** or **PLAUSIBLE** — THEORETICAL findings are skipped
- No existing open issue with the same finding ID (deduplicated by title search)

Each issue gets `security` and `severity:<level>` labels and includes the full finding block with evidence, exploit path, Remediation Guidance, and a link to the workflow run.

Fork pull requests are skipped to prevent secret exposure. See [docs/github-actions.md](docs/github-actions.md) for full setup and troubleshooting.

---

## Suggested Team Workflows

**Before implementation** — run `/threat-model` on the design or initial feature slice. Convert high-priority mitigations into acceptance criteria and record scope and residual risks with the design decision.

**Before merge** — run `/security-review`. Resolve BLOCK-level findings, document accepted residual risk, and run the recommended test cases before merging.

**Before release** — run `/threat-model` on production-facing paths. Use `/threat-model-deep` for high-value or regulated components. Compare with the original threat model to surface risk added during implementation.

**Air-gapped or confidential repos** — use `/threat-model-local` and `/security-review-local` so analysis runs entirely on-device with no data leaving the machine.

**Supply chain and infrastructure checks** — run `/dependency-audit` when adding or updating packages. Run `/iac-review` and `/cicd-audit` when changing Terraform, Kubernetes, or workflow files. Run `/secrets-scan` before committing sensitive configuration changes or onboarding new contributors.

---

## Customization

Agent instruction files are Markdown. Edit them to fit your environment:

- Add required security standards (ASVS, internal policies, compliance controls).
- Add organization-specific data classifications, asset names, and sensitivity tiers.
- Add approved authentication, logging, secrets-management, and deployment patterns.
- Add a severity taxonomy and escalation path matching your incident process.
- Add exclusions for generated code, third-party code, or non-production environments.

Keep each customization focused. Add instructions that improve scope or analysis quality — not instructions that turn the agents into code-generation or deployment agents.

---

## Repository Layout

```text
.
├── AGENTS.md                                         ← Codex / AGENTS.md-compatible tools (all 14 agents)
├── CLAUDE.md                                         ← Claude Code routing for this project
├── LICENSE
├── .claude
│   ├── agents
│   │   ├── appsec-threat-modeler.md                 ← Threat modeling agent
│   │   ├── appsec-code-reviewer.md                  ← Code review agent
│   │   ├── appsec-dependency-auditor.md             ← Supply chain audit agent
│   │   ├── appsec-secrets-scanner.md                ← Secrets detection agent
│   │   ├── appsec-iac-reviewer.md                   ← IaC security agent
│   │   ├── appsec-cicd-auditor.md                   ← CI/CD audit agent
│   │   ├── appsec-api-security-reviewer.md          ← OWASP API Security agent
│   │   ├── appsec-auth-reviewer.md                  ← Auth/authz deep-dive agent
│   │   ├── appsec-fp-reviewer.md                    ← False positive triage agent
│   │   ├── appsec-compliance-checker.md             ← Compliance mapping agent
│   │   ├── appsec-attack-tree.md                    ← AND/OR attack tree agent
│   │   ├── appsec-red-team.md                       ← Red team scenario agent
│   │   ├── appsec-threat-delta.md                   ← Report delta comparison agent
│   │   └── appsec-verify-fix.md                     ← Fix verification agent
│   ├── commands
│   │   ├── threat-model.md                          ← /threat-model (cloud)
│   │   ├── threat-model-deep.md                     ← /threat-model-deep (cloud)
│   │   ├── threat-model-local.md                    ← /threat-model-local (LM Studio)
│   │   ├── threat-model-deep-local.md               ← /threat-model-deep-local (LM Studio)
│   │   ├── security-review.md                       ← /security-review (cloud)
│   │   ├── security-review-local.md                 ← /security-review-local (LM Studio)
│   │   ├── dependency-audit.md                      ← /dependency-audit (cloud)
│   │   ├── dependency-audit-local.md                ← /dependency-audit-local (LM Studio)
│   │   ├── secrets-scan.md                          ← /secrets-scan (cloud)
│   │   ├── secrets-scan-local.md                    ← /secrets-scan-local (LM Studio)
│   │   ├── iac-review.md                            ← /iac-review (cloud)
│   │   ├── iac-review-local.md                      ← /iac-review-local (LM Studio)
│   │   ├── cicd-audit.md                            ← /cicd-audit (cloud)
│   │   ├── cicd-audit-local.md                      ← /cicd-audit-local (LM Studio)
│   │   ├── api-security-review.md                   ← /api-security-review (cloud)
│   │   ├── api-security-review-local.md             ← /api-security-review-local (LM Studio)
│   │   ├── auth-review.md                           ← /auth-review (cloud)
│   │   ├── auth-review-local.md                     ← /auth-review-local (LM Studio)
│   │   ├── compliance-check.md                      ← /compliance-check (cloud)
│   │   ├── attack-tree.md                           ← /attack-tree (cloud)
│   │   ├── attack-tree-local.md                     ← /attack-tree-local (LM Studio)
│   │   ├── red-team.md                              ← /red-team (cloud)
│   │   ├── red-team-local.md                        ← /red-team-local (LM Studio)
│   │   ├── threat-delta.md                          ← /threat-delta (cloud)
│   │   └── verify-fix.md                            ← /verify-fix (cloud)
│   ├── hooks
│   │   └── pre-commit                               ← Optional git hook: blocks staged secrets
│   └── scripts
│       └── md_to_docx.py                            ← Markdown → Word converter
├── .github
│   ├── agents
│   │   ├── appsec-threat-modeler.agent.md           ← Copilot Chat threat modeling agent
│   │   ├── appsec-code-reviewer.agent.md            ← Copilot Chat code review agent
│   │   ├── appsec-dependency-auditor.agent.md       ← Copilot Chat dependency audit agent
│   │   ├── appsec-secrets-scanner.agent.md          ← Copilot Chat secrets scanner agent
│   │   ├── appsec-iac-reviewer.agent.md             ← Copilot Chat IaC review agent
│   │   ├── appsec-cicd-auditor.agent.md             ← Copilot Chat CI/CD audit agent
│   │   ├── appsec-api-security-reviewer.agent.md   ← Copilot Chat API security agent
│   │   ├── appsec-auth-reviewer.agent.md            ← Copilot Chat auth review agent
│   │   ├── appsec-fp-reviewer.agent.md              ← Copilot Chat false positive reviewer
│   │   ├── appsec-compliance-checker.agent.md       ← Copilot Chat compliance checker
│   │   ├── appsec-attack-tree.agent.md              ← Copilot Chat attack tree agent
│   │   ├── appsec-red-team.agent.md                 ← Copilot Chat red team agent
│   │   ├── appsec-threat-delta.agent.md             ← Copilot Chat threat delta agent
│   │   └── appsec-verify-fix.agent.md               ← Copilot Chat fix verifier
│   ├── prompts
│   │   ├── discover-application-threat-model.prompt.md
│   │   └── threat-model-report.prompt.md
│   ├── scripts
│   │   ├── appsec_api.py                            ← OpenAI / GitHub Models / LM Studio runner
│   │   ├── create_issues.py                         ← Findings → GitHub issues
│   │   ├── to_sarif.py                              ← Report → SARIF 2.1.0 (Code Scanning)
│   │   └── post_pr_comment.py                       ← Posts PR summary comment
│   └── workflows
│       ├── appsec-pr-review.yml                     ← PR security review
│       ├── appsec-threat-model.yml                  ← Manual threat model
│       ├── appsec-scheduled.yml                     ← Weekly automated threat model
│       ├── appsec-dependency-audit.yml              ← Manifest-triggered dependency audit
│       └── appsec-iac-review.yml                    ← IaC-triggered infrastructure review
├── teams-app
│   ├── bot.js                                       ← Teams bot (Node.js + Bot Framework)
│   ├── manifest.json                                ← Teams app manifest
│   └── package.json                                 ← Bot dependencies
├── web
│   ├── server.js                                    ← Web UI backend (Express + WebSocket)
│   ├── public/index.html                            ← Web UI frontend
│   └── tests/                                       ← Node.js test suite
├── docs
│   ├── agents.md                                    ← Per-agent documentation for all 14 agents
│   └── github-actions.md                            ← Provider setup and Actions troubleshooting
└── README.md

# Installed globally on each user's machine (not in any repo):
~/.claude/scripts/md_to_docx.py                      ← Markdown-to-Word converter
~/.claude/scripts/appsec_api.py                      ← Local-model analysis runner (LM Studio)
~/.claude/agents/                                    ← Global Claude Code agents (optional)
~/.claude/commands/                                  ← Global Claude Code commands (optional)
~/.codex/AGENTS.md                                   ← Global Codex instructions (optional)
```

---

## Troubleshooting

### Commands do not appear in the `/` picker

1. Confirm command files are in `.claude/commands/` (project) or `~/.claude/commands/` (global).
2. Commands in a project directory are only available when Claude Code is opened from that directory root.
3. For availability across all projects without per-repo imports, use the global path `~/.claude/commands/`.
4. Restart Claude Code after adding command files.

### Agents do not appear in the `@` picker

1. Confirm agent files are in `.claude/agents/` (project) or `~/.claude/agents/` (global).
2. Start Claude Code from the repository root.
3. Restart the session if the directory was added while Claude Code was already running.

### Word document is not saved — command completes but no .docx appears

The commands require both the converter script and the python-docx library. Check both:

```bash
ls -l ~/.claude/scripts/md_to_docx.py
python3 -c "import docx; print('ok')"
```

If either is missing:

```bash
pip3 install python-docx
mkdir -p ~/.claude/scripts
cp /path/to/threatlint/.claude/scripts/md_to_docx.py ~/.claude/scripts/
```

Test the converter directly (expected output: `Usage: md_to_docx.py <input.md> <output.docx>`):

```bash
python3 ~/.claude/scripts/md_to_docx.py
```

### Local model commands fail — LM Studio not reachable

Verify LM Studio is running:

```bash
curl -s http://localhost:1234/v1/models
```

If the command fails or returns an empty list:
1. Open LM Studio.
2. Load a model from the Discover or My Models tab.
3. Go to Developer → Local Server → Start Server.
4. Retry the curl command — it should now return the loaded model's ID.

If LM Studio runs on a non-default port, set `LMSTUDIO_BASE_URL`:

```bash
export LMSTUDIO_BASE_URL=http://localhost:5678/v1
```

### Local model commands fail — appsec_api.py not found

The local-model commands require `~/.claude/scripts/appsec_api.py`:

```bash
ls -l ~/.claude/scripts/appsec_api.py
```

If missing:

```bash
mkdir -p ~/.claude/scripts
cp /path/to/threatlint/.github/scripts/appsec_api.py ~/.claude/scripts/
pip3 install openai
```

### Analysis runs but no Word document (agents invoked directly, not via command)

Using `@appsec-threat-modeler` or `claude --agent appsec-threat-modeler` runs the agent directly. The agent produces the report in chat but does not save a file — that step is owned by the commands. Use `/threat-model` or `/security-review` instead.

### Codex does not follow the analysis instructions

1. Confirm `AGENTS.md` is present at the repository root or the global path.
2. The file must be plain Markdown — no YAML frontmatter.
3. If appending to an existing `AGENTS.md`, ensure there is no conflicting instruction that overrides the security analysis sections.

### Copilot Chat agents or prompts do not appear

1. Confirm VS Code opened the repository root.
2. Confirm files are under `.github/agents/` and `.github/prompts/`.
3. Reload the VS Code window after adding files.
4. Confirm GitHub Copilot Chat is enabled and the workspace is trusted.

### The report lacks evidence or is too generic

Give the agent the relevant files, paths, diff, or architecture details. It marks missing information as an assumption or unknown rather than inventing implementation details. For a more exhaustive review, use `/threat-model-deep` or `/threat-model-deep-local`. Local models with fewer than 7B parameters may produce shorter, less detailed reports — try a larger model in LM Studio if output quality is insufficient.

### A finding needs confirmation

Use the per-finding Validation step, inspect deployed configuration, and reproduce the attacker path in an authorized test environment. Treat the report as a high-signal review artifact, not automatic proof of exploitability.

### GitHub Actions

See [docs/github-actions.md](docs/github-actions.md) for the full troubleshooting table covering provider authentication, issue creation, and workflow triggers.

Key points:
- Provider is set via the `APPSEC_PROVIDER` repository variable (PR review) or the dispatch input (threat model). No workflow edit is needed to switch.
- `github-models` requires no extra secret — the built-in `GITHUB_TOKEN` is sufficient.
- If no issues are created after a run, open the workflow log and check the **Create GitHub issues for findings** step — it reports the count of parsed findings, each skip reason, and any API errors.
- Issues are deduplicated by finding ID. A finding that already has an open issue will not create a second one.
