```
TTTTT H   H RRRR  EEEEE  AAA  TTTTT L     IIIII N   N TTTTT
  T   H   H R   R E     A   A   T   L       I   NN  N   T
  T   HHHHH RRRR  EEEE  AAAAA   T   L       I   N N N   T
  T   H   H R R   E     A   A   T   L       I   N  NN   T
  T   H   H R  RR EEEEE A   A   T   LLLLL IIIII N   N   T
```

# threatlint

`threatlint` provides application security agents for threat modeling and security code review. It supports Claude Code (via subagents and slash commands), Codex CLI and other AGENTS.md-compatible tools (via `AGENTS.md`), and GitHub Copilot Chat (via `.github/` customizations). Reports are saved as Word documents in the repository being analyzed.

Analysis is grounded in the inspected source and local configuration. Assumptions and unknowns are labeled explicitly rather than hidden behind generic findings.

## What Is Included

| File | Use it for |
| --- | --- |
| [`AGENTS.md`](AGENTS.md) | Cross-platform agent instructions for OpenAI Codex CLI, GitHub Copilot Coding Agent, Cursor, and any other tool that reads `AGENTS.md`. Self-contained: includes threat modeling, code review, and Word document output instructions. |
| [`.claude/agents/appsec-threat-modeler.md`](.claude/agents/appsec-threat-modeler.md) | Claude Code subagent for threat modeling with autonomous repository discovery. |
| [`.claude/agents/appsec-code-reviewer.md`](.claude/agents/appsec-code-reviewer.md) | Claude Code subagent for security review of a diff or pull request. |
| [`.claude/commands/threat-model.md`](.claude/commands/threat-model.md) | `/threat-model` slash command. Invokes the threat modeler and saves output as a Word document. **Required for Word output in Claude Code.** |
| [`.claude/commands/threat-model-deep.md`](.claude/commands/threat-model-deep.md) | `/threat-model-deep` slash command. Aggressive deep-dive with bypass chain analysis, chained kill chains, and coverage audit. |
| [`.claude/commands/security-review.md`](.claude/commands/security-review.md) | `/security-review` slash command. Reviews a diff, branch, or PR and saves output as a Word document. |
| [`CLAUDE.md`](CLAUDE.md) | Routes Claude Code to the project security subagents when working in the threatlint directory. |
| [`.github/agents/appsec-threat-modeler.agent.md`](.github/agents/appsec-threat-modeler.agent.md) | Threat-modeling agent for GitHub Copilot Chat. |
| [`.github/agents/appsec-code-reviewer.agent.md`](.github/agents/appsec-code-reviewer.agent.md) | Code review agent for GitHub Copilot Chat. |
| [`.github/prompts/discover-application-threat-model.prompt.md`](.github/prompts/discover-application-threat-model.prompt.md) | Slash prompt for discovery-mode threat modeling in Copilot Chat. |
| [`.github/prompts/threat-model-report.prompt.md`](.github/prompts/threat-model-report.prompt.md) | Slash prompt for standardized threat-model reports in Copilot Chat. |
| [`.github/scripts/appsec_api.py`](.github/scripts/appsec_api.py) | Analysis runner for OpenAI and GitHub Models providers in Actions. |
| [`.github/scripts/create_issues.py`](.github/scripts/create_issues.py) | Parses a completed report and opens GitHub issues for qualifying findings. |
| [`docs/github-actions.md`](docs/github-actions.md) | Provider setup, issue filing configuration, and troubleshooting for GitHub Actions. |

### Word Document Converter

`~/.claude/scripts/md_to_docx.py` is a helper script used by the Claude Code skills and Codex agents to convert the markdown report to a formatted `.docx` file. It is installed to the user's home directory — not checked into target repositories. See [Word Document Output](#word-document-output) for setup.

---

## Requirements

**For Claude Code:**
- Claude Code CLI or IDE extension
- Python 3 + python-docx: `pip3 install python-docx` (required for Word document output)
- `~/.claude/scripts/md_to_docx.py` installed (see [Word Document Output](#word-document-output))

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
/threat-model                    # auto-discover the repo and threat model it
/threat-model src/api/auth       # threat model a specific component
/threat-model-deep               # aggressive deep-dive (maximum coverage)
/security-review                 # review the current working-tree diff
/security-review main..feature   # review a branch
/security-review 42              # review PR #42
```

You can also address the agents directly via the `@` picker or `--agent` flag:

```bash
claude --agent appsec-threat-modeler   # threat modeling session
claude --agent appsec-code-reviewer    # code review session
```

Using `@` or `--agent` directly produces the report in chat but **does not save a Word document** — that step is handled by the skills. Use the slash commands when you need file output.

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

The `.github/agents/` files register two custom agents in Copilot Chat. The `.github/prompts/` files register two slash commands. Both the agents and the prompts are available as soon as the repository is open in a trusted VS Code workspace.

### Agents

Open Copilot Chat and select an agent from the agent picker (the `@` icon or the model selector):

- **AppSec Threat Modeler** — threat model a component, feature, or the entire repository.
- **AppSec Code Reviewer** — security review a pull request, diff, or set of changed files.

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

### Installing Copilot Chat Agents in Another Repository

Copy the `.github/` files into the target repository and commit them:

```bash
cd /path/to/your-repo
mkdir -p .github/agents .github/prompts

cp /path/to/threatlint/.github/agents/appsec-threat-modeler.agent.md .github/agents/
cp /path/to/threatlint/.github/agents/appsec-code-reviewer.agent.md .github/agents/
cp /path/to/threatlint/.github/prompts/discover-application-threat-model.prompt.md .github/prompts/
cp /path/to/threatlint/.github/prompts/threat-model-report.prompt.md .github/prompts/

git add .github
git commit -m "Add threatlint Copilot Chat security agents and prompts"
```

There is no global equivalent for Copilot Chat agents — the `.github/` files must be present in the repository that VS Code has open as its workspace root. After committing, reload the VS Code window once to pick up the new agents and prompts.

---

## Installing on Another Repository

There are four installation paths depending on tool and scope. **Agents alone are not sufficient for Word document output in Claude Code** — the skills are what wire up the conversion pipeline.

---

### Claude Code — Global (No Per-Repo Import Required)

Agents and skills installed globally are available in every repository you open. **This is already done** on this machine. For a fresh setup:

```bash
mkdir -p ~/.claude/agents
cp /path/to/threatlint/.claude/agents/appsec-threat-modeler.md ~/.claude/agents/
cp /path/to/threatlint/.claude/agents/appsec-code-reviewer.md ~/.claude/agents/

mkdir -p ~/.claude/commands
cp /path/to/threatlint/.claude/commands/threat-model.md ~/.claude/commands/
cp /path/to/threatlint/.claude/commands/threat-model-deep.md ~/.claude/commands/
cp /path/to/threatlint/.claude/commands/security-review.md ~/.claude/commands/

mkdir -p ~/.claude/scripts
cp /path/to/threatlint/.claude/scripts/md_to_docx.py ~/.claude/scripts/
pip3 install python-docx
```

Open any repository in Claude Code. No further setup is needed. `/threat-model`, `/threat-model-deep`, and `/security-review` appear in the `/` picker and write `.docx` output to the repo root.

---

### Claude Code — Per-Repository (Team Use)

Check the files into the target repository so every teammate gets the agents and commands when they open the repo.

```bash
cd /path/to/your-repo

mkdir -p .claude/agents .claude/commands

cp /path/to/threatlint/.claude/agents/appsec-threat-modeler.md .claude/agents/
cp /path/to/threatlint/.claude/agents/appsec-code-reviewer.md .claude/agents/

cp /path/to/threatlint/.claude/commands/threat-model.md .claude/commands/
cp /path/to/threatlint/.claude/commands/threat-model-deep.md .claude/commands/
cp /path/to/threatlint/.claude/commands/security-review.md .claude/commands/

cat >> CLAUDE.md << 'EOF'

## Security Analysis

- Delegate threat-modeling requests to `appsec-threat-modeler`.
- Delegate security reviews of diffs and risky configuration changes to `appsec-code-reviewer`.
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
| `.claude/agents/` only | `/threat-model` etc. appear in the skill picker; analysis runs; **no Word document is saved** |
| `.claude/agents/` + `.claude/commands/` | Full pipeline: analysis runs and `.docx` is saved to the repo root |
| `CLAUDE.md` routing | Claude Code automatically routes security requests to the right agent without needing `@` |
| Personal: `md_to_docx.py` + `python-docx` | Required for the skills to write the `.docx` file |

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

### Verifying Any Installation

1. **Claude Code**: type `@` — `appsec-threat-modeler` and `appsec-code-reviewer` should appear. Type `/` — `threat-model`, `threat-model-deep`, and `security-review` should appear.
2. **Codex**: confirm `AGENTS.md` is present at the repo root or the global path. Ask the agent to "threat model this repository" — it should begin discovery immediately.
3. **GitHub Copilot Chat**: type `@` in the Copilot Chat input — `AppSec Threat Modeler` and `AppSec Code Reviewer` should appear. Type `/` — `Discover Application Threat Model` and `Threat Model Report` should appear. Requires the `.github/agents/` and `.github/prompts/` files to be present in the open workspace.
4. **End-to-end (Claude Code / Codex)**: run `/threat-model` (Claude Code) or ask for a threat model (Codex) with no arguments. A `threat-model-YYYY-MM-DD.docx` should appear in the current directory when the report completes.

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

This is a one-time personal setup. The script lives in `~/.claude/scripts/` and is referenced by both the Claude Code skills and the Codex `AGENTS.md` instructions.

### Output Locations and Filenames

| Invocation | Filename | Directory |
| --- | --- | --- |
| `/threat-model` | `threat-model-YYYY-MM-DD.docx` | Current working directory |
| `/threat-model src/auth` | `threat-model-src-auth-YYYY-MM-DD.docx` | Current working directory |
| `/threat-model-deep` | `threat-model-deep-YYYY-MM-DD.docx` | Current working directory |
| `/security-review` | `security-review-YYYY-MM-DD.docx` | Repository root |
| `/security-review main..feature` | `security-review-main-feature-YYYY-MM-DD.docx` | Repository root |
| `/security-review 42` | `security-review-pr42-YYYY-MM-DD.docx` | Repository root |

Codex follows the same filename and directory conventions defined in `AGENTS.md`.

**Copilot Chat does not save Word documents.** Reports stay in the chat window. Use Claude Code skills or Codex when a `.docx` file is required.

### What the Converter Handles

The converter (`md_to_docx.py`) renders the full report structure:
- H1–H4 headings with colour coding (navy → blue → green → near-black)
- Finding summary tables and finding detail tables
- Fenced code blocks in monospace (remediation snippets, shell commands)
- Bullet and numbered lists (attack steps, remediation steps)
- Bold, italic, and inline-code runs
- Horizontal rules as styled section separators

If the converter is not installed, the skills fall back to saving the report as a `.md` file and note the missing dependency.

---

## Analysis Posture

Both agents use an **aggressive-by-default** posture. The same posture is encoded in `AGENTS.md` for Codex.

- Borderline THEORETICAL/PLAUSIBLE findings are escalated to PLAUSIBLE when the preconditions are realistic for a production deployment.
- Every defensive control — authentication, authorization, input validation, rate limiting — is examined for bypass paths. A clean result is stated explicitly, not silently omitted.
- Low-severity findings that enable higher-severity ones are combined into chained attack scenarios.
- Source code, configuration, and documentation are all treated as known to the attacker. "Requires internals knowledge" is not a downgrade reason.
- An attack path is only excluded if a defensive control is verifiably correct in the reviewed code, or the prerequisite is architecturally impossible.

Use `/threat-model-deep` for maximum coverage: additionally requires bypass chain analysis per control, multi-step kill chains, per-category breadth coverage, and a runtime blindspot inventory.

---

## Start Without Application Context

Run `/threat-model` with no arguments (Claude Code), ask "threat model this repository" (Codex), or type `/Discover Application Threat Model` in Copilot Chat. The agent:

1. Inventories documentation, manifests, source roots, Dockerfiles, IaC, and CI/CD workflows.
2. Maps entry points, trust boundaries, identities, sensitive data, and privileged operations.
3. Ranks candidate scopes by external exposure, privilege level, sensitive-data handling, and blast radius.
4. Selects the highest-risk representative scope, explains the selection with evidence, and begins the full threat model immediately.

The report ends with **Suggested Focused Follow-Ups**: three to five ready-to-send prompts naming specific discovered components and asking narrow, high-value security questions.

---

## AppSec Threat Modeler

Use before implementation, before a release, after an architectural change, or while investigating an application-security concern.

**Claude Code:** `/threat-model [target]` or `/threat-model-deep [target]` or `@appsec-threat-modeler`  
**Codex:** ask naturally — "threat model src/api/auth", "analyze this service for injection risks"  
**Copilot Chat:** `@AppSec Threat Modeler` from the agent picker, or `/Discover Application Threat Model` / `/Threat Model Report` slash prompts

### Review Scope

- Application source code and nearby implementation context.
- HTTP, CLI, event, queue, file, and other entry points.
- Authentication, authorization, tenancy, secrets, and privilege transitions.
- Sensitive data flows, persistence, external services, dependency boundaries.
- IaC, CI/CD workflows, deployment controls, and dependency manifests.

### Report Contents

1. Document header: repository name, date, scope.
2. Tier 1 executive summary: risk posture, finding summary table (CONFIRMED / PLAUSIBLE / THEORETICAL), top immediate actions, compliance exposure, recommended next step.
3. Tier 2 technical threat model: discovery and scope selection, system model, full threat register with STRIDE / OWASP / CWE, prioritized remediation roadmap, residual risk.
4. Per-finding **Remediation Guidance**: numbered steps, before/after code snippets, specific library/API references, follow-up hardening.
5. Per-finding **Validation**: a curl command, unit test, or manual check that confirms the fix.
6. Suggested Focused Follow-Ups.

### Example Prompts

```text
/threat-model src/auth
```

```text
/threat-model-deep services/media
Threat-model the file-upload API. Focus on tenant isolation,
malicious file payloads, signed URLs, and the object-storage policy.
```

```text
Threat-model the payment webhook handler and its Terraform resources.
```

---

## AppSec Code Reviewer

Use when a change exists and the question is whether it introduces a security regression.

**Claude Code:** `/security-review [diff target]` or `@appsec-code-reviewer`  
**Codex:** ask naturally — "security review the current diff", "review PR #42 for auth bypasses"  
**Copilot Chat:** `@AppSec Code Reviewer` from the agent picker

### Targeting the Review

```text
/security-review                    # working-tree diff (staged + unstaged)
/security-review main..feature/x    # branch comparison
/security-review abc123..def456     # commit range
/security-review 42                 # pull request number (uses gh pr diff)
/security-review -- src/api/billing # path-scoped diff
```

### Report Contents

1. Document header: repository name, date, change identifier.
2. Tier 1 executive summary: change risk level, finding summary, top issues, merge recommendation (BLOCK / MERGE WITH ACTION / MERGE).
3. Tier 2 technical review: review scope, findings with exploit paths and evidence, security-positive changes, residual risk.
4. Per-finding **Remediation Guidance**: exact lines to change, before/after snippets, library references, follow-up actions.
5. Per-finding **Test Case**: reproduction payload, curl command, or unit test for both the vulnerability and the fix.

---

## Read-Only Safety Boundaries

Both agents do not alter source files, install dependencies, stage changes, or create commits. Word document output is handled by the calling skill (Claude Code) or by the agent itself running the converter script (Codex) — not by modifying any source file.

| Agent | Permitted shell commands |
| --- | --- |
| Threat modeler | `git log`, `git show`, `git ls-files`, `git status`, `find`, `grep`, `cat`, `head`, `wc`, `ls` |
| Code reviewer | Same as above plus `git diff`, `git blame` |

`Write` and `Edit` are explicitly denied for Claude Code agents. For Codex, the same constraint is stated directly in `AGENTS.md`.

---

## GitHub Actions

Both workflows support three AI providers. Choose the one that fits your team.

| Provider | How it authenticates | Analysis depth |
| --- | --- | --- |
| `claude` (default) | `ANTHROPIC_API_KEY` secret | Fully agentic — reads any file, follows call chains, browses the whole codebase |
| `openai` | `OPENAI_API_KEY` secret | Prompt-based — receives the diff or a curated snapshot as static context |
| `github-models` | `GITHUB_TOKEN` (built-in, no secret needed) | Same as OpenAI; uses the GitHub Models API endpoint |

| Workflow | Trigger | Provider selection | Output |
| --- | --- | --- | --- |
| [AppSec PR Review](.github/workflows/appsec-pr-review.yml) | Non-draft pull requests from same-repo branches | `APPSEC_PROVIDER` repository variable (default `claude`) | Workflow run log + GitHub issues |
| [AppSec Threat Model](.github/workflows/appsec-threat-model.yml) | Manual Actions-tab run | Dispatch input (default `claude`) | Workflow run log + GitHub issues |

### GitHub Issues for Findings

After each analysis, the workflow automatically opens one GitHub issue per qualifying finding. Findings are filtered before filing:

- Severity at or above the threshold (`APPSEC_MIN_ISSUE_SEVERITY` variable for PR review, or the dispatch input for threat model; default: **HIGH**)
- Confidence is **CONFIRMED** or **PLAUSIBLE** — THEORETICAL findings are skipped
- No existing open issue with the same finding ID already exists (deduplication by title search)

Each issue gets `security` and `severity:<level>` labels (created automatically if absent) and includes the full finding block — evidence, exploit path, Remediation Guidance, and a link to the workflow run.

Fork pull requests are intentionally skipped to prevent secret exposure. See [docs/github-actions.md](docs/github-actions.md) for full setup, provider configuration, and troubleshooting.

---

## Suggested Team Workflows

**Before implementation** — run `/threat-model` on the design or initial feature slice. Convert high-priority mitigations into acceptance criteria and record scope and residual risks with the design decision.

**Before merge** — run `/security-review`. Resolve BLOCK-level findings, document accepted residual risk, and run the recommended test cases before merging.

**Before release** — run `/threat-model` on production-facing paths. Use `/threat-model-deep` for high-value or regulated components. Compare with the original threat model to surface risk added during implementation.

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
├── AGENTS.md                                  ← Codex / AGENTS.md-compatible tools
├── CLAUDE.md                                  ← Claude Code routing (threatlint project)
├── .claude
│   ├── agents
│   │   ├── appsec-code-reviewer.md            ← Claude Code security review agent
│   │   └── appsec-threat-modeler.md           ← Claude Code threat modeling agent
│   └── commands
│       ├── security-review.md                 ← /security-review (+ Word output)
│       ├── threat-model.md                    ← /threat-model (+ Word output)
│       └── threat-model-deep.md               ← /threat-model-deep (+ Word output)
├── .github
│   ├── agents
│   │   ├── appsec-code-reviewer.agent.md      ← Copilot Chat code review agent
│   │   └── appsec-threat-modeler.agent.md     ← Copilot Chat threat modeling agent
│   ├── prompts
│   │   ├── discover-application-threat-model.prompt.md
│   │   └── threat-model-report.prompt.md
│   ├── scripts
│   │   ├── appsec_api.py                      ← OpenAI / GitHub Models analysis runner
│   │   └── create_issues.py                   ← Findings → GitHub issues
│   └── workflows
│       ├── appsec-pr-review.yml
│       └── appsec-threat-model.yml
├── docs
│   └── github-actions.md
└── README.md

# Installed globally on each user's machine (not in any repo):
~/.claude/scripts/md_to_docx.py               ← Markdown-to-Word converter
~/.claude/agents/                              ← Global Claude Code agents (optional)
~/.claude/commands/                              ← Global Claude Code commands (optional)
~/.codex/AGENTS.md                             ← Global Codex instructions (optional)
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

### Word document is not saved — skill completes but no .docx appears

The skills require both the converter script and the python-docx library. Check both:

Verify the converter exists and python-docx is installed:

```bash
ls -l ~/.claude/scripts/md_to_docx.py
python3 -c "import docx; print('ok')"
```

If either is missing, install them:

```bash
pip3 install python-docx
mkdir -p ~/.claude/scripts
cp /path/to/threatlint/.claude/scripts/md_to_docx.py ~/.claude/scripts/
```

Test the converter directly (expected output: `Usage: md_to_docx.py <input.md> <output.docx>`):

```bash
python3 ~/.claude/scripts/md_to_docx.py
```

### Analysis runs but no Word document (agents invoked directly, not via skill)

Using `@appsec-threat-modeler` or `claude --agent appsec-threat-modeler` runs the agent directly. The agent produces the report in chat but does not save a file — that step is owned by the skills. Use `/threat-model` or `/security-review` instead.

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

Give the agent the relevant files, paths, diff, or architecture details. It marks missing information as an assumption or unknown rather than inventing implementation details. For a more exhaustive review, use `/threat-model-deep`.

### A finding needs confirmation

Use the per-finding Validation step, inspect deployed configuration, and reproduce the attacker path in an authorized test environment. Treat the report as a high-signal review artifact, not automatic proof of exploitability.

### GitHub Actions

See [docs/github-actions.md](docs/github-actions.md) for the full troubleshooting table covering provider authentication, issue creation, and workflow triggers.

Key points:
- Provider is set via the `APPSEC_PROVIDER` repository variable (PR review) or the dispatch input (threat model). No workflow edit is needed to switch.
- `github-models` requires no extra secret — the built-in `GITHUB_TOKEN` is sufficient.
- If no issues are created after a run, open the workflow log and check the **Create GitHub issues for findings** step — it reports the count of parsed findings, each skip reason, and any API errors.
- Issues are deduplicated by finding ID. A finding that already has an open issue will not create a second one.
