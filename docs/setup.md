# Get your first useful review

Security tooling earns its place when it helps you decide what to do next.
Choose the workflow you already use; you do not need to configure every integration.

**Start here:** Python 3.9+ for the CLI, Node.js 22+ for the Workbench.
Provider accounts are needed only for the provider you choose. Source-control,
ServiceNow, and Semgrep credentials are needed only for their integrations.

## Install from this checkout

```bash
git clone https://github.com/h0p3sf4ll/threatlint.git
cd threatlint
python3 -m pip install -e .
threatlint --help
```

Use the same Python environment for installation and execution. If `threatlint`
is not on your path, try `python3 -m threatlint --help`.

## Choose your workspace

| You work in | Next step | First useful result |
| --- | --- | --- |
| Browser or desktop | [Workbench guide](workbench.md) | Open a repository and run a review playbook |
| Claude Code | Install below, then `/security-review` | A scoped report; commands also handle report export |
| GitHub Copilot | Install below, then choose an AppSec agent | Findings in chat, grounded in available source |
| Codex or another AGENTS.md client | Follow the AGENTS.md setup below | Repository discovery or a focused review |
| Terminal with local models | Start LM Studio, then `threatlint run` | A report without a cloud model provider |
| Pull requests | [CI templates](ci-templates.md) | A warn-first review on a test PR |
| Microsoft Teams | [Teams setup](teams.md) | Review supplied, redacted evidence in a conversation |

### Claude Code

Run from the target repository:

```bash
threatlint install --local -y
```

For your own machine-wide setup, omit `--local`. The installer copies complete
agents, commands, skills, and helper scripts together. Do not copy just one
Python script: the standalone entry points now use sibling helpers.

Restart Claude Code, then try:

```text
/security-review
/threat-model src/auth
/fp-review ./results.sarif
```

No target for `/threat-model` is required: discovery selects a source-supported
starting scope. A focused target is better when you already know the question.

**Check success:** the report names inspected files and lines, distinguishes
assumptions from evidence, and gives a next action. See [report outputs](reports.md)
for export behavior.

### GitHub Copilot

Run from the target repository:

```bash
threatlint install --copilot --local -y
```

This writes agents and complete skills under `.github/`. Omit `--local` to use the
installer's `~/.copilot/` destination; support for discovering that user-level
location depends on your client.

Open the target repository in a trusted VS Code workspace, reload the window,
and choose an AppSec agent. For example:

```text
Review the changed authentication code. Show the attacker path, evidence,
smallest effective fix, and a regression assertion.
```

The checkout also contains `.github/prompts/` for threat-model discovery and
report prompts. The Copilot installer installs agents and skills, not those
prompt files. Copy the specific prompts separately if you need them.

**Export is client-dependent.** Do not assume a chat response created a Word file.
Use the [converter](reports.md#convert-an-existing-report) when needed.

### Codex and other AGENTS.md clients

Use this repository's [AGENTS.md](../AGENTS.md) as the routing/protocol reference.
Merge the relevant instructions into your target repository's existing instructions;
do not overwrite team rules blindly.

The instructions reference packaged workflows. Keep Threatlint installed and make
the referenced skills available to your client; copying only AGENTS.md does not
copy its dependencies. Use your client's supported instruction and skill locations.

Then ask:

```text
Threat model this repository. Discover the highest-risk starting scope,
cite the evidence, and separate verified behavior from assumptions.
```

### Terminal with LM Studio

1. Install [LM Studio](https://lmstudio.ai), load a suitable instruction-following model,
   and start its local server.
2. Verify that the server lists the loaded model:

   ```bash
   curl -fsS http://localhost:1234/v1/models
   ```

3. From the repository you want reviewed:

   ```bash
   threatlint run threat-model --provider lmstudio
   threatlint run security-review --base HEAD~1 --head HEAD
   threatlint run fp-review --findings ./results.sarif
   ```

Use `--model MODEL_ID` to select a model, `--base-url URL` for another server,
and `--output-dir ./reports` for a dedicated report directory.
The direct CLI's LM Studio integration uses the Python standard library.

For Claude Code's `*-local` slash commands, run `threatlint install -y` first.
Those commands invoke the installed snapshot script, not the direct CLI's
tool-driven loop. The script accepts `LMSTUDIO_BASE_URL` and `LMSTUDIO_MODEL`.
Snapshot limits are disclosed in its prompts; local execution does not imply
complete repository coverage.

### Cloud providers

The direct CLI supports `--provider claude-code`, `--provider claude`, and `--provider openai`:

```bash
threatlint run threat-model --provider claude-code
threatlint run security-review --provider claude --base main --head HEAD
threatlint run threat-model --provider openai --output-dir ./reports
```

**`claude-code` uses your Claude Code login, so no API key is needed.** Install
[Claude Code](https://claude.com/claude-code) and run `claude` once to sign in.
Threatlint never reads the login itself. It runs the installed `claude` CLI in
headless mode (`claude -p`), which signs itself in. Because the repository under
review is untrusted, every run is locked down:

- **Restricted mode** (`--restricted`) removes every command- or code-running
  tool. It also ignores user, project, and local settings files, so a scanned
  repository's `.claude/settings.json` hooks never run.
- **Read-only tools:** only `Read`, `Grep`, and `Glob` are available, confined to
  the repository, and nothing else is allowed.
- **No extras:** no MCP servers and no saved session history.
- **Login only:** `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` are removed from
  the run, so it bills your Claude Code plan rather than a key.

Runs time out after an hour; set `THREATLINT_CLAUDE_CODE_TIMEOUT_S` to change that.

For `claude` and `openai`, provide `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` through your shell or secret store.
Avoid putting keys in command history with `--api-key`. Source and supplied
evidence sent to a cloud model leave your machine; choose a provider permitted
for that repository.

## Models

For Claude, the current scanning and general-assistance defaults are both
`claude-opus-5-5`. The policy lives in [models.py](../src/threatlint/models.py)
and [model-policy.cjs](../web/lib/model-policy.cjs).

Override with an explicit run setting, or configure:

| Setting | Environment variable | `org.json` key |
| --- | --- | --- |
| Security analysis | `THREATLINT_SCAN_MODEL` | `scanModel` |
| General assistance | `THREATLINT_GENERAL_MODEL` | `generalModel` |

The file is `~/.threatlint/org.json`. Explicit run choices take precedence;
environment values take precedence over file values. Other providers retain
their own defaults. Check model access with your provider rather than assuming
an example model is available to every account.

## Troubleshooting

| Symptom | Do this next |
| --- | --- |
| CLI not found | Use the installation interpreter: `python3 -m threatlint --help` |
| No native agents or commands | Check the target client directory; restart/reload the client |
| Missing script helper after a manual copy | Re-run the installer so the complete script bundle is copied |
| LM Studio unavailable | Load a model, start the local server, and retry `/v1/models` |
| No Word file | Check [report export](reports.md#no-word-file) rather than assuming analysis failed |
| Generic findings | Narrow the question and provide the relevant source/diff; require evidence and explicit unknowns |
| AVIT credentials missing | Run `threatlint setup --check`; follow [AVIT setup](avit-integration.md) |

**Next:** choose a [specialist by outcome](agents.md), not by the size of its checklist.
