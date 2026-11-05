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

### Load shared setup settings from AWS

For a team that keeps integration credentials in AWS Systems Manager Parameter
Store, a new machine needs AWS CLI v2, an authorized AWS sign-in, and the names
of the parameters to read. Install the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
and verify `aws --version` in a new terminal before running setup.

An administrator can publish one JSON parameter containing connection settings
and references to the credential parameters. For example (replace every example
URL, organization, and parameter name with your own):

```json
{
  "snowInstance": "https://your-instance.service-now.com",
  "snowClientIdParameter": "/your-team/servicenow/client-id",
  "snowClientSecretParameter": "/your-team/servicenow/client-secret",
  "semgrepTokenParameter": "/your-team/semgrep/token",
  "semgrepDeployment": "your-deployment",
  "awsProfile": "appsec",
  "adoOrganizations": ["your-organization"],
  "adoPatParameter": "/your-team/ado/pat"
}
```

Keep credential values in the referenced parameters, using `SecureString` for
secrets; do not put them in this settings JSON. The AWS identity needs permission
to read the selected parameters and decrypt their KMS key where applicable.
Threatlint does not list or guess parameter names across the AWS account.

```powershell
threatlint setup --org-parameter /your-team/threatlint/setup --aws-region us-west-2
```

Setup signs in to AWS, loads the shared settings, and retrieves and validates the
configured ServiceNow, Azure DevOps, and Semgrep credentials. ServiceNow and
Semgrep settings are saved for the CLI and Workbench. For Azure DevOps, Threatlint
keeps only the Parameter Store reference and validates the shared service-account
PAT separately for every selected organization; it does not save a local PAT copy.
All these parameters use the selected AWS region (`us-west-2` by default).

The existing `adoPatParameter` is the authoritative ADO credential source when
configured. Runtime operations read its current value instead of using personal
environment or locally saved PATs. Lookup failures stop the operation; they do not
fall back to a personal identity. Allowed organizations come from `adoOrganizations`.
The AWS profile comes from an explicit `--aws-profile`, then `awsProfile` /
`THREATLINT_AWS_PROFILE`, then the AWS default credential chain.

To configure or migrate an existing machine, use Settings → Azure DevOps in the
Workbench, or run:

```bash
threatlint ado service-account --parameter /your-team/ado/pat --organization your-organization --aws-profile appsec --region us-west-2
threatlint ado status
```

Repeat `--organization` for additional organizations. The command validates access
before saving metadata. Existing personal PATs remain stored but are not used while
`adoPatParameter` is configured. The service account needs Code: Read & write and
repository permissions to create branches and pull requests for the proposed-fix
flow. The Workbench replaces cached personal source connections when configuration
changes and refreshes shared source credentials periodically when they are used.

`THREATLINT_ORG_PARAMETER` can supply the shared parameter name instead of the
option. Setup remembers the name and region in `~/.threatlint/org.json`
(`%USERPROFILE%\\.threatlint\\org.json` on Windows). Environment settings take
precedence over local settings; imported metadata fills missing local settings.
Remove a local override to accept that field from the shared parameter on the
next setup. A successful fresh AWS sign-in also offers a shared parameter prompt
when no integration parameter names have been configured.

AWS sign-in or shared-settings failures stop setup before integration prompts.
A configured credential lookup failure reports its cause rather than asking
you to copy secrets manually. Manual setup remains available when no parameter
references are configured. `threatlint setup --check` checks current configuration
without prompting, importing shared settings, or saving credentials.

## Choose your workspace

| You work in | Next step | First useful result |
| --- | --- | --- |
| Browser or desktop | [Workbench guide](workbench.md) | Open a repository and run a review playbook |
| Claude Code | Install below, then `/security-review` | A scoped report; commands also handle report export |
| GitHub Copilot | Install below, then choose an AppSec agent | Findings in chat, grounded in available source |
| Codex | Install below, then invoke an AppSec skill | Repository discovery or a focused review |
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

For headless AVIT or ISST write-back, install and sign in to the Copilot CLI,
then run `threatlint run fp-review --provider copilot --isst ISST0035374
--resolve-avits --yes`. This uses the same reviewer and resolver as Claude Code
and Codex; see the [AVIT workflow](avit-integration.md).

**Export is client-dependent.** Do not assume a chat response created a Word file.
Use the [converter](reports.md#convert-an-existing-report) when needed.

### Codex

This Threatlint checkout already includes repo-local Codex skill entry points.
For another repository, run from the repository you want to review:

```bash
threatlint install --codex --local -y
```

This installs the 22 AppSec agents as native Codex skills under
`.codex/skills/`. Each agent skill contains its required shared workflows and
the complete evidence and reporting instructions, so it works in a
target repository without a Threatlint source checkout. Omit `--local` to
install for your user under `~/.codex/skills/` (or `$CODEX_HOME/skills/` when
that variable is set).

Open a new Codex chat, then name the skill you want:

```text
Use $appsec-threat-modeler to threat model this repository. Discover the
highest-risk starting scope and cite the evidence.
```

Codex also uses each skill's description to decide when to load it for a
matching request. The repository's [AGENTS.md](../AGENTS.md) remains the routing
and protocol reference when working in this checkout. See the official
[Codex skill format and locations](https://developers.openai.com/blog/eval-skills)
and [AGENTS.md loading guidance](https://developers.openai.com/cookbook/examples/gpt-5/codex_prompting_guide).

For an authorized, headless ServiceNow false-positive review, use the shared
CLI with your Codex login:

```bash
threatlint setup --check
threatlint run fp-review --provider codex \
  --avit AVIT000000095938462 --resolve-avits --yes
```

Repeat `--avit` for more records. Threatlint reviews each AVIT against the
repository and branch in its record. It attaches a Word report for every
decided finding: true positives remain open; false positives close, with
Semgrep triage and proven SAST/Secrets rule tuning. SCA false positives
receive Supply Chain finding triage without rule tuning. The command uses
temporary files and prints each outcome; ServiceNow and Semgrep writes can
succeed or fail separately. Without `--resolve-avits --yes`, `--avit` produces
a report only. See the [AVIT workflow](avit-integration.md) for setup and
recovery details.

If your Codex workspace has approved Daybreak Blue access, enable the Daybreak
toggle in Codex's Advanced model picker for the request. Installing Threatlint
skills does not grant or enable that access. See [OpenAI's Daybreak overview](https://help.openai.com/en/articles/20001258-openai-daybreak-trusted-access-for-cyber-overview).

To remove this integration, run `threatlint uninstall --codex --local -y`
from the same repository (or omit `--local` for the user-level install).

### Other AGENTS.md clients

Use this repository's [AGENTS.md](../AGENTS.md) as the routing/protocol reference.
Merge the relevant instructions into your target repository's existing instructions;
make the referenced packaged workflows available through that client's supported
instruction and skill locations.

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

Choose the Claude authentication method you use: `claude-code` for your login,
`claude` for an Anthropic API key, or `bedrock` for an Amazon Bedrock API key.
The direct CLI also supports a signed-in Codex session, `openai`, and local models.

```bash
threatlint run threat-model --provider claude-code
threatlint run threat-model --provider codex
threatlint run threat-model --provider codex --daybreak-blue
threatlint run security-review --provider claude --base main --head HEAD
threatlint run threat-model --provider openai --output-dir ./reports
threatlint run threat-model --provider bedrock --bedrock-region us-east-1 --model YOUR_BEDROCK_MODEL_ID
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
  the run, along with Bedrock keys, custom Anthropic endpoints, and third-party
  provider routing flags. Settings-file provider overrides are ignored, keeping this
  option on your Claude Code login when Bedrock is also configured.

Runs time out after an hour; set `THREATLINT_CLAUDE_CODE_TIMEOUT_S` to change that.

**`codex` uses your Codex login without an API key.** Install the Codex CLI and
sign in with `codex login` or the Codex app. Threatlint checks `codex login status`,
then runs `codex exec` in a read-only, ephemeral session. It does not read
`auth.json`, extract OAuth credentials, or copy a key into the model request.
The CLI run ignores user-level configuration to reduce exposure to configured
MCP tools or hooks; its default model is Codex's built-in default unless `--model` is set.
The target repository's `AGENTS.md` is still loaded by Codex. Source and
supplied evidence remain untrusted, and Codex's read-only sandbox is the
filesystem boundary. The direct Threatlint API providers use their own
credentials; a ChatGPT-based Codex login does not expose an OpenAI API key.

For an approved Daybreak Blue account, `--daybreak-blue` adds the documented
`-c daybreak=true` setting to this headless Codex run and selects `gpt-6-sol`
unless you set `--model`. It does not grant Daybreak access. See
[OpenAI's headless Codex guide](https://help.openai.com/en/articles/20001607-using-daybreak-in-codex-cli).

For `claude` and `openai`, provide `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` through your shell or secret store.

**Amazon Bedrock:** set `AWS_BEARER_TOKEN_BEDROCK` (or `BEDROCK_API_KEY`), then use
`--provider bedrock` with the exact Claude model or inference profile ID from your AWS console.
`--api-key` overrides the configured key. The CLI and Workbench also read these two Bedrock key
names from the `env` block in `~/.claude/settings.json`; Anthropic API keys and Claude Code
subscription credentials are never used for Bedrock.

Choose the region with `--bedrock-region` or the Workbench **AWS region** field. An empty region
uses `AWS_REGION`, then `AWS_DEFAULT_REGION`, then those names in Claude settings, then
`us-east-1`. Use the region where the key was created. The Bedrock provider calls the regional
`bedrock-runtime` Anthropic Messages endpoint with `x-api-key`, streamed responses, read-only
repository tools, and image attachments. It uses the Bedrock API key directly; it does not sign
requests with IAM access keys or use your AWS SSO session. See the
[AWS Messages API guide](https://docs.aws.amazon.com/bedrock/latest/userguide/inference-messages-api.html).

In the Workbench, select **Settings → Amazon Bedrock**, enter the region and model ID, and
provide a session key or leave it empty to use a configured Bedrock key. Session keys remain in
memory. Model IDs are entered manually; Threatlint does not verify model access until a run.

**Design inputs.** Give a threat model the intended architecture with `--design`, using files or folders:

```bash
threatlint run threat-model --provider claude-code --design docs/architecture/ payments.drawio api.json
```

The formats and limits match the Workbench's [design inputs](workbench.md#design-inputs). Reading PDFs
from the CLI needs `pdftotext` (Poppler: `brew install poppler`); without it, export the PDF as text or
add it in the Workbench. Images are attached for API providers and passed as files to Claude Code or Codex.
Avoid putting keys in command history with `--api-key`. Source and supplied
evidence sent to a cloud model leave your machine; choose a provider permitted
for that repository.

## Models

For Claude, the current scanning and general-assistance defaults are both
`claude-opus-5-5`. The policy lives in [models.py](../src/threatlint/models.py)
and [model-policy.cjs](../web/lib/model-policy.cjs).
Bedrock requires an explicit model ID because its model and inference profile IDs differ from
the direct Anthropic API.

Override with an explicit run setting, or configure:

| Setting | Environment variable | `org.json` key |
| --- | --- | --- |
| Security analysis | `THREATLINT_SCAN_MODEL` | `scanModel` |
| General assistance | `THREATLINT_GENERAL_MODEL` | `generalModel` |

The file is `~/.threatlint/org.json`. Explicit run choices take precedence;
environment values take precedence over file values. Other providers retain
their own defaults. Check model access with your provider rather than assuming
an example model is available to every account.

### Where scanned repositories are cloned

The dynamic scans that clone a repository into a throwaway workspace — DAST,
the runtime red team, and AVIT triage/rule-tuning — clone under the system
temporary directory by default. To send every such clone to a specific disk
instead, set a base directory:

| Setting | Environment variable | `org.json` key |
| --- | --- | --- |
| Clone base directory | `THREATLINT_REPO_STORE` | `repoStore` |

For example, `{"repoStore": "/Volumes/Repo Store/threatlint"}`. The directory is
created on demand, each run gets its own subdirectory under it, and the workspace
is deleted after the run (use `--keep-checkout` to keep a red-team checkout). Keep
this path in your local `org.json` or environment, not in the repository.

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
