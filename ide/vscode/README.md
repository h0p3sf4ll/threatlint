# Threatlint for VS Code

Secure-by-default guardrails for the code you write, and for the code your AI assistant writes.

- **Inline diagnostics on open and save.** Each finding names the rule ID and CWE and gives the
  secure alternative. Hover over it to read the alternative.
- **Quick fix to suppress a verified false positive.** It inserts a
  `threatlint-ignore: RULE-ID reason` comment, which needs a real reason before it is honoured.
- **Status bar shield.** It shows the open blocking (error) and warning counts. Click it to rescan
  the workspace.
- **Model picker (Copilot or Claude).** `Threatlint: Select model` lists the models your signed-in
  accounts can use, and the robot item in the status bar shows the current one:
  - **GitHub Copilot.** Listed through VS Code's Language Model API, using your existing Copilot
    sign-in. The extension never sees a token. The first request asks you to allow Threatlint to use
    Copilot.
  - **Claude.** If `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` is set, in the environment or in the
    `env` block of `~/.claude/settings.json` (including `ANTHROPIC_BASE_URL` gateways), the list comes
    from `GET /v1/models`. Without a key, a signed-in `claude` CLI is used with its model aliases
    (`fable`, `opus`, `sonnet`, `haiku`). Claude Code OAuth credentials are never read.
- **Explain a finding.** `Threatlint: Explain finding with selected model` sends the finding on the
  cursor line plus ±20 lines of source to the selected model, with no tools, and opens the answer
  beside the editor. It asks for consent once per provider.
- **Commands:** `Threatlint: Scan workspace`, `Threatlint: Scan current file`,
  `Threatlint: Open Workbench`, and `Threatlint: Install secure-by-default AI instructions`.

## Install

```bash
pip install threatlint            # provides the `threatlint guard` engine
cd ide/vscode
npx @vscode/vsce package          # produces threatlint-1.0.0.vsix
code --install-extension threatlint-1.0.0.vsix
```

For development, open `ide/vscode` in VS Code and press F5 to launch an Extension Development Host.
The extension also works in Cursor and Windsurf, which are both VS Code forks.

## Settings

| Setting | Default | Purpose |
| --- | --- | --- |
| `threatlint.executable` | `threatlint` | Path to the CLI, e.g. a virtualenv's `bin/threatlint` |
| `threatlint.scanOnSave` / `scanOnOpen` | `true` | When to run the guard |
| `threatlint.minimumSeverity` | `low` | Hide findings below this severity |
| `threatlint.claudeExecutable` | `claude` | Claude Code CLI used when Claude is signed in without an API key |
| `threatlint.workbenchUrl` | `http://127.0.0.1:3000` | The local Workbench opened by the command |

The guard is a fast pattern check. A clean result means no known-insecure pattern matched; it does
**not** mean the code is approved. For auth, crypto, payments, tenancy, and file-handling changes,
run the `appsec-code-reviewer` agent or the Workbench. See [docs/ide.md](../../docs/ide.md).
