# Threatlint for VS Code

See a risky pattern and its secure alternative before leaving the editor. Offline `guard`
checks add rule/CWE diagnostics on open/save; optional Copilot/Claude explanations add context.

## Install

Requires VS Code **1.90+**, the Threatlint CLI, and Node/npm for packaging from this repository.

1. Install the checker and package the extension:

   ```bash
   pip install threatlint
   cd ide/vscode
   npx @vscode/vsce package
   code --install-extension threatlint-1.0.0.vsix
   ```

2. Open a repository and run **Threatlint: Scan current file**.
3. Hover any diagnostic for the secure alternative. The shield rescans the workspace when clicked.

**Result:** Problems entries for matches—not security approval.
Next: [install assistant instructions and hooks](../../docs/ide.md#one-command-setup).
Cursor/Windsurf accept VS Code extensions; model availability depends on their editor APIs.
For development, open this folder and press F5.

## Commands and boundaries

| Command | What happens |
| --- | --- |
| **Scan workspace / Scan current file** | Runs `threatlint guard --format json --fail-on none`; diagnostics do not block edits or commits |
| **Install secure-by-default AI instructions** | Writes instructions, hooks, and tasks into the first workspace folder; inspect the diff |
| **Open Workbench** | Opens the configured URL; [start the server separately](../../docs/workbench.md#requirements-and-first-launch) |
| **Select model (Copilot or Claude)** | Lists account-available Copilot models and configured Claude models/CLI aliases; saves the non-secret selection |
| **Explain finding with selected model** | Sends cursor-line findings and up to 20 lines of source either side; opens an answer beside the editor, without tools or code edits |

Explanation consent persists per provider. Share only authorized source. Copilot owns sign-in;
the extension does not obtain its token. Claude discovery reads `~/.claude/settings.json`'s `env`
before process environment (`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL`);
otherwise the installed CLI supplies aliases. Explanations prefer that CLI when available;
it owns authentication. Claude OAuth credentials are never read.

The suppression quick fix **edits source**, inserting `REPLACE-WITH-VERIFIED-REASON`.
Replace it only after verifying a false positive; the checker cannot verify your justification.
See the [suppression policy](../../docs/ide.md#suppression-policy).

## Settings

| Setting | Default | Use |
| --- | --- | --- |
| `threatlint.executable` | `threatlint` | Absolute CLI path if the editor cannot find it |
| `threatlint.scanOnSave` / `scanOnOpen` | `true` | Automatic local checks |
| `threatlint.minimumSeverity` | `low` | Hide lower-severity diagnostics |
| `threatlint.claudeExecutable` | `claude` | Claude CLI path |
| `threatlint.workbenchUrl` | `http://127.0.0.1:3000` | Already-running Workbench |

## Troubleshooting

| Symptom | Next action |
| --- | --- |
| Shield shows an alert | Hover it for the error; check CLI path and `threatlint guard --list-rules` |
| No diagnostics | Save a file-backed document; inspect severity/scan settings and [checker limits](../../docs/ide.md#the-guard) |
| No Copilot models | Check sign-in and editor Language Model API support |
| Claude explanation fails | Check configured key/gateway or the signed-in CLI and executable path |
| Match needs context | Use a [source-grounded specialist review](../../docs/workbench.md#review-experience), not a suppression by default |
