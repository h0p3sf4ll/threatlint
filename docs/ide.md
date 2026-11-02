# <img src="media/logo.svg" alt="" width="28" height="31" align="top"> Threatlint in the IDE: secure-by-default code generation

Catch a risky pattern while the code is still in front of you. Threatlint pairs secure-coding
instructions for your AI assistant with an offline pattern checker, `threatlint guard`.
Findings name the rule, CWE, and secure alternative; specialist reviews provide the deeper
source/control tracing a pattern match cannot.

[Watch the IDE walkthrough](../web/public/media/ide.mp4) or open **Learn & videos** in the Workbench.

## One-command setup

1. Install the CLI, enter your repository, and choose your editors:

   ```bash
   pip install threatlint
   cd your-repo
   threatlint ide install --editors claude,copilot
   # Omit --editors to install for vscode,cursor,claude,copilot,windsurf.
   ```

2. Inspect the reported `added`, `updated`, `unchanged`, or `skipped` files before committing.
   **This command writes repository configuration.**
3. Check one existing source file:

   ```bash
   threatlint guard src/service.py --fail-on medium
   ```

**Expected result:** findings with location and a secure alternative, or no matched patterns.
Exit `1` means a finding met your threshold—not that every issue was found.
Next: [install the editor extension](../ide/vscode/README.md) for inline feedback.

| Files written | Purpose |
| --- | --- |
| `.github/copilot-instructions.md`, `.github/instructions/threatlint-secure-code.instructions.md` | Copilot instructions; the scoped file uses `applyTo: "**"` |
| `.cursor/rules/threatlint-secure-code.mdc`, `.windsurfrules` | Always-applied Cursor rule / Windsurf instructions |
| `CLAUDE.md`, `.claude/settings.json` | Claude instructions and `PostToolUse` guard hook |
| `.vscode/tasks.json` | Workspace, current-file, and staged-file guard tasks |
| `.pre-commit-config.yaml` | Hook config if absent; otherwise a snippet is printed when needed |

Marked Markdown sections update in place; JSON settings/hooks/tasks are merged. Dedicated rule
files are refreshed. Re-run after upgrading, then review the diff. The installer writes pre-commit
configuration but does **not** activate Git hooks; install the hook through your existing
pre-commit workflow. `threatlint ide instructions` prints the canonical instructions without installing.

## Per-editor usage

### VS Code, Cursor, Windsurf: the Threatlint extension

The [extension](../ide/vscode/README.md) scans file-backed documents on open/save by default.
Hover for the secure alternative; the shield counts diagnostics, not verified vulnerabilities.
**Threatlint: Open Workbench** opens the configured URL—it does not start the server.
Without the extension, use the installed **Threatlint: guard current file** task.

### Claude Code

The installer adds this hook:

```json
{"hooks":{"PostToolUse":[{"matcher":"Edit|Write|MultiEdit","hooks":[{"type":"command","command":"threatlint guard --hook","timeout":30}]}]}}
```

For recognized file paths in the tool payload, medium-or-higher findings go to stderr with exit `2`,
giving Claude feedback to act on. Otherwise the hook exits `0` silently. This is post-edit
feedback, **not** an edit rollback or a guarantee the model will fix the code.

### GitHub Copilot (Chat and agent mode)

Copilot reads the installed instruction files. Install specialist agents separately with
`threatlint install --copilot --local`; save accepted suggestions to trigger extension checks.

### Cursor and Windsurf

Their rules carry the same instructions. Both accept VS Code extensions, but Copilot model access
depends on the editor's Language Model API and sign-in; do not assume identical provider support.

## The guard

```bash
threatlint guard src/ app.py                 # explicit files/directories
threatlint guard                            # current directory
threatlint guard --staged                    # selects Git-staged filenames
threatlint guard --format sarif -o threatlint.sarif
threatlint guard --format json
threatlint guard --fail-on medium            # default high; "none" never fails findings
threatlint guard --list-rules
```

The 21 rules cover patterns in injection, unsafe deserialization, disabled TLS verification,
weak password hashing/token randomness, secret-like values, dynamic HTML, CORS, request-derived
paths, JWT verification, and debug mode. Secret-rule snippets are redacted.

**Limits:** line-oriented matching is not data-flow analysis. Files over 1,000,000 bytes, lines
over 4,000 characters, unsupported types, and excluded build/vendor directories are skipped.
`--staged` reads **working-tree contents** of staged filenames, not Git index blobs; an empty
staged selection currently falls back to the current directory. A clean result is not approval.

## Suppression policy

- Suppress only a verified false positive, naming a rule and reason on the same/preceding line:
  `# threatlint-ignore: TL-PY-SHELL constant command; no user input`.
- `ALL` is line-scoped, not file-wide. A reason is required.
- Fixtures/rule definitions may name specific rules in the first 10 lines:
  `# threatlint-ignore-file: TL-PY-EVAL intentionally insecure fixture`.
- The extension quick fix inserts a comment **and changes source**. Replace
  `REPLACE-WITH-VERIFIED-REASON` before saving; the scanner checks for a reason, not its truth.
  Review suppressions as code changes. A triage verdict alone does not authorize them.

## Recommended workflow

1. **Write/generate:** installed instructions guide the assistant; they do not enforce correctness.
2. **Check:** use on-save checks or the Claude hook; repair the cause using the suggested alternative.
3. **Review:** ask `appsec-code-reviewer` about the diff for auth, crypto, payments, tenancy,
   file handling, and AI/tool changes. Reviews propose changes; they do not apply them.
4. **Gate deliberately:** run guard in your pre-commit/CI workflow with an explicit threshold.
   Check its exit status and the [CI setup](github-actions.md), rather than treating an editor
   shield as a merge gate.

## Troubleshooting

| Symptom | Next action |
| --- | --- |
| CLI not found in editor | Set `threatlint.executable` to the installed CLI's absolute path |
| No inline findings | Save a file-backed document; check scan settings, severity filter, and skipped-file limits |
| Claude ignores hook feedback | Check merged settings and CLI PATH; review the diff yourself |
| Expected pre-commit hook did not run | Activate pre-commit separately and inspect its installed configuration |
| Unsure whether a match is real | Trace the source/control path with a [specialist review](workbench.md#review-experience) |
