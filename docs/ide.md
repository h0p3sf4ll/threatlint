# <img src="media/logo.svg" alt="" width="28" height="31" align="top"> Threatlint in the IDE: secure-by-default code generation

▶ Watch: [Secure-by-default code in the IDE](../web/public/media/ide.mp4) (narrated) · also in the app under **Learn & videos**.

Threatlint meets you where you write code. Two pieces work together:

1. **Instructions.** Secure-by-default instructions load into your AI coding assistant (Copilot,
   Cursor, Claude Code, Windsurf), so generated code starts out with parameterized queries, argument
   arrays, `secrets`, verified TLS, and server-side authorization.
2. **`threatlint guard`.** This is a deterministic, offline, dependency-free check. It runs on save,
   after every AI edit, in pre-commit, and in CI. It catches the insecure patterns that still slip
   through and tells you, or the model, the secure alternative.

Neither piece replaces the evidence-led specialist agents. Use them for anything security-sensitive
(see [the workflow](#recommended-workflow)).

## One-command setup

```bash
pip install threatlint
cd your-repo
threatlint ide install                       # all editors
threatlint ide install --editors claude,copilot   # or a subset: vscode,cursor,claude,copilot,windsurf
```

| File | Editor | What it does |
| --- | --- | --- |
| `.github/copilot-instructions.md` (marked section) | GitHub Copilot | Repository-wide secure-coding instructions |
| `.github/instructions/threatlint-secure-code.instructions.md` | Copilot / VS Code | Same rules with `applyTo: "**"` |
| `.cursor/rules/threatlint-secure-code.mdc` | Cursor | Rule with `alwaysApply: true` |
| `.windsurfrules` (marked section) | Windsurf | Workspace rules |
| `CLAUDE.md` (marked section) | Claude Code | Project instructions |
| `.claude/settings.json` | Claude Code | `PostToolUse` hook on `Edit\|Write\|MultiEdit` that runs `threatlint guard --hook` |
| `.vscode/tasks.json` | VS Code / Cursor / Windsurf | *Guard workspace*, *Guard current file*, *Guard staged changes* tasks with a problem matcher |
| `.pre-commit-config.yaml` | Any | `threatlint-guard` hook (created only if the file is absent; otherwise the snippet is printed) |

The installer is idempotent. Markdown content stays between
`<!-- threatlint:secure-code:begin/end -->` markers and is updated in place. JSON files are merged:
your existing settings, hooks, and tasks are kept. Re-run the command after upgrading threatlint to
refresh the rules. `threatlint ide instructions` prints the canonical text
(`src/threatlint/data/ide/secure-code-instructions.md`) if you want to paste it somewhere else.

## Per-editor usage

### VS Code, Cursor, Windsurf: the Threatlint extension

The extension in [`ide/vscode`](../ide/vscode/README.md) runs the guard when a file is opened or
saved:

- Problems appear inline with the rule ID, the CWE, and the **secure alternative**. Hover over a
  finding to see it.
- A quick fix inserts a justified suppression comment.
- The status bar shield shows the open counts.
- **Threatlint: Open Workbench** launches the full Workbench, where you run the specialist agents,
  connect sources, run runtime scans, and view dashboards.

No extension? Run the `Threatlint: guard current file` task. Its problem matcher fills the Problems
panel the same way.

### Claude Code

`threatlint ide install --editors claude` adds the instructions to `CLAUDE.md` and registers this
hook:

```json
{ "hooks": { "PostToolUse": [ { "matcher": "Edit|Write|MultiEdit",
  "hooks": [ { "type": "command", "command": "threatlint guard --hook", "timeout": 30 } ] } ] } }
```

After every file edit, Claude Code sends the tool call JSON to the hook on stdin. If the edited file
has a finding at medium severity or higher, the hook exits with code `2` and writes the findings and
secure alternatives to stderr. Claude Code shows that output to the model, which then rewrites the
code. Clean files exit `0` silently. To go deeper, ask for a review: *"use appsec-code-reviewer on
my working-tree diff"*.

### GitHub Copilot (Chat and agent mode)

Copilot reads `.github/copilot-instructions.md` and the `.instructions.md` file automatically. Copilot
Chat custom agents (`threatlint install --copilot --local`) add `@appsec-code-reviewer` and the
other specialists. After accepting a suggestion, save the file (the extension runs the guard) or run
the *guard staged changes* task before committing.

### Cursor and Windsurf

Their rules files load the same instructions into every request. Install the VSIX for inline
diagnostics; both editors accept VS Code extensions.

## The guard

```bash
threatlint guard                       # scan the current directory
threatlint guard src/ app.py           # files or directories
threatlint guard --staged              # only git-staged files (pre-commit)
threatlint guard --format sarif -o threatlint.sarif   # for GitHub code scanning / ADO
threatlint guard --format json         # machine-readable, used by the extension
threatlint guard --fail-on medium      # exit 1 at or above this severity (default: high; "none" never fails)
threatlint guard --list-rules
```

It covers 21 rules: eval/exec on dynamic input, shell command injection, SQL built from strings,
unsafe deserialization (pickle, `yaml.load`), disabled TLS verification, MD5/SHA-1 password hashing,
non-cryptographic randomness for tokens, hardcoded AWS/GitHub/private-key/generic secrets
(redacted in output), `innerHTML` and `dangerouslySetInnerHTML` with dynamic values, wildcard CORS
with credentials, filesystem paths from request input, disabled JWT verification or `alg: none`,
and debug mode. Each rule carries a CWE and a concrete secure alternative.

The guard is line-oriented pattern matching. It is fast and predictable, and it misses anything that
needs data-flow analysis. **A clean result is not a security approval.**

## Suppression policy

- Suppress only a **verified** false positive. Write the rule ID and a reason on the same line or
  the line above:
  `# threatlint-ignore: TL-PY-SHELL command is a constant; no user input`
- A suppression without a reason is ignored. `ALL` works only on a single line, never file-wide.
- For fixtures or rule definitions, a file-level opt-out in the first 10 lines must name specific
  rules: `# threatlint-ignore-file: TL-PY-EVAL deliberately insecure test samples`.
- Review suppressions in code review like any other code. To triage many scanner findings at once,
  use the `appsec-fp-reviewer` agent; a false-positive verdict does not by itself authorize a
  suppression.

## Recommended workflow

```text
generate / write code ─► guard on save + AI hook ─► guard --staged (pre-commit)
        ▲                     │ secure alternative fed back to you or the model
        └─────────────────────┘
  open PR ─► CI template (guard SARIF + appsec-code-reviewer on the diff) ─► merge
```

1. **Generate.** The assistant already follows the installed secure-by-default instructions.
2. **Guard on save / after each AI edit.** Fix findings with the listed secure alternative. Claude
   Code fixes them itself through the hook.
3. **Review the diff.** For changes that touch auth, crypto, payments, tenancy, file handling, or
   AI/tool calls, run `appsec-code-reviewer` (Claude Code, Copilot, or the Workbench). Run it on
   generated code too.
4. **Pre-commit.** `threatlint guard --staged` blocks high-severity patterns before they reach the
   remote.
5. **CI.** The reusable GitHub Actions and Azure Pipelines templates upload guard SARIF and run the
   specialist agents on every PR (see `docs/github-actions.md` and `azure-pipelines/README.md`).
