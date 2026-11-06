# Make the next change easier to understand

A readable module is a smaller decision: you can see what it owns, test that
behavior, and change it without learning an unrelated workflow.
This guide is the map for contributors, not a second product manual.

## Run the checks that match your change

From the checkout:

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest -q
```

Without an editable installation, use `PYTHONPATH=src python3 -m pytest -q`.
For focused work, select the affected test files before running the full suite.

For Workbench changes:

```bash
npm --prefix web ci
npm --prefix web test
```

Desktop and browser smoke checks are separate:

```bash
npm --prefix web run test:desktop
npm --prefix web run test:browser
```

Those checks have their own runtime/browser prerequisites; passing unit tests
does not imply they ran. Word-dependent Workbench unit tests inject a converter:
they do not require shell wrappers or `python-docx` on the test host. The actual
Python converter has separate tests. Build the Python distribution with:

```bash
python3 -m build --wheel
```

Use temporary directories and synthetic clients in tests. Do not validate a
refactor against live queues, credentials, or customer data.

## Python source design

Split by responsibility—not by an arbitrary line-count target.

- Use plain functions for parsing/rendering and dataclasses for state.
- Keep provider-specific behavior together.
- Pass explicit collaborators at I/O boundaries.
- Preserve public imports, serialized formats, and tested integration seams.
- Prefer a direct unit test over a forwarding layer added only to shrink a file.

| Boundary | Where it lives |
| --- | --- |
| CLI composition | `src/threatlint/cli.py` |
| Read-only inspection tools | `agent_tools.py` |
| Model transport/tool-use loop | `agent_runner.py` |
| Mode, provider, and prompt configuration | `run_context.py` |
| Report naming/export | `report_output.py` |
| Bundle installation/removal | `installation.py` |
| Terminal presentation | `terminal.py` |
| Guard models/rules/scanning/output/CLI | `guard/` |
| Queue models/storage/lifecycle/execution/CLI | `avit_orchestrator/` |

Paths after the first row are relative to `src/threatlint/`.

Integration boundaries are similarly explicit:

- `servicenow_{credentials,checkout,records,markdown,cli}.py`.
- `semgrep_{engine,policies,rule_text,cli}.py`.
- `avit_{report,repositories,semgrep,cli}.py` and `sctask_{text,cli}.py`.
- `dast_{probe,requests,passive,evidence,records,cli}.py`.
- `runtime_{models,config,compose,discovery}.py`.
- `github_app_{config,payloads,cli}.py`, `ado_payloads.py`, `aws_profiles.py`.

Sidekick keeps clients, storage, operations, reports, and workbook handling
separate. Integrations are grouped by type under `integrations/`
(`findings_management/`, `scanning/`, `secret_validation/`); each type has its
own base class and never imports another type. Shared plumbing lives in
`integrations/common.py`, the review commands in `integrations/verbs.py`, and
verdict syntax in `integrations/verdicts.py`. Community integrations register
through the `threatlint.integrations` entry point; see
[Writing an integration](integrations/authoring.md).
`threatlint.scanners` is a deprecated alias kept for old imports; new code
imports from `threatlint.integrations`.

The bundled Python scripts have sibling helpers. Keep matching files in
`src/threatlint/data/scripts/` and `.github/scripts/` synchronized.
Test a copied standalone bundle—not only imports from the checkout.
Installation and uninstall own those shipped files while preserving custom scripts.

Small cohesive modules such as `models.py`, `skills.py`, `ide.py`, and
`setup_wizard.py` need no artificial extra layers.

## Find the right source

| Area | Source |
| --- | --- |
| Python CLI and integrations | [src/threatlint/](../src/threatlint/) |
| Canonical agents, skills, commands | [package data](../src/threatlint/data/) |
| Desktop/browser server and UI | [web/](../web/) |
| VS Code extension | [ide/vscode/](../ide/vscode/) |
| Teams bot | [teams-app/](../teams-app/) |
| GitHub/Azure integrations | [.github/](../.github/) · [azure-pipelines/](../azure-pipelines/) |

Edit agent customizations deliberately: update their canonical definitions and
check client mirrors and skill registration together. The
[agent guide](agents.md) explains the user-facing contracts.

## Validate workflow contracts and scheduling

The [execution contracts](../src/threatlint/data/agent-contracts.json) define each specialist's
inputs, outputs, boundaries, and `source`/`upstream` evidence mode. Keep them aligned with the
canonical agents, skill registry, prompt assembly, installed-client exports, and the agent UI.
A new specialist must not silently inherit an arbitrary scheduling dependency.

Read [Execution controls](architecture.md#execution-controls) before changing concurrency.
Test independent overlap, deterministic ancestor context, cycles and bad limits, failed
prerequisites, queued/active cancellation, bounded admission, and stable tool-call identity.
Use fake providers and temporary repositories so tests do not spend real quotas or mutate
external findings. Preserve serialized write-capable workflows unless their authorization and
idempotency contracts are explicitly redesigned.

For documentation/media changes, validate relative links and SVG XML, render each changed
figure, and inspect its pixels. Use the [current-UI capture procedure](media/README.md) for
screenshots. Passing DOM tests is not a successful browser capture.

## Write docs that help someone act

Start with the reader's problem and desired outcome. Show one concrete next step,
what success looks like, and the limits that could change the decision.
Put long reference tables behind a focused guide, not before the first useful action.

Editorial influences: Simon Sinek's *Start With Why* for purpose before features,
and Chip and Dan Heath's *Made to Stick* for simple, concrete, credible, memorable
explanations. Use original examples and prose; neither book endorses this project.
Do not trade accuracy for a better-sounding promise.

## Media and Git LFS

The current [attributes file](../.gitattributes) normalizes line endings; it does
not enable LFS. Media is presently stored in ordinary Git.

Before adding many new binary recordings, choose normal Git, Git LFS, or external
release assets. [The LFS example](../.gitattributes.lfs-example) lists suggested
patterns; **merge** those patterns into `.gitattributes` rather than replacing
its existing rules. Contributors/builders need Git LFS and checked-out objects
if LFS is adopted. Review host quotas and archive behavior at that time.
Do not rewrite existing history or force-push as a routine documentation update.

To prepare the narrated demos for a human female narrator:

```bash
npm --prefix web run videos:scripts -- --output-dir /tmp/threatlint-narration
```

Follow the [recording and listening workflow](narration.md), then import the
approved WAV takes with `--narration-dir`. Rendering requires Playwright Chromium
and ffmpeg/ffprobe; there is no synthetic speech fallback. Use `--output-dir` for
a draft before replacing published media. Keep visuals fixture-based and free
of private data.

## Keep organization details out of commits

Use environment variables or `~/.threatlint/org.json` for organization-specific
settings. Enable the repository's hooks once per clone:

```bash
git config core.hooksPath .githooks
scripts/check-org-references.sh tree
```

The pre-commit/commit-message checks and organization-reference CI check are
additional safeguards, not permission to commit private reports or credentials.

**Before sharing a change:** run the focused tests, inspect the diff, update the
relevant guide, and state what validation actually ran.
