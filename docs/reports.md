---
title: Reports
description: Read a review, export the result, and share findings with the right evidence and validation status.
---

Use a report to decide what needs attention, inspect the supporting evidence, and agree on the next action. A file attachment does not establish that a proposed fix or test has been executed.

## Before you start

Finish a review or import a scan report. Word conversion needs Python with `python-docx`; viewing an existing report does not require a model request.

## View and export in the Workbench

1. Finish a review or [triage a scan report](workbench.md#triaging-a-scan-report).
2. Open **Findings**, then choose **Read report** on its card.
3. Check the finding ID, inspected file/line, impact, proposed correction, and validation status.
4. Download **Markdown** or **Word** where available. Choose **PowerPoint** for an editable one-slide summary of the top finding; the report's **Findings** tab can export a specific finding.
5. Keep the original Markdown when you need a diffable review history.

PowerPoint includes reported and proposed code when the report supplies them. Missing code is labelled rather than invented; remediation prose may be used instead.

To remove a saved report and its files, choose **Delete…** on its card and confirm. Scan run history, downloaded copies, and tracker attachments remain.

## What to expect

A useful report states the decision, scope, evidence, unresolved uncertainty, and next action. Findings should include a proposed fix and a regression assertion or acceptance check.

Finding reviews use the title **Finding Review** and either **TRUE POSITIVE** or **FALSE POSITIVE**. A false-positive decision needs evidence disproving the scanner claim. Without that proof, a conservative true positive keeps its actual confidence and evidence gaps; it does not claim a confirmed exploit. The `fp-review` command and filename remain compatible.

A proposed test is **NOT RUN** unless execution and its result are recorded. Read the coverage and limitations alongside the verdict.

## Where the report goes

| Workflow | Output |
| --- | --- |
| Workbench review or scan-report triage | A report in Findings; Markdown and Word where conversion is available |
| `threatlint run MODE` | Word when conversion succeeds, otherwise Markdown |
| Claude Code slash command | The command coordinates export after analysis |
| Native agent or chat | Client-dependent; chat text is not necessarily a saved file |
| CI or Teams | Configured artifacts or conversation output; see [CI templates](ci-templates.md) and [Teams](teams.md) |

Use `--output-dir DIR` for a direct CLI destination; otherwise it uses the repository root. Its basename is:

```text
<repo>-<branch>-<mode>-local-YYYY-MM-DD
```

The `-local-` suffix is a naming convention, even for cloud providers. It does not describe where prompts were processed.

Native command names vary. Examples include:

| Command | Typical basename |
| --- | --- |
| `/threat-model` | `<repo>-<branch>-threat-model-YYYY-MM-DD` |
| `/threat-model src/auth` | `<repo>-<branch>-threat-model-src-auth-YYYY-MM-DD` |
| `/security-review` | `<repo>-<branch>-security-review-YYYY-MM-DD` |
| `/security-review 42` | `<repo>-<branch>-security-review-pr42-YYYY-MM-DD` |
| `/fp-review` | `<repo>-<branch>-fp-review-YYYY-MM-DD` |

Repository names are lowercased; spaces and branch slashes become hyphens. The command confirms the actual saved path.

## Convert an existing report

From a Threatlint checkout, install the package and complete script bundle in the same Python environment:

```bash
python3 -m pip install -e .
threatlint install -y
python3 ~/.claude/scripts/md_to_docx.py report.md report.docx
```

On Windows, use your installation's `python` or `py -3` and the full script path:

```powershell
py -3 "$env:USERPROFILE\.claude\scripts\md_to_docx.py" report.md report.docx
```

Threatlint declares `python-docx` as a dependency. The converter supports headings, tables, lists, emphasis, and fenced code. It does not execute tests or turn Mermaid source into a verified architecture.

## No Word file

Check the interpreter and converter:

```bash
python3 -c "import docx; print('python-docx available')"
python3 ~/.claude/scripts/md_to_docx.py
```

The second command prints usage and exits nonzero because no files were supplied; that is expected. If a script or sibling helper is missing, re-run the installer. If the library is missing, install Threatlint in that interpreter's environment. The direct CLI falls back to Markdown when conversion fails, so check its saved-path message.

## Validate Semgrep false-positive tuning

Eligible false-positive reviews include rule tuning. The automated findings-file workflow validates supported tuning before saving; blocked tuning is reported as incomplete. To validate an existing local report containing the full rule and true/false-positive fixtures:

```bash
threatlint semgrep tune-report --report review.md --repo /path/to/checkout --output-dir /path/to/tuned-rules
```

This uses Pro to validate the exact false-positive location and retained true-positive fixtures. Only validated replacements are saved, with a per-finding `tuning-manifest.json`; blocked proposals return an unsuccessful exit status. It does not upload findings or publish rules. Replace the listed original rule IDs rather than enabling both original and replacement.

Semgrep token lookup is environment, native settings (`SEMGREP_SETTINGS_FILE` or `~/.semgrep/settings.yml`), Threatlint saved login, then Parameter Store. A token alone does not establish Pro availability. Reports retain the input scan's recorded engine provenance. See [Semgrep policies](semgrep-policies.md).

## Share the report

1. Remove credentials, personal data, and customer identifiers that the audience should not receive.
2. Confirm that quoted source and architecture may be shared.
3. Keep scope, confidence, coverage, and validation status with the finding.
4. Assign an owner and a measurable acceptance check to each agreed action.

**Next:** use [fix verification](agents.md#appsec-verify-fix) to review remediation, then run the relevant tests in an authorized environment. Return to the [Quickstart](learning.md) for a complete review flow.
