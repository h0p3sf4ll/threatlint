---
title: Reports
description: Read a review, export the result, and share findings with the right evidence and validation status.
---

Use a report to decide what needs attention, inspect the supporting evidence, and agree on the next action. A file attachment does not establish that a proposed fix or test has been executed.

## Before you start

Finish a review or import a scan report. Word conversion needs Python with `python-docx`; viewing an existing report does not require a model request.

## Choose a finding source

Model reviews use the provider chosen under **Settings → Model provider**. Reading tickets, pulling an issue inbox, parsing an upload, and running the built-in source scanner do not by themselves establish a model-reviewed verdict.

| Source | Where to start | Connection or input |
| --- | --- | --- |
| Local source, GitHub, or Azure DevOps repository | **Review code** for a specialist review | Open a folder or connect the repository and branch through **Connect source**; use **Settings → Integrations** for saved source accounts |
| A findings file used as review context | **Review code → Attach findings** | One SARIF, JSON, Markdown, or text file, up to 5 MiB; run the selected specialist pipeline to produce a report |
| ServiceNow AVITs, SCTASKs, or ISSTs | **Finding triage → ServiceNow** | **Settings → Scanning & triage → ServiceNow AVIT triage**, plus the required setup shown on the review form; see [ServiceNow AVITs](avit-integration.md) |
| DefectDojo findings | **Finding triage → DefectDojo**, by finding ID or filter | **Settings → Scanning & triage → DefectDojo**; see [DefectDojo](integrations/defectdojo.md) |
| SonarQube issues or security hotspots | **Finding triage → SonarQube**, by key or filter | **Settings → Scanning & triage → SonarQube**; see [SonarQube](integrations/sonarqube.md) |
| Jira, Azure DevOps Boards, or GitHub Issues tickets | Select the system under **Finding triage**, enter ticket IDs, and choose **Triage tickets** | Its dedicated **Settings → Scanning & triage → Jira / Azure DevOps Boards / GitHub Issues** connection; optionally supply the matching workspace or source link |
| An exported scanner report | **Finding triage → Scan report upload** | One supported file from the table below; choose **Triage findings** or **Import without review** |
| An issue inbox from several systems | **Issue management → Pull issues** | Named Jira, Azure Boards, and GitHub Issues connections under **Settings → Integrations**; ServiceNow uses its existing ServiceNow Settings automatically |
| Baseline, Semgrep, or Trivy source-scan results | **Review code → Run scanners** | An open workspace and the selected installed engines; see [Scan source code](security-scanner.md) |
| A running application | **Scan running app** | The authorized target, scope, and scan authentication supplied on that page; see [Runtime scans](runtime-redteam.md) |

The dedicated ticket connections used by **Finding triage** and **Metrics** are separate from Issue management's multiple named integrations. Configuring one does not configure the other. Pulling or importing ticket IDs in **Issue management** updates its saved inbox; it does not run model triage or create a Findings report. Use **Finding triage → Triage tickets** for that review workflow. See [Integrations](integrations.md).

Architecture diagrams, API specifications, design documents, images, and code snippets added with **Add supporting docs** are review context. They are not separate scanner findings or automatically generated reports. See [Supporting documents](workbench.md#design-inputs).

**Attach findings** accepts `.sarif`, `.json`, `.md`, and `.txt` as evidence for a specialist pipeline. It is a separate 5 MiB attachment path, rather than the structured 25 MB scan-report import below. Markdown and text findings are supported as review context even though they are not formats in that import menu.

## Supported uploaded reports

Choose **Auto-detect** or the matching **Report format**. Detection reads the content, so renaming a file does not convert an unsupported export.

| Source | Supported file | Expected content |
| --- | --- | --- |
| Invicti / Netsparker | XML, JSON, or PDF | A full vulnerability export, including finding titles and evidence; JSON contains its vulnerability list |
| MobSF | JSON or PDF | A full mobile static-analysis report, with app identity and analysis sections |
| DefectDojo | JSON | API v2 findings `results` or a findings list, including finding IDs, severity, and scanner metadata |
| SonarQube | JSON | Issue-search `issues` and/or hotspot-search `hotspots`, with their keys and components |
| Semgrep | JSON | Scan output containing `version` and `results`, with rule IDs and source locations |
| Trivy | JSON | Scan output containing `SchemaVersion` and `Results`; vulnerability, misconfiguration, secret, and license findings are read |
| SARIF | JSON / `.sarif` | A SARIF document with `version`, `runs`, and result records; scanner identity and source locations are retained where supplied |
| Other scanner PDFs | PDF through **Auto-detect** | Selectable text with identifiable individual finding titles and evidence; extraction depends on the report layout |

Upload one report at a time, up to **25 MB** (25 × 1024 × 1024 bytes). PDF extraction reads selectable text, up to 1,000 pages and 8,388,608 extracted characters; it does not run OCR. Image-only PDFs, application archives such as APK/IPA/ZIP, and browser printouts of paginated MobSF results are not complete supported exports. Prefer the scanner's structured export when available, and check the extracted count and evidence.

The ticket workflow internally produces a Threatlint-normalized `threatlintFindings` JSON payload. This is a ticket/API payload, not support for arbitrary ticket JSON or an additional format choice in the upload menu.

An upload produces one consolidated **Finding Review**, with a result for each extracted finding. **Import without review** makes no model call and labels findings as unverified true positives, with a not-triaged explanation; it is not a confirmed vulnerability assessment. Model triage needs a provider and benefits from source at the scanned revision. The original uploaded file is not retained; the report contains bounded, redacted evidence, so keep the original export when you need a complete audit copy.

Connected DefectDojo and SonarQube reviews use one model run per finding, with at most 64 model runs per batch. Uploaded reports group up to 20 findings per model request and check the model-run budget too. Split large inputs when the budget is exceeded. These budgets do not impose a total-finding cap on ServiceNow AVIT batches. See [Review orchestration](review-orchestration.md).

## View and export in the Workbench

1. Finish a review that saves to Findings, such as [scan-report triage](workbench.md#triaging-a-scan-report). ServiceNow AVIT batches have the separate destination described below.
2. Open **Findings**, then choose **Read report** on its card.
3. Check the finding ID, inspected file/line, impact, proposed correction, and validation status.
4. Download **Markdown** or **Word** where available. Choose **PowerPoint** for an editable one-slide summary of the top finding; the report's **Findings** tab can export a specific finding.
5. Keep the original Markdown when you need a diffable review history.

PowerPoint is a **single-finding summary**, not a conversion of every report into a slide deck. It is available when the report has a structured finding. It includes reported and proposed code when supplied; missing code is labelled rather than invented, and remediation prose may be used instead.

The report API also exposes its structured JSON view. Markdown, Word, and PowerPoint are the report reader's download formats; uploading a PDF does not create a PDF report-download option.

To remove a saved report and its files, choose **Delete…** on its card and confirm. Scan run history, downloaded copies, and tracker attachments remain.

## What to expect

A useful report states the decision, scope, evidence, unresolved uncertainty, and next action. Findings should include a proposed fix and a regression assertion or acceptance check.

Finding reviews use the title **Finding Review** and either **TRUE POSITIVE** or **FALSE POSITIVE**. A false-positive decision needs evidence disproving the scanner claim. Without that proof, a conservative true positive keeps its actual confidence and evidence gaps; it does not claim a confirmed exploit. The `fp-review` command and filename remain compatible.

A proposed test is **NOT RUN** unless execution and its result are recorded. Read the coverage and limitations alongside the verdict.

## Where the report goes

| Workflow | Report or export destination |
| --- | --- |
| Workbench specialist review | Saved in **Findings** for its workspace; Markdown, Word when conversion succeeds, and eligible single-finding PowerPoint |
| Uploaded report or Jira / Azure Boards / GitHub ticket triage | A consolidated Finding Review in **Findings**, under the selected workspace or **Scan imports**; Markdown and available Word |
| DefectDojo / SonarQube connected review | A separate report per reference in the corresponding review workspace in **Findings**; posting back is a later confirmed action |
| ServiceNow AVIT batch | The Word report is attached to the AVIT; SCTASKs receive their AVIT reports, and ISSTs receive true-positive reports. The batch attempts to remove temporary local reports, workspace entries, and checkouts, including on failure; check any cleanup warnings |
| Issue management Pull / Import ticket IDs | Saved issue inbox rows with source links and status; no review report is generated |
| Built-in source scanner | Engine findings, coverage, scan history, and Repository risk evidence; it does not automatically generate a Markdown/Word Findings report |
| Runtime scan | Separate observation exports in **JSON, Markdown, or HTML**; **Review evidence with specialists** can subsequently produce normal Findings reports |
| Metrics | A separate **CSV** export of retained findings from selected report, runtime, and synced tracker sources; the aggregate ServiceNow AVIT count panel is excluded |
| Sidekick vReports / trends | vReport workbooks are **XLSX**; the trends executive summary uses the browser print dialog for PDF. These are separate from Finding Review downloads; see [Sidekick](sidekick.md) |
| `threatlint run MODE` | Word when conversion succeeds, otherwise Markdown |
| Claude Code slash command | The command coordinates export after analysis |
| Native agent or chat | Client-dependent; chat text is not necessarily a saved file |
| CI or Teams | Configured artifacts or conversation output; see [CI templates](ci-templates.md) and [Teams](teams.md) |

For a ServiceNow batch, inspect each item's attachment and error history before relying on ServiceNow as the retained copy. The batch attempts local cleanup even if attachment fails, so a local fallback report in Findings is not guaranteed. This cleanup rule belongs to the automatic AVIT batch; an ordinary saved report later attached or posted through a confirmation dialog remains saved unless you delete it.

ServiceNow batches review up to **three findings concurrently by default**, with **Parallel reviews** from **1–8**. Each finding can finish independently; shared external updates run one at a time. **Stop batch** cancels queued and cancellable active work, waits for updates already started, and retains completed outcomes. Reloading the page replays the active run. Normal Workbench shutdown also waits for started updates; unfinished reviews do not automatically resume after restart. See [ServiceNow batch progress](avit-integration.md).

DefectDojo posting attaches the Word report and applies the confirmed note/status action. SonarQube stores no attachments: posting adds a summary/report-location comment and the supported issue or hotspot transition. An uploaded report can also be posted to ServiceNow, DefectDojo, or SonarQube after confirmation and exact destination mapping; importing or reviewing alone does not perform that post.

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
