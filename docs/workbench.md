---
title: Use the Workbench
description: Open source code, run scans and specialist reviews, and work with findings and reports.
---

# Use the Workbench

The Workbench brings source code, security scans, specialist reviews, and findings into one place. Start with a small repository and one question. Follow the [Quickstart](learning.md) for a first scan.

<a name="requirements-and-first-launch"></a>

## Open the Workbench {#requirements-and-first-launch}

Use the [web app](https://app.threatlint.dev) or open your installed desktop app. Desktop works without a Threatlint account. On the web, check that the account menu shows the personal or company profile you intend to use.

A workspace is the source directory you want to inspect, together with its saved reports.

| Where you work | Source you can open |
| --- | --- |
| Desktop | A folder on your computer, or a repository checked out through a connected source account |
| Web app | A folder already available in your profile runtime, or a connected repository checked out there |

The web app cannot browse files on your laptop. See [Installation](setup.md) and [Profiles and saved settings](profiles.md).

<a name="source-code-managers"></a>

## Connect a repository {#source-code-managers}

For a folder, choose **Open repository**, select or enter the directory, and choose **Open workspace**. Desktop provides a native folder picker; the web app browses profile folders.

For GitHub or Azure DevOps:

1. In **Review code**, choose **Connect source** or **Select repo / branch**.
2. Select a saved account, or connect an account with access to the repository.
3. Choose the repository and branch.
4. Select **Check out & open workspace**.
5. Check the repository, branch, and commit shown before starting a review.

Connected checkouts are pinned to the verified commit. If the branch moves during checkout, select it again. Local folders use the current working tree, including uncommitted changes; avoid editing the source during a review.

Manage saved accounts under **Settings → Integrations**. If an account is listed as disconnected, use **Reconnect** and check its access. See [GitHub App setup](github-app.md) for installation-based access.

Downloaded repositories use the normal temporary location unless an existing, writable optional repository store is configured. Unavailable optional storage falls back before the download starts. The selected path stays with the workspace and its saved sessions; changing storage settings does not move it. See [Repository storage](setup.md#where-scanned-repositories-are-cloned) for configuration and disconnected-disk behavior.

## Choose your experience

Use the **Experience** menu at the top of the Workbench:

- **Guided** keeps the main scan and review tasks visible.
- **Advanced** adds controls such as specialist workers, independent providers, and review budgets.

Changing the experience does not start a scan or apply a fix. The selection is saved for your active web profile or desktop installation. Advanced controls are optional; start with the defaults.

<a name="models-and-credentials"></a>

## Choose a model {#models-and-credentials}

The built-in baseline scan and sample findings report work without a model. Specialist reviews, model-based triage, and **Ask Threatlint** need a configured provider.

Open **Settings → Model provider**, choose the provider and model, and save the settings. Starting a review or chat sends prompts, supporting documents, and inspected source to that provider.

In the web app, model-server URLs and credential files are reached from the server runtime. A loopback URL there does not point to your laptop.

See [Model providers](model-providers.md) for provider setup and credential behavior.

## Scan source code

Open **Review code → Run scanners**, or choose **Scan my code** from the Guided starting path. Select the checks you want and start the scan.

The results show findings and engine coverage. Check which engines completed and which were unavailable or failed before interpreting an empty result.

When **Review suggested change** is available, inspect the proposed edit. **Apply this change & rescan** is a separate write action. Advanced automatic fixes also require an explicit opt-in. Run your application's tests after changing code.

See [Scan source code](security-scanner.md) for engine setup, supported fixes, and rescanning.

<a name="review-experience"></a>

## Run a specialist review {#review-experience}

1. Open **Review code** and choose a workflow, or use **Add a specialist**.
2. Confirm the selected workspace.
3. Enter a focused question in **Scope and additional context**.
4. Attach relevant findings or supporting documents.
5. Confirm the model, then choose **Run pipeline**.
6. Follow **Live activity**, then open the completed report in **Findings**.

For example:

> Review the invoice-download route for access between customer accounts. Explain the enforced ownership check and propose a regression test.

Specialist analysis is read-only. Suggested fixes and tests remain proposals until a separately authorized workflow applies or runs them.

**Stop review** requests cancellation. Completed reports remain available. Check the final status before starting another review. For optional worker and provider controls, see [Review orchestration](review-orchestration.md).

<a name="model-a-system-from-source-and-design"></a>

### Create a threat model {#model-a-system-from-source-and-design}

Choose **Model a system**, select the source revision, and describe the system's users, important data, and security question. Add design material when it helps explain the intended behavior.

The report should distinguish implemented controls from design assumptions and identify disagreements between them. Follow the [threat-modeling guide](threat-modeling.md) for a complete walkthrough.

<a name="design-inputs"></a>

### Add supporting documents {#design-inputs}

Use **Add supporting docs** for architecture diagrams, API specifications, documents, or images. Wait for extraction to finish and inspect the listed files before running.

You can add up to 20 files, 25 MB in total, and 10 MB per file. Images are limited to eight files of up to 5 MB each. Extracted text also has context limits; review any truncation notice. Uploading a document does not establish that its claims are true.

<a name="triaging-a-scan-report"></a>

## Review scanner findings {#triaging-a-scan-report}

Open **Finding triage** and choose the ticket system, scanner integration, or report source.

For an uploaded report, use the scanner's complete export, check the extracted findings, and select source at the scanned revision where available. Add sanitized supporting evidence for deployment-specific claims. **Import without review** saves the findings without calling a model.

For model triage, confirm the provider and start the review. In ServiceNow batches, **Parallel reviews** starts up to three findings at once by default; choose 1–8 to suit your provider. Each finding has its own progress and result. Inspect each disposition and its evidence before taking an action. Use the destination guide for [ServiceNow AVITs](avit-integration.md), [DefectDojo](integrations/defectdojo.md), or [SonarQube](integrations/sonarqube.md).

## Use findings and reports

In **Findings**, open a saved report to inspect locations, evidence, proposed corrections, and verification steps. Download Markdown or Word when available. **Triage finding** prepares a review of that finding; it does not start the model automatically.

**Resolve selected** records a decision with the evidence and attestation requested by the confirmation form. Tracker updates, scanner exceptions, and source changes have their own actions. See [Reports and exports](reports.md) and [Review findings](finding-intelligence.md).

Use **Metrics** for summaries and history. Missing or partial observations do not prove remediation. See [Metrics and dashboards](dashboards.md).

## Get help

Use **Ask Threatlint** for a focused question about the workspace or an existing report. It uses your selected model and read-only inspection tools.

Open **Learn & videos** or a control's **?** tooltip for in-app help. For connection, model, scan, or export problems, start with [Troubleshooting](troubleshooting.md).
