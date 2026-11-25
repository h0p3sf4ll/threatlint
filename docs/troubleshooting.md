---
title: Troubleshooting
description: Resolve common repository, sign-in, model, scanner, and report problems.
---

# Troubleshooting

Start with the job's status and error message. Check which profile, repository, and provider were selected before retrying an action.

## I cannot select a repository

On the desktop, select a local folder containing the repository. On the web, connect a source provider and check out a repository into the hosted workspace; the browser cannot open a folder on your laptop.

For private repositories, confirm that the saved source connection has access to the intended organization and repository. See [Use the Workbench](workbench.md#source-code-managers).

## Company sign-in fails, or my settings look different

Confirm the company slug, provider identity, and signed-in profile in the top bar. Your personal, company, and desktop profiles have separate settings. Company access requires an administrator to add the identity you use; a matching email domain does not enroll you automatically.

See [Profiles and saved settings](profiles.md). Do not create a second provider identity to recover settings from the first.

## A model review cannot start

Check the selected provider, model identifier, credentials, and any required region or sharing consent. Source-provider login and model-provider login can be separate steps. For a CLI-backed provider, confirm its executable is available to the app and its own authentication is complete.

You can still run supported source scans without a model. See [Model providers](model-providers.md).

## Semgrep is unavailable on the desktop

Install Semgrep using the supported setup, confirm `semgrep --version` works, then restart Threatlint so it receives the updated PATH. See [Semgrep on Windows desktop](security-scanner.md#semgrep-on-windows-desktop).

Semgrep Community Edition source scans do not require a Semgrep login. If one engine completes while the overall job is **partial**, inspect the coverage summary for unavailable or unsupported engines. Partial coverage does not mean every configured scanner ran.

## A scan returned no findings

Check the selected repository, revision, rules, file scope, and engine status. An empty or partial result is not proof that the code is secure. Read [Scan source code](security-scanner.md) and record any coverage limits with the report.

## A report has no Word download

Some paths save Markdown first or require an explicit conversion step. Open the saved report and follow [Convert an existing report](reports.md#convert-an-existing-report). Keep the original report if conversion fails.

## A tracker update failed or has an uncertain result

Check the destination connection and provider status before retrying. If ticket creation is uncertain, look for its Threatlint reference in the provider and import the existing ticket. See [Manage connections and tickets](integrations.md#recover-an-uncertain-ticket-creation).

## Saved state cannot be read

Keep the original files and error message. Do not delete a profile to clear a read error. Ask your administrator to recover a trusted backup or investigate the state directory. For self-hosted deployments, use the [self-hosting reference](web-app.md).
