---
title: Quickstart
description: Open a workspace, run a small scan, and optionally follow up with a specialist review.
---

# Quickstart

Run a first scan, inspect one result, and learn how to request a focused review. The built-in baseline does not need a model account or API key.

## Before you start

Open the [web app](https://app.threatlint.dev) or your installed desktop app. If you need it, follow [Installation](setup.md). On the web, choose the correct [personal or company profile](profiles.md).

Use a small repository you are authorized to inspect. You do not need to configure every integration or model provider first.

## 1. Open your source

In **Review code**, choose **Open repository** for an available folder, or **Connect source** to select a GitHub or Azure DevOps repository and branch. Choose **Check out & open workspace** for a connected repository.

Desktop can open folders on your computer. The web app opens source in your server profile; it cannot browse your laptop.

**Expected result:** the Workbench shows your workspace. Confirm its branch and commit where available.

## 2. Run a scan

1. Set **Experience** to **Guided**.
2. Choose **Scan my code** to open the scanner.
3. Select the checks you want. The baseline runs without a model; installed Semgrep and Trivy engines add coverage.
4. Start the scan. Leave automatic fixes off for this first run.

**Expected result:** findings and engine-status cards. An unavailable engine means that coverage was not obtained. Read [Scan source code](security-scanner.md) if you need to install an optional engine.

## 3. Inspect one result

Open a finding and identify its location, impact, evidence, and suggested correction. Check the declared scan scope before treating an empty result as reassuring.

If **Review suggested change** is available, inspect the before-and-after diff. Applying a change is a separate action. After any approved edit, rescan and run your application's tests.

**Expected result:** you can explain what the scan observed and what still needs verification. You can stop here without configuring a model.

## 4. Request a specialist review (optional)

Configure a [model provider](model-providers.md), then return to **Review code**. Choose **Add a specialist** and select a role for your question, or choose **Model a system** for a threat model.

For example, use the [authentication reviewer](agents.md#appsec-auth-reviewer) for a password-reset flow:

> Review the password-reset flow. Explain how an expired token is rejected and propose an acceptance test.

Confirm the workspace and model, then choose **Run pipeline**. Specialist analysis is read-only; a proposed test is not a test result.

**Expected result:** a saved report in **Findings** with evidence, recommendations, and stated limits.

## Next steps

- [Use the Workbench](workbench.md) to connect source and manage reviews.
- [Create a threat model](threat-modeling.md) using source and design material.
- [Read and export reports](reports.md) or [review connected findings](finding-intelligence.md).
- Use [Troubleshooting](troubleshooting.md) if a step fails.
