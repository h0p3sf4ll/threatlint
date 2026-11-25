---
slug: /
title: Introduction
description: Get started with Threatlint and find guides for scanning, reviewing, and managing application security findings.
---

# Threatlint documentation

Threatlint helps you scan source code, review security findings, and produce reports with supporting evidence. Use the [web app](https://app.threatlint.dev) with a personal or company profile, or run the desktop app without a Threatlint account.

## Start here

1. [Follow the Quickstart](learning.md) to scan a small repository and read the results.
2. [Install Threatlint](setup.md) if you want to work from your desktop or terminal.
3. [Configure a model provider](model-providers.md) when you are ready for specialist reviews and threat modeling. Source scans do not require a model.

See [Profiles and saved settings](profiles.md) for sign-in, company workspaces, and the settings saved to each profile.

## Common tasks

| I want to… | Guide |
| --- | --- |
| Connect a repository and navigate the app | [Use the Workbench](workbench.md) |
| Run Semgrep and review suggested fixes | [Scan source code](security-scanner.md) |
| Review a design alongside its implementation | [Create a threat model](threat-modeling.md) |
| Verify findings and track repository risk | [Review findings](finding-intelligence.md) |
| Review results from supported sources and export reports | [Reports and exports](reports.md) |
| Pull existing issues or create and track tickets | [Manage connections and tickets](integrations.md) |
| Run scans and reviews from MCP clients or scripts | [MCP and headless workflows](mcp.md) |

## Explore further

Use **Integrations** for source providers, issue trackers, and collaboration tools. **Automation** covers editors, CI, and batch reviews. **Reference** includes specialist roles, advanced scanners, and self-hosting.

If a step fails, start with [Troubleshooting](troubleshooting.md). Check each report's scope and coverage before treating an empty result as evidence that a repository is secure.
