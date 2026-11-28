---
title: Scan for React2Shell across repositories
description: Find CVE-2025-55182, CVE-2025-66478 and follow-up exposure in one repository or every repository and branch your SCM credentials can read.
---

`detect-2shell` finds React Server Components and Next.js versions affected by the React2Shell family:

| CVE | What it is | Severity |
| --- | --- | --- |
| CVE-2025-55182 | Unauthenticated remote code execution in `react-server-dom-webpack`, `-parcel`, `-turbopack` 19.0.0, 19.1.0, 19.1.1, 19.2.0 | Critical (CVSS 10.0) |
| CVE-2025-66478 | The same flaw in Next.js App Router (15.x, 16.x, 14.3 canaries) | Critical |
| CVE-2025-55184, CVE-2025-67779, CVE-2026-23864 | Server Function denial of service | High |
| CVE-2025-55183 | Server Function source code exposure | Medium (folded into the High finding) |

The scan has two parts. A **deterministic detector** compares the versions your lockfiles resolve with a catalog copied from the vendor advisories, so the same input always gives the same answer and no model is needed. The **`appsec-2shell-detector` agent** then verifies reachability in source and writes the remediation plan.

## Run it in the Workbench

1. Connect GitHub (token or GitHub App) or Azure DevOps (PAT) under **Sources**.
2. Open **Test → 2Shell exposure**.
3. Pick the connected sources, then **All repositories this credential can access** or the repositories you choose.
4. Pick **Default branch**, **All branches**, or a comma-separated list such as `main, release/*`.
5. Choose **Scan for 2Shell exposure**. Results stream in per repository and branch. Download the JSON or Markdown report when the run finishes.

## Run it from the command line

```bash
# One checkout
threatlint detect-2shell scan --path .

# Every repository and default branch every saved credential can read
threatlint detect-2shell fleet --all

# Every branch, as a Markdown report
threatlint detect-2shell fleet --all --branches all --output 2shell-report.md

# A subset: wildcards work for repositories (owner/name or project/repo) and branches
threatlint detect-2shell fleet --repo "acme/*" --repo "Payments/checkout-web" --branches "main,release/*"

# Only Azure DevOps
threatlint detect-2shell fleet --all --connection azure-devops

# Fail a pipeline on confirmed or plausible critical exposure (exit code 3)
threatlint detect-2shell scan --path . --fail-on CRITICAL
```

`fleet` uses your saved logins: the GitHub App, `GH_TOKEN`/`GITHUB_TOKEN` or `gh auth token`, and Azure DevOps PATs from `threatlint ado login`. For repeatable runs, pass a targets file:

```json
{
  "connections": [
    { "connection": "github", "repositories": "all", "branches": "default" },
    { "connection": "azure-devops:contoso", "repositories": ["Retail/*"], "branches": ["main", "release/*"] }
  ],
  "maxRepositories": 500,
  "maxBranchesPerRepository": 50
}
```

```bash
threatlint detect-2shell fleet --targets-file targets.json --format json --output 2shell.json --progress
```

## Run it in CI

The **AppSec Detect 2Shell** workflow (`.github/workflows/appsec-detect-2shell.yml`, with `azure-pipelines/detect-2shell.yml` for Azure Pipelines) runs when a lockfile changes and weekly. To sweep the fleet, choose **Actions → AppSec Detect 2Shell → Run workflow** and set **fleet** to true. Fleet runs read the `THREATLINT_FLEET_GITHUB_TOKEN` and `THREATLINT_FLEET_ADO_PAT` secrets and the `THREATLINT_FLEET_ADO_ORG` variable.

## Run it over MCP

Assistants connected to the Workbench MCP server can call `start_2shell_scan` (with `confirm: true`), `get_2shell_scan`, `list_2shell_scans` and `cancel_2shell_scan`. See [MCP tools](mcp-tools.md).

## Read the results

| Confidence | Meaning |
| --- | --- |
| CONFIRMED | A lockfile resolves an affected version, and the code path is reachable (App Router present for Next.js). |
| PLAUSIBLE | `package.json` allows an affected version and no lockfile pins what is installed. Confirm with the deployed build. |
| THEORETICAL | An affected Next.js version with no App Router files. Not reachable as built; upgrade anyway. |

Every finding names the lockfile line, the installed version, and the version to upgrade to on the same release line. A target marked **error** could not be read and is not a clean result.

If an internet-facing app ran an affected version after 2025-12-04, upgrade it, redeploy, rotate the secrets it can read, and review web and WAF logs for Server Function requests from before the upgrade.

## What the scan reads and records

- Fleet scans list each branch's file tree and download only `package.json` files and npm, Yarn, pnpm and Bun lockfiles. They never clone, never download other source files, never write to an SCM, and never send traffic to running applications.
- Tokens are sent only to the configured SCM API host. They are never written to disk, logs, reports or responses.
- **Aggregate metrics.** Each run appends one line of counts to `~/.threatlint/detect-2shell/metrics.jsonl` on the machine that runs the scan (for the hosted Workbench, the ThreatLint server). The line holds the run time, mode, provider names, target and result counts, and findings counted by severity, confidence and advisory. It holds no repository, organization, project or branch names, file paths, commits or credentials. The file is created owner-only and is write-only from ThreatLint's side: no Workbench route, MCP tool or report reads it back. Set `THREATLINT_2SHELL_METRICS=off` to turn it off.

## Coverage limits

- The catalog covers the React2Shell family above. Other similarly named flaws (for example PHP2Shell or WP2Shell) are not detected until vendor-verified version data is added to `src/threatlint/detect_2shell/advisories.py`.
- Copies bundled into build output or container images without a lockfile are outside the deterministic check; the agent looks for them in source.
- GitHub truncates file trees for very large repositories; the report says when that happens.
