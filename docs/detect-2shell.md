---
title: Scan for *-2Shell and *-4Shell exposures
description: Find React2Shell, Next.js, Log4Shell, Spring4Shell and Text4Shell exposure in one repository or every repository and branch your SCM credentials can read.
---

`detect-2shell` (alias `detect-4shell`) finds framework versions affected by two families of critical remote-code-execution flaws.

## *-2Shell (JavaScript)

| CVE | What it is | Severity |
| --- | --- | --- |
| CVE-2025-55182 (React2Shell) | Unauthenticated remote code execution in `react-server-dom-webpack`, `-parcel`, `-turbopack` 19.0.0, 19.1.0, 19.1.1, 19.2.0 | Critical (CVSS 10.0) |
| CVE-2025-66478 | The same flaw in Next.js App Router (15.x, 16.x, 14.3 canaries) | Critical |
| CVE-2025-55184, CVE-2025-67779, CVE-2026-23864 | Server Function denial of service | High |
| CVE-2025-55183 | Server Function source code exposure | Medium (folded into the High finding) |

## *-4Shell (Java)

| CVE | What it is | Affected | Upgrade to | Severity |
| --- | --- | --- | --- | --- |
| CVE-2021-44228 (Log4Shell) | JNDI lookup code execution in `log4j-core` | 2.0-beta9 – 2.14.1 (except 2.3.1, 2.12.2) | 2.17.0+ (Java 8), 2.12.3 (Java 7), 2.3.1 (Java 6) | Critical (10.0) |
| CVE-2021-45046 | Incomplete Log4Shell fix (Thread Context lookups) | up to 2.15.0 | same | Critical (9.0) |
| CVE-2021-45105, CVE-2021-44832 | Recursive lookup DoS; JDBC Appender code execution | up to 2.16.0 | same | Medium |
| CVE-2022-22965 (Spring4Shell) | Data-binding code execution in Spring MVC / WebFlux | Spring Framework 5.3.0 – 5.3.17, 5.2.19.RELEASE and earlier | 5.3.18 / 5.2.20.RELEASE (Spring Boot 2.6.6 / 2.5.12) | Critical |
| CVE-2022-42889 (Text4Shell) | Interpolation code execution in `commons-text` | 1.5 – 1.9 | 1.10.0 | Critical (9.8) |

`log4j-api` on its own is not affected. Spring4Shell's known exploit needs JDK 9+ and a WAR deployed to Tomcat or another servlet container; Spring Boot executable jars are not vulnerable to it. Text4Shell is exploitable only when untrusted input reaches `StringSubstitutor` interpolation with the default lookups.

## How it works

A **deterministic detector** compares the versions your builds resolve with a catalog copied from the vendor advisories, so the same input always gives the same answer and no model is needed. It reads:

- **JavaScript:** npm, Yarn, pnpm and Bun lockfiles, plus `package.json` where no lockfile exists, and the Next.js App Router layout.
- **Java:** Maven `pom.xml` (direct dependencies, properties, Spring Boot parents), Gradle `build.gradle`/`build.gradle.kts` and `libs.versions.toml`, `gradle.lockfile`, WAR packaging, and vendored jars such as `lib/log4j-core-2.14.1.jar` (recognised by file name).

The **`appsec-2shell-detector` agent** then verifies reachability in source and writes the remediation plan.

## Run it in the Workbench

1. Connect GitHub (token or GitHub App) or Azure DevOps (PAT) under **Sources**.
2. Open **Test → 2Shell & 4Shell exposure**.
3. Pick the connected sources, then **All repositories this credential can access** or the repositories you choose.
4. Pick **Default branch**, **All branches**, or a comma-separated list such as `main, release/*`.
5. Start the scan. Results stream in per repository and branch, labelled 2Shell or 4Shell. Download the JSON or Markdown report when the run finishes.

## Run it from the command line

```bash
# One checkout
threatlint detect-2shell scan --path .

# Every repository and default branch every saved credential can read
threatlint detect-2shell fleet --all

# Every branch, as a Markdown report
threatlint detect-2shell fleet --all --branches all --output shell-exposure-report.md

# A subset: wildcards work for repositories (owner/name or project/repo) and branches
threatlint detect-2shell fleet --repo "acme/*" --repo "Payments/checkout-web" --branches "main,release/*"

# Only Azure DevOps
threatlint detect-2shell fleet --all --connection azure-devops

# Fail a pipeline on confirmed or plausible critical exposure (exit code 3)
threatlint detect-4shell scan --path . --fail-on critical
```

`detect-4shell` is the same command. `fleet` uses your saved logins: the GitHub App, `GH_TOKEN`/`GITHUB_TOKEN` or `gh auth token`, and Azure DevOps PATs from `threatlint ado login`. For repeatable runs, pass a targets file:

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
threatlint detect-2shell fleet --targets-file targets.json --format json --output exposure.json --progress
```

## Run it in CI

The **AppSec Detect 2Shell** workflow (`.github/workflows/appsec-detect-2shell.yml`, with `azure-pipelines/detect-2shell.yml` for Azure Pipelines) covers both families. It runs when a lockfile, Maven or Gradle build file, or vendored jar changes, and weekly. To sweep the fleet, choose **Actions → AppSec Detect 2Shell → Run workflow** and set **fleet** to true; leave **targets** empty for every repository's default branch. Fleet runs read the `THREATLINT_FLEET_GITHUB_TOKEN` and `THREATLINT_FLEET_ADO_PAT` secrets and the `THREATLINT_FLEET_ADO_ORG` variable.

## Run it over MCP

Assistants connected to the Workbench MCP server can call `start_2shell_scan` (with `confirm: true`), `get_2shell_scan`, `list_2shell_scans` and `cancel_2shell_scan`. They scan for both families. See [MCP tools](mcp-tools.md).

## Read the results

| Confidence | Meaning |
| --- | --- |
| CONFIRMED | A lockfile, `gradle.lockfile`, vendored jar or direct Maven dependency pins an affected version, and the code path is reachable as built. |
| PLAUSIBLE | The affected version is likely but not pinned (a `package.json` range, a Gradle declaration, a Spring Boot parent), or an exploit precondition is unconfirmed (Spring without WAR packaging, Text4Shell usage). |
| THEORETICAL | An affected Next.js version with no App Router files. Not reachable as built; upgrade anyway. |

Every finding names its family, the file and line, the installed version, and the version to upgrade to. A target marked **error** could not be read and is not a clean result.

After upgrading an exposed internet-facing app, rotate the secrets it can read and review web, WAF and application logs from before the upgrade for Server Function requests (*-2Shell), `${jndi:` lookup strings (Log4Shell) and `class.module` data-binding payloads (Spring4Shell).

## What the scan reads and records

- Fleet scans list each branch's file tree and download only package manifests, lockfiles and Java build files. Jars are recognised by name and never downloaded. Scans never clone, never download other source files, never write to an SCM, and never send traffic to running applications.
- Tokens are sent only to the configured SCM API host. They are never written to disk, logs, reports or responses.
- **Aggregate metrics.** Each run appends one line of counts to `~/.threatlint/detect-2shell/metrics.jsonl` on the machine that runs the scan (for the hosted Workbench, the ThreatLint server). The line holds the run time, mode, provider names, target and result counts, and findings counted by severity, confidence and advisory. It holds no repository, organization, project or branch names, file paths, commits or credentials. The file is created owner-only and is write-only from ThreatLint's side: no Workbench route, MCP tool or report reads it back. Set `THREATLINT_2SHELL_METRICS=off` to turn it off.

## Coverage limits

- The catalog covers the advisories above. Other similarly named flaws (for example PHP2Shell or WP2Shell) are not detected until vendor-verified version data is added to `src/threatlint/detect_2shell/advisories.py`.
- Dependencies Maven or Gradle pull in transitively are only seen when a lockfile or vendored jar records them; run `mvn dependency:tree` or `gradle dependencies` for a full picture. Copies shaded inside other jars or baked into container images are outside the deterministic check; the agent looks for them in source.
- GitHub truncates file trees for very large repositories; the report says when that happens.
