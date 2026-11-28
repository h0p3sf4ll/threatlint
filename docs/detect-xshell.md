---
title: Scan for *-Shell exposures (detect-xshell)
description: Find *-2Shell and *-4Shell remote-code-execution exposure, including impacted versions with no fix, in one repository or every repository and branch your SCM credentials can read.
---

`detect-xshell` finds framework, library and runtime versions affected by the *-2Shell and *-4Shell families of critical remote-code-execution flaws. `detect-2shell` and `detect-4shell` are aliases for the same command.

It reports **every impacted version, including release lines that have no fix**. An end-of-life Node.js, PHP or JDK line is still flagged, marked *no fix on this line*, so teams know they are affected and that the only remedy is moving to a supported release.

## *-2Shell

| Flaw | CVE | Component | Affected | Upgrade to | Severity |
| --- | --- | --- | --- | --- | --- |
| React2Shell | CVE-2025-55182 | `react-server-dom-webpack` / `-parcel` / `-turbopack` | 19.0.0, 19.1.0, 19.1.1, 19.2.0 | 19.0.4 · 19.1.5 · 19.2.4 (also closes the follow-ups) | Critical (10.0) |
| React2Shell in Next.js | CVE-2025-66478 | `next` (App Router) | 15.x, 16.x, 14.3 canaries | 15.0.8 · 15.1.12 · 15.2.9 · 15.3.9 · 15.4.11 · 15.5.10 · 16.0.11 · 16.1.5 | Critical |
| RSC follow-ups | CVE-2025-55184, -67779, CVE-2026-23864, CVE-2025-55183 | same packages | 19.0.0 – 19.2.3; Next.js from 13.3 | as above | High |
| RSC typed-array RCE (2026) | CVE-2026-126187 | RSC packages; `next` | 19.0.0–19.0.8, 19.1.0–19.1.9, 19.2.0–19.2.8, 19.3.0; `next` 16.0 – 16.4.0 | 19.0.9 · 19.1.10 · 19.2.9 · 19.3.1; `next` 16.4.1 | Critical (9.5), rare preconditions |
| PHP2Shell (2026) | CVE-2026-109618, -109619 | PHP runtime | below 8.2.35, 8.3.36, 8.4.27, 8.5.12; **7.4–8.1 impacted, no official fix** | 8.2.35 · 8.3.36 · 8.4.27 · 8.5.12 | Critical (9.2), CISA KEV |
| PHP session serializer RCE (2026) | CVE-2026-115560 | PHP runtime | below 8.2.36, 8.3.37, 8.4.28, 8.5.13; **8.1 and older impacted, no fix** | 8.2.36 · 8.3.37 · 8.4.28 · 8.5.13 · 8.6.0 | Critical (9.2), needs upload progress + serializer mismatch + gadget chain |
| WP2Shell (2026) | CVE-2026-63030 (+ CVE-2026-60137) | WordPress core | 6.9.0–6.9.4, 7.0.0–7.0.1, 7.1-beta1 (SQLi half also 6.8.0–6.8.5) | 6.9.5 · 7.0.2 (6.8.6) | Critical (9.8), CISA KEV |
| Node2Shell (2026) | CVE-2026-111497 | Node.js runtime; PyPI `brotli`, `brotlicffi` | Node 22 < 22.23.4, 24 < 24.22.1, 26 < 26.12.1, **EOL lines (20 and older, odd releases) impacted, no fix**; `brotli` < 1.0.10 / 1.1.1 / 1.2.1, `brotlicffi` < 1.2.1.0 | Node 22.23.4 · 24.22.1 · 26.12.1; `brotli` 1.2.1; `brotlicffi` 1.2.1.0 | Critical (9.2), CISA KEV |

## *-4Shell

| Flaw | CVE | Component | Affected | Upgrade to | Severity |
| --- | --- | --- | --- | --- | --- |
| Log4Shell | CVE-2021-44228 (+ -45046, -45105, -44832) | `log4j-core` | 2.0-beta9 – 2.16.0 (2.3.1, 2.12.3 patched) | 2.17.0+ (Java 8) · 2.12.3 (Java 7) · 2.3.1 (Java 6) | Critical (10.0) |
| Spring4Shell | CVE-2022-22965 | Spring Framework (`spring-beans`, `-webmvc`, `-webflux`); Spring Boot | 5.3.0–5.3.17, 5.2.0–5.2.19; **5.1 and older impacted, no fix**; Boot < 2.5.12, 2.6.0–2.6.5 | 5.3.18 · 5.2.20 (Boot 2.6.6 · 2.5.12) | Critical |
| Text4Shell | CVE-2022-42889 | `commons-text` | 1.5 – 1.9 | 1.10.0 | Critical (9.8) |
| Java4Shell (2026) | CVE-2026-114938 | JDK (HotSpot) | 17.0.6+ < 17.0.21.1, 21 < 21.0.13.1, 25 < 25.0.5.1, 27 < 27.0.1.1; **non-LTS 18–20, 22–24, 26 impacted, no fix**; 8 and 11 not affected | 17.0.21.1 · 21.0.13.1 · 25.0.5.1 · 27.0.1.1 | High (8.1; Red Hat 9.8), AVX-512 VBMI CPUs only |

Java4Shell fixed versions come from Debian, Ubuntu and Corretto packages because Oracle's advisory was unreachable when the catalog was built, so its findings are PLAUSIBLE at most; confirm with your JDK vendor.

## What it reads

A **deterministic detector** compares exact versions with a catalog copied from vendor advisories, so the same input always gives the same answer and no model is needed.

| Evidence | Examples | Confidence |
| --- | --- | --- |
| Lockfiles | npm, Yarn, pnpm, Bun lockfiles; `gradle.lockfile`; `composer.lock` (WordPress core packages); `poetry.lock`, `uv.lock`, `Pipfile.lock` | CONFIRMED |
| Build pins | direct Maven dependencies in `pom.xml`; vendored jars such as `lib/log4j-core-2.14.1.jar`; Docker `FROM php:8.3.10-apache`, `FROM node:22.23.3`, `FROM eclipse-temurin:21.0.13_11-jdk`, `FROM wordpress:6.9.3`; `wp-includes/version.php`; `requirements.txt` `==` pins | CONFIRMED |
| PHP session configuration | `session.upload_progress.enabled` and `session.serialize_handler` in `php.ini`, `conf.d/*.ini`, FPM pools, `.htaccess`, `.user.ini`, Dockerfile `echo` lines | Exposure context for CVE-2026-115560 |
| Declarations and tooling pins | `package.json` ranges; Gradle builds and `libs.versions.toml`; Spring Boot parents; `.nvmrc`, `.node-version`, `.tool-versions`, `.java-version`, `.sdkmanrc`, `package.json` `volta`, composer `config.platform.php`, CI `setup-node` / `setup-php` / `setup-java` versions | PLAUSIBLE |

Floating tags such as `node:22` or `php:8.3-apache` resolve to whatever patch is current, so they are ignored. Exposure is then graded: Next.js App Router layout, Spring WAR packaging, and flaws whose preconditions a repository cannot show (Node2Shell's untrusted Brotli input, Java4Shell's CPU requirement, the rare RSC typed-array case, Text4Shell's `StringSubstitutor` use) are reported as PLAUSIBLE.

The **`appsec-xshell-detector` agent** then verifies reachability in source and writes the remediation plan.

## Run it in the Workbench

1. Connect GitHub (token or GitHub App) or Azure DevOps (PAT) under **Sources**.
2. Open **Test → *-Shell exposure**.
3. Pick the connected sources, then **All repositories this credential can access** or the repositories you choose.
4. Pick **Default branch**, **All branches**, or a comma-separated list such as `main, release/*`.
5. Select **Scan for *-Shell exposure**. Results stream in per repository and branch, labelled 2Shell or 4Shell, with *No fix on this line* where applicable. Download the JSON or Markdown report when the run finishes.

## Run it from the command line

```bash
# One checkout
threatlint detect-xshell scan --path .

# Every repository and default branch every saved credential can read
threatlint detect-xshell fleet --all

# Every branch, as a Markdown report
threatlint detect-xshell fleet --all --branches all --output xshell-report.md

# A subset: wildcards work for repositories (owner/name or project/repo) and branches
threatlint detect-xshell fleet --repo "acme/*" --repo "Payments/checkout-web" --branches "main,release/*"

# Only Azure DevOps
threatlint detect-xshell fleet --all --connection azure-devops

# Fail a pipeline on confirmed or plausible critical exposure (exit code 3)
threatlint detect-xshell scan --path . --fail-on critical
```

`fleet` uses your saved logins: the GitHub App, `GH_TOKEN`/`GITHUB_TOKEN` or `gh auth token`, and Azure DevOps PATs from `threatlint ado login` (or `THREATLINT_ADO_PAT` with `THREATLINT_ADO_ORG`). For repeatable runs, pass a targets file:

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
threatlint detect-xshell fleet --targets-file targets.json --format json --output exposure.json --progress
```

## Run it in CI

The **AppSec Detect *-Shell** workflow (`.github/workflows/appsec-detect-xshell.yml`, with `azure-pipelines/detect-xshell.yml` for Azure Pipelines) runs when a lockfile, build file, Dockerfile, runtime version file or vendored jar changes, and weekly. To sweep the fleet, choose **Actions → AppSec Detect *-Shell → Run workflow** and set **fleet** to true; leave **targets** empty for every repository's default branch. Fleet runs read the `THREATLINT_FLEET_GITHUB_TOKEN` and `THREATLINT_FLEET_ADO_PAT` secrets and the `THREATLINT_FLEET_ADO_ORG` variable.

## Run it over MCP

Assistants connected to the Workbench MCP server can call `start_xshell_scan` (with `confirm: true`), `get_xshell_scan`, `list_xshell_scans` and `cancel_xshell_scan`. See [MCP tools](mcp-tools.md).

## Read the results

| Field | Meaning |
| --- | --- |
| Family | 2Shell or 4Shell. |
| Confidence | CONFIRMED: pinned evidence and reachable as built. PLAUSIBLE: likely but unpinned, or an exploit precondition is unconfirmed. THEORETICAL: affected Next.js version with no App Router files. |
| Fixed in / `fixAvailable` | The version to upgrade to on the same release line. `fixAvailable: false` means the line is impacted and has **no fix**: move to a supported release line. |

A target marked **error** could not be read and is not a clean result.

After upgrading an exposed internet-facing app, rotate the secrets it can read and review web, WAF and application logs from before the upgrade for Server Function requests (React2Shell), `${jndi:` strings (Log4Shell), `class.module` parameters (Spring4Shell), and unexpected `/batch/v1` REST calls (WP2Shell).

## What the scan reads and records

- Fleet scans list each branch's file tree and download only manifests, lockfiles and runtime version files (Dockerfiles, `.nvmrc`, `.tool-versions`, composer files, CI workflow files, `wp-includes/version.php`). Jars are recognised by name and never downloaded. Scans never clone, never download other source files, never write to an SCM, and never send traffic to running applications.
- Tokens are sent only to the configured SCM API host. They are never written to disk, logs, reports or responses.
- **Aggregate metrics.** Each run appends one line of counts to `~/.threatlint/detect-xshell/metrics.jsonl` on the machine that runs the scan (for the hosted Workbench, the ThreatLint server). The line holds the run time, mode, provider names, target and result counts, and findings counted by severity, confidence and advisory. It holds no repository, organization, project or branch names, file paths, commits or credentials. The file is created owner-only and is write-only from ThreatLint's side: no Workbench route, MCP tool or report reads it back. Set `THREATLINT_XSHELL_METRICS=off` to turn it off.

## Coverage limits

- Only vendor-verified advisories are in the catalog (`src/threatlint/detect_xshell/advisories.py`).
- CVE-2026-115560 findings are PLAUSIBLE at most: a repository cannot prove the serializer mismatch on a shared session store. The finding adds configuration context: whether `session.upload_progress.enabled` is explicitly On, disabled administratively (php.ini, FPM pool, server config or a Dockerfile `conf.d` write; `.user.ini` and `ini_set()` do not count), and which `session.serialize_handler` values are set. A patched runtime with upload progress explicitly enabled and mismatched serializers is still exposed; check that in review. Ubuntu 22.04 and older and RHEL PHP 8.0 and older builds hard-disable upload progress, so upstream version matching over-reports on them.
- Runtime versions are only visible where a repository pins them exactly; managed hosting, base images built elsewhere and auto-updating WordPress sites may differ from the repository.
- Dependencies Maven or Gradle pull in transitively are only seen when a lockfile or vendored jar records them; copies shaded inside other jars or baked into images are outside the deterministic check.
- GitHub truncates file trees for very large repositories; the report says when that happens.
