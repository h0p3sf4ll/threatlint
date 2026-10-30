# SonarQube integration

Threatlint reviews SonarQube (or SonarCloud) vulnerabilities and security hotspots with the Findings triage agent
and writes the verdict back. It follows the [DefectDojo](defectdojo-integration.md) and
[ServiceNow AVIT](avit-integration.md) flows, through the same scanner-adapter package
(`src/threatlint/scanners/`).

## What you need

| Item | Where it comes from |
| --- | --- |
| Base URL (HTTPS) | e.g. `https://sonarqube.example.test` or a context path such as `https://example.test/sonarqube`; SonarCloud: `https://sonarcloud.io` |
| User token | SonarQube → My Account → Security |
| Permissions | **Browse** on the project to read; **Administer Issues** to comment and transition issues; **Administer Security Hotspots** to change hotspot status |
| Repository | The project's SCM link (Project Settings → Links), or its DevOps platform binding; otherwise `--repo-url` / `THREATLINT_SONAR_REPO_URL` |

## Credentials

1. `THREATLINT_SONAR_URL` and `THREATLINT_SONAR_TOKEN`
2. `~/.threatlint/sonarqube.json` (mode `0600`), written by `threatlint sonar login` or *Workbench → Settings →
   SonarQube* after `GET /api/authentication/validate` accepts the token
3. Parameter Store via `THREATLINT_SONAR_TOKEN_PARAMETER` (or `sonarTokenParameter` in `org.json`)
4. An interactive prompt (not saved)

The token is sent as HTTP Basic user with an empty password (accepted by every SonarQube version and SonarCloud).
Redirects are refused.

## CLI

```bash
threatlint sonar login --url https://sonarqube.example.test
threatlint sonar fetch AYxExampleKey01 SONAR-HOTSPOT-AYxExampleKey02 -o sonar.md
threatlint sonar fetch --project web --branch develop --severity CRITICAL -o sonar.md
threatlint sonar checkout SONAR-AYxExampleKey01 --dir /tmp/sonar-1 [--repo-url URL] [--branch NAME]
threatlint sonar resolve SONAR-AYxExampleKey01 --report fp_review.md --report-url https://wiki.example.test/r/1   # asks first; --yes
threatlint sonar note SONAR-AYxExampleKey01 --message "…"
```

References: `SONAR-<issue key>` and `SONAR-HOTSPOT-<hotspot key>`; a bare key is tried as an issue, then as a hotspot.
Filters: `--project` (required for a search), `--branch` or `--pull-request`, `--organization` (SonarCloud),
`--type` (default `VULNERABILITY` and `SECURITY_HOTSPOT`), `--severity`, `--status` (issues default
`OPEN,CONFIRMED,REOPENED`; hotspots default `TO_REVIEW`), `--limit`.

Mapping: component key → `components[].path` (or the part after `project:`) for the file; `line` / `textRange`;
rule key; issue branch or the requested branch; repository from the SCM link or DevOps binding.

## Resolve

SonarQube cannot store attachments, so the comment carries a one-line summary (finding id, confidence, title) and
says where the full report lives: `--report-url`, or the report's file name when none is given.

| Verdict | Issues | Hotspots |
| --- | --- | --- |
| FALSE POSITIVE | `add_comment`, then `do_transition` `falsepositive` | `change_status` `REVIEWED` / `SAFE` with the comment |
| TRUE POSITIVE | `add_comment`, then `do_transition` `confirm` (when the server refuses Confirm, the comment stands) | `add_comment` only |
| AMBIGUOUS | `add_comment` only | `add_comment` only |

The comment starts with *“Closed by Threatlint as a false positive.”*, *“True positive per Threatlint review; left
open.”*, or *“Ambiguous per Threatlint review; left open pending the evidence the report names.”*

## API calls

`GET /api/issues/search`, `GET /api/hotspots/search`, `GET /api/hotspots/show`, `GET /api/project_links/search`,
`GET /api/alm_settings/get_binding`, `GET /api/authentication/validate`, `POST /api/issues/add_comment`,
`POST /api/issues/do_transition`, `POST /api/hotspots/change_status`, `POST /api/hotspots/add_comment`.

## Workbench

- **Settings → SonarQube**: URL and token.
- **SonarQube review**: keys or project/branch filters; one report per finding in **Findings**; **Post to SonarQube…**
  per finding after confirmation, with an optional HTTPS location for the full report.
- **Import scan report** accepts a SonarQube `/api/issues/search` or `/api/hotspots/search` JSON; **Post to
  SonarQube…** posts each imported issue or hotspot back to itself.

## Adding another scanner

Subclass `threatlint.scanners.base.Adapter` (connection, `parse_references`, `fetch`, `search`, `resolve`, `note`,
`validate_token`), register it in `threatlint.scanners.registry()`, and `threatlint <command> fetch|checkout|resolve|note|login`
follows. Add a matching entry to `web/lib/scanners.cjs` `TOOLS` for the Workbench.

## Limits

Verified only against mocked HTTP using SonarQube's documented Web API shapes. SonarQube 10.x+ may not offer the
`confirm` transition; the comment then records the verdict.
