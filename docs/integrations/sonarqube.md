# SonarQube integration

**Integration type: scanning tool.** SonarQube and SonarCloud analyze code themselves and own the issues
they raise, so verdicts go through SonarQube's own issue workflow. Compare the
[DefectDojo findings-management integration](defectdojo.md) and the [integration types](README.md).

Decide whether an issue or hotspot needs action, then record the evidence where your team works.
Threatlint triages SonarQube/SonarCloud findings. Reviewing changes no server status; posting
requires separate confirmation.

## What you need

| Requirement | Action |
| --- | --- |
| HTTPS base URL | SonarQube origin/context path (`https://example.test/sonarqube`) or `https://sonarcloud.io` |
| User token | **My Account → Security** |
| Read permissions | **Browse** on the project |
| Posting permissions | **Administer Issues** / **Administer Security Hotspots**, as applicable |
| Source and model | SCM link or DevOps binding; GitHub/Azure DevOps access; [configured model](../setup.md) |
| Direct CLI triage | Semgrep Community Edition on PATH (`semgrep --version`); `run fp-review` requires it |

## CLI

Replace the sample URL/key with an authorized issue:

1. Validate/save credentials:

   ```bash
   threatlint sonar login --url https://sonarqube.example.test
   ```

2. Fetch one issue and check out its source:

   ```bash
   threatlint sonar fetch AYxExampleKey01 -o sonar.md
   threatlint sonar checkout SONAR-AYxExampleKey01 --dir ./sonar-review
   ```

3. Run triage from the checkout (LM Studio by default; change `--provider` as needed):

   ```bash
   (cd sonar-review && threatlint run fp-review --findings ../sonar.md --provider lmstudio)
   ```
4. Inspect the report before [posting](#resolve).

**Result:** an artifact and advisory report, no server updates. Without source mapping, supply
`--repo-url URL` / `--branch NAME`, or disclose an evidence-only review.

References are `SONAR-<issue-key>` and `SONAR-HOTSPOT-<hotspot-key>`. A bare key is tried as an
issue, then a hotspot. Preserve that full reference in the report's **Original finding** field.
Explicit lists allow up to 50 findings.

```bash
threatlint sonar fetch --project web --branch develop --severity CRITICAL -o sonar.md
```

Search filters: required `--project`; `--branch` or `--pull-request`;
`--organization` for SonarCloud; repeatable `--type`, `--severity`, `--status`; `--limit`
(default 50, maximum 500). Types default to `VULNERABILITY` and `SECURITY_HOTSPOT`.
Issues default to `OPEN,CONFIRMED,REOPENED`; hotspots to `TO_REVIEW`.

File/line: `components[].path` (else suffix after `project:`), `line` / `textRange`.
Repository: SCM link → DevOps binding; `THREATLINT_SONAR_REPO_URL` overrides.
Verify reviewed branch/revision matches the scan.

## Credentials

CLI: `THREATLINT_SONAR_URL` / `THREATLINT_SONAR_TOKEN` → saved
`~/.threatlint/sonarqube.json` → Parameter Store token → unsaved interactive prompt.
`THREATLINT_HOME` relocates the saved file. Login calls `GET /api/authentication/validate`
before saving with POSIX mode `0600`; protect Windows ACLs too.

Parameter Store: `THREATLINT_SONAR_TOKEN_PARAMETER` or `sonarTokenParameter` in `~/.threatlint/org.json`,
using your AWS session (`--aws-profile`). Workbench shares the file; direct connections prefer
saved values over environment. Tokens use HTTP Basic with an empty password; redirects are refused.

## Resolve

SonarQube stores **no attachments**. Publish the report for authorized reviewers and supply its URL:

```bash
threatlint sonar resolve SONAR-AYxExampleKey01 --report fp_review.md \
  --report-url https://reports.example.test/reviews/123
```

The CLI asks first; `--yes` authorizes writes without prompting. Without `--report-url`, comments
name a local file, not a shared report. `--docx` names a file but does not upload it.

| Verdict | Issue | Security hotspot |
| --- | --- | --- |
| FALSE POSITIVE | Add summary comment, then `falsepositive` transition | Mark `REVIEWED` / `SAFE` with comment |
| TRUE POSITIVE | Add comment, attempt `confirm` | Comment only |
| AMBIGUOUS | Comment only | Comment only |

Comments include ID, confidence, title, outcome, and report location. Unavailable Confirm (HTTP 400)
leaves the comment; other failures are reported. Writes are nontransactional: inspect server state before retrying.

For a status-neutral note, use
`threatlint sonar note SONAR-AYxExampleKey01 --message "Awaiting matching scan revision."`
(confirmation required).

## Workbench

1. Save URL/token in **Settings → SonarQube**.
2. Open **SonarQube review** with keys or project/branch filters; run and inspect each report
   in **Findings**.
3. Select **Post to SonarQube…**, supply an optional HTTPS report location, and confirm.

**Import scan report** also accepts `/api/issues/search` and `/api/hotspots/search` JSON exports;
posting maps each imported result back to its issue/hotspot.
Workbench review batches allow at most 50 findings; narrow filters if more match.
See [Workbench import limits](../workbench.md#importing-a-scan-report).

## API calls

Reads: `/api/issues/search`, `/api/hotspots/search`, `/api/hotspots/show`,
`/api/project_links/search`, `/api/alm_settings/get_binding`, `/api/authentication/validate`.
Writes: `/api/issues/add_comment`, `/api/issues/do_transition`,
`/api/hotspots/change_status`, `/api/hotspots/add_comment`.

## Adding another scanner

Implement `threatlint.scanners.base.Adapter` connection, reference parsing, fetch/search,
resolve/note, and token-validation methods; register it in `threatlint.scanners.registry()`.
Add a matching `TOOLS` entry in `web/lib/scanners.cjs` for Workbench integration.
See [Development](../development.md) and [Writing an integration](authoring.md) before changing this integration.

## Limits

[Python](../../tests/test_integrations.py) and [Workbench](../../web/tests/scanners.test.cjs) tests use mocked
Web API responses, not live certification. Transitions vary by version/state; newer servers may
omit Confirm. Verdicts do not establish suppression safety or runtime exploitability.

## Troubleshooting

| Symptom | Next action |
| --- | --- |
| 401 / 403 | Check token, Browse access, and permission for the specific write |
| Empty project search | Check branch/PR, organization, type, and default status filters |
| No repository | Add an SCM link/binding, use `THREATLINT_SONAR_REPO_URL`, or pass `--repo-url` |
| Comment posted, no Confirm | Check the reported transition result and server version; do not infer closure |
| Full report inaccessible | Publish it securely and use `--report-url`; local filenames are not uploads |

Next: [check evidence, proposed fixes, and acceptance criteria](../reports.md) before changing status.
