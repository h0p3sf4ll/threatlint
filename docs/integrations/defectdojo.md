---
title: "DefectDojo"
description: "Connect DefectDojo, review findings against source, and post an approved disposition."
---

# DefectDojo integration

**Integration type: findings management.** DefectDojo is a centralized system of record: it aggregates
findings that many scanners produced and tracks their status. It does not scan code. Compare the
[SonarQube scanning-tool integration](sonarqube.md) and the [integration types](README.md).

Keep the decision and its source evidence with the finding. Threatlint fetches DefectDojo
findings, locates their source, and runs findings triage. You approve posting and status changes.

**Boundary:** fetching/reviewing does not update DefectDojo. `resolve` and `note` do, after
confirmation. Semgrep-origin false positives can also trigger Semgrep writes; see [Resolve](#resolve).

## What you need

| Requirement | Setup |
| --- | --- |
| HTTPS URL / token | Instance URL; profile → **API v2 Key**. Pasted `/api/v2/…` paths are trimmed |
| Permissions | View findings/tests/engagements; edit findings/notes/files/status only for posting |
| Repository / model | [GitHub App](../github-app.md), GitHub token/CLI, or [Azure DevOps credentials](../avit-integration.md#one-time-setup); [model setup](../model-providers.md) |
| Direct CLI triage | Semgrep CLI on PATH (`semgrep --version`); Community Edition satisfies the installation check, but Semgrep false-positive rule proof requires a matching Pro engine and login |

## CLI

Replace `123` with an authorized finding:

1. Validate/save the token (hidden prompt):

   ```bash
   threatlint dojo login --url https://defectdojo.example.test
   ```

2. Fetch without changing status:

   ```bash
   threatlint dojo fetch 123 -o dojo.md
   ```

3. Check out source into an empty directory:

   ```bash
   threatlint dojo checkout DOJO-123 --dir ./dojo-123
   # Add --repo-url URL or --branch NAME to override missing/incorrect metadata.
   ```

4. Triage from the checkout; change `--provider` if needed:

   ```bash
   (cd dojo-123 && threatlint run fp-review --findings ../dojo.md --provider lmstudio)
   ```

**Result:** `dojo.md` and an advisory report, not closure. Check revision/limits before
[posting](#resolve). Without source, review exported evidence and disclose uncertainty.

For a bounded batch:

```bash
threatlint dojo fetch --product 3 --active true --severity High -o dojo.md
```

Filters: `--product`, `--engagement`, `--test`, `--active`, `--verified`, repeatable
`--severity` / `--tag`, and `--limit` (default: every matching finding). Searches require product,
engagement, test, or tag scope. Explicit ID lists have no limit.

### Review target mapping

| Context | Source field |
| --- | --- |
| Repository | Engagement `source_code_management_uri` (GitHub or Azure DevOps) |
| Branch | Test `branch_tag`, else engagement `branch_tag` |
| Commit | Test `commit_hash`, else engagement `commit_hash`; detaches when reachable |
| File / line | `file_path` / `line`, else `sast_source_file_path` / `sast_source_line` |
| Rule | `vuln_id_from_tool`, else `vulnerability_ids`, else `CWE-<cwe>` |
| Tool / component | Test type, else `found_by`; `component_name` / `component_version` |

If a recorded commit is unreachable, checkout warns and reviews branch head instead.
Reports must preserve **Original finding**, e.g.
`DOJO-123; rule-id; Semgrep; src/search.py:42`. Matching uses whole references, so `DOJO-12`
does not match `DOJO-123`.

## Credentials

CLI: `THREATLINT_DOJO_URL` / `THREATLINT_DOJO_TOKEN` → saved `~/.threatlint/defectdojo.json`
→ Parameter Store token → unsaved prompt. `THREATLINT_HOME` relocates configuration. Login checks
`GET /api/v2/findings/?limit=1` before saving, with POSIX mode `0600`; protect Windows ACLs too.

Parameter Store: `THREATLINT_DOJO_TOKEN_PARAMETER` or `dojoTokenParameter` in `~/.threatlint/org.json`,
using your AWS session (`--aws-profile`). Workbench shares the file; direct connections prefer
saved values over environment. Tokens are masked/not returned to the page. Redirects are refused;
pagination stays on the validated base URL.

## Resolve

Inspect the matching report section first. To update **only DefectDojo**:

```bash
threatlint dojo resolve DOJO-123 --report fp_review.md --docx fp_review.docx --skip-semgrep
```

The CLI asks first; `--yes` authorizes writes without prompting. `note` asks and changes no status:

```bash
threatlint dojo note DOJO-123 --message "Review blocked: repository archived."
```

| Verdict | Applied changes, in order |
| --- | --- |
| FALSE POSITIVE | Attach Word report; note “Closed by Threatlint as a false positive, see attached report.”; set `false_p=true, active=false, verified=false` |
| Evidence-backed TRUE POSITIVE | Attach; note “True positive, see attached report.”; set `verified=true`; if previously false positive, clear `false_p` and reactivate |
| Conservative TRUE POSITIVE | Attach and note the evidence gaps; do not add a verification claim. The CLI reactivates a finding previously marked false positive |

Current reviews use **TRUE POSITIVE** or **FALSE POSITIVE**. Legacy `AMBIGUOUS`
reports become conservative, unverified true positives with their uncertainty retained.
This is a triage decision, not proof that exploitation was reproduced.

Attachment comes first; matching titles skip upload. Writes are **not transactional**: failure
can leave attachments/notes without status changes. Inspect returned status/warnings before retrying.

**Semgrep:** omitting `--skip-semgrep` allows CLI false-positive resolution to ignore matching
open Semgrep findings. `--skip-rule-tuning` keeps that triage write but skips replacement rules.
With `--checkout`, supported rule tuning is validated against the flagged file; replacement rules
need a Semgrep login and matching Pro engine for proof; there is no Community Edition fallback.
Policy changes depend on the deployment: legacy replacements use monitor mode before disabling
the original, while supported Unified policies use project-scoped selection and exclusions.
The supplied checkout is deleted afterward,
including on failure, unless `--keep-checkout` is set. Use a disposable checkout, not your working
repository. DefectDojo and Semgrep outcomes are separate; inspect both.

## Workbench

1. Save URL/token in **Settings → Scanning & triage → DefectDojo**.
2. Open **Finding triage**, select **DefectDojo** as the finding source, enter IDs or a scoped filter, and run. Reports appear in **Findings**;
   the review itself posts no external changes.
3. Inspect each report, then **Post to DefectDojo…**. Confirm the previewed changes.
   A Semgrep-origin false positive in this direct review workflow also updates Semgrep triage;
   eligible SAST and Secrets findings require rule tuning. Do not treat posting as a DefectDojo-only action.

**Triage a scan report** also accepts `/api/v2/findings/` JSON exports. Imported findings can post
back to their original references or explicit mapped references after confirmation. This imported-report
posting path attaches the report and updates DefectDojo; it does not publish Semgrep changes.

Direct Workbench reviews use one model run per finding, with up to **64** model runs per batch.
Narrow a filter or split a longer list before reviewing. Reviews run concurrently, normally **3** at a time.
In **Advanced** experience, **Parallel review and budget** lets you choose **1–8** parallel reviewers
and a lower model-run budget. Reports remain in Findings after temporary checkouts are removed.
Company administrators configure the connection; administrators and analysts can review and post.
The desktop app uses its local profile without a Threatlint login.

## API calls

Under `/api/v2/`: `GET findings/{id}/`, `findings/`, `tests/{id}/`, `engagements/{id}/`,
`test_types/{id}/`, `findings/{id}/files/`; `POST findings/{id}/files/`,
`findings/{id}/notes/`; `PATCH findings/{id}/`.

## Limits

[Python](../../tests/test_integrations.py) and [Workbench](../../web/tests/scanners.test.cjs) tests use
mocked HTTP, not live certification. Custom verification/deduplication policies can alter or reopen findings.

## Troubleshooting

| Symptom | Next action |
| --- | --- |
| 401 / 403 | Check API v2 token and product-specific read/write access |
| No repository | Check engagement SCM URL, or pass `--repo-url` |
| No matching verdict | Preserve the complete `DOJO-<id>` in **Original finding** |
| Attachment exists but status unchanged | Inspect server response/permissions; writes may have partially completed |
| Semgrep unchanged | Check match metadata, token, warnings, and tuning prerequisites separately |

Next: [review report evidence and acceptance criteria](../reports.md) before approving closure.
