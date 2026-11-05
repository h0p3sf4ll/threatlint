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
| Repository / model | [GitHub App](../github-app.md), GitHub token/CLI, or `threatlint ado login`; [model setup](../setup.md) |
| Direct CLI triage | Semgrep Community Edition on PATH (`semgrep --version`); `run fp-review` requires it |

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
| TRUE POSITIVE | Attach; note “True positive, see attached report.”; set `verified=true`; if previously false positive, clear `false_p` and reactivate |
| AMBIGUOUS | Attach; note “Ambiguous, see attached report. Left open pending the evidence the report names.”; no status change |

Attachment comes first; matching titles skip upload. Writes are **not transactional**: failure
can leave attachments/notes without status changes. Inspect returned status/warnings before retrying.

**Semgrep:** omitting `--skip-semgrep` allows CLI false-positive resolution to ignore matching
open Semgrep findings. `--skip-rule-tuning` keeps that triage write but skips replacement rules.
With `--checkout`, supported rule tuning is validated against the flagged file; replacement rules
are monitor-only and the original is disabled. The supplied checkout is deleted afterward,
including on failure, unless `--keep-checkout` is set. Use a disposable checkout, not your working
repository. DefectDojo and Semgrep outcomes are separate; inspect both.

## Workbench

1. Save URL/token in **Settings → DefectDojo**.
2. Open **DefectDojo review**, enter IDs or a scoped filter, and run. Reports appear in **Findings**;
   the review itself posts no external changes.
3. Inspect each report, then **Post to DefectDojo…**. Confirm the previewed changes.
   Semgrep posting is opt-in in the Workbench.

**Triage a scan report** also accepts `/api/v2/findings/` JSON exports. Imported findings can post
back to their original references or explicit mapped references after confirmation.
Workbench review batches have no limit: every listed or matching finding is reviewed in turn.

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
