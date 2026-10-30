# DefectDojo integration

Threatlint reviews DefectDojo findings with the Findings triage agent (`appsec-fp-reviewer`) and writes the
verdict back to DefectDojo. It mirrors the [ServiceNow AVIT flow](avit-integration.md): fetch, check out the
repository and branch the finding names, triage, then resolve with an explicit confirmation.

## What you need

| Item | Where it comes from |
| --- | --- |
| DefectDojo base URL (HTTPS) | e.g. `https://defectdojo.example.test` (a pasted `…/api/v2/…` URL is trimmed to the base) |
| API v2 token | DefectDojo → your profile → **API v2 Key** |
| Permissions | The token's user must **view** findings, tests and engagements in the products you review, and **edit** findings (notes, files, status) to resolve them |
| Repository access | Same as AVIT review: an Azure DevOps PAT (`threatlint ado login`) or GitHub (`gh auth login` / `GH_TOKEN`) |

## Credentials

Resolved in this order; the token is never printed or logged:

1. `THREATLINT_DOJO_URL` and `THREATLINT_DOJO_TOKEN`
2. `~/.threatlint/defectdojo.json` (`THREATLINT_HOME` relocates it), written with mode `0600` by
   `threatlint dojo login --url <url>` or *Workbench → Settings → DefectDojo*. The token is checked against
   `GET /api/v2/findings/?limit=1` before it is saved.
3. AWS Parameter Store, when `THREATLINT_DOJO_TOKEN_PARAMETER` (or `dojoTokenParameter` in `~/.threatlint/org.json`)
   names a SecureString parameter; read with your own AWS CLI credentials.
4. An interactive prompt (not saved).

Requests refuse redirects so the token only reaches the validated host; pagination `next` links are followed only
when they stay on the same base URL.

## CLI

```bash
threatlint dojo login --url https://defectdojo.example.test
threatlint dojo fetch 123 DOJO-124 -o dojo.md                    # by id
threatlint dojo fetch --product 3 --active true --severity High -o dojo.md   # by filter
threatlint dojo checkout DOJO-123 --dir /tmp/dojo-123            # [--repo-url URL] [--branch NAME]
threatlint dojo resolve DOJO-123 --report fp_review.md --docx fp_review.docx  # asks first; --yes to skip
threatlint dojo note DOJO-123 --message "Could not review: repository archived" # asks first
```

Filters for `fetch`: `--product`, `--engagement`, `--test`, `--active`, `--verified`, `--severity` (repeatable),
`--tag` (repeatable), `--limit` (default 50, at most 500). A search must be scoped by product, engagement, test, or tag.

`fetch` writes a findings artifact for `/fp-review` or `threatlint run fp-review --findings dojo.md`. Each finding
is keyed `DOJO-<id>`; the report's **Original finding** line must name it (`DOJO-123; <rule>; <tool>; <path:line>`).
References match as whole tokens, so `DOJO-12` never matches `DOJO-123`.

### Review target mapping

| Context | DefectDojo field |
| --- | --- |
| Repository | engagement `source_code_management_uri` (GitHub or Azure DevOps URL) |
| Branch | test `branch_tag`, else engagement `branch_tag` |
| Commit | test `commit_hash`, else engagement `commit_hash` (checkout detaches there when reachable) |
| File / line | `file_path` / `line` (or `sast_source_file_path` / `sast_source_line`) |
| Rule | `vuln_id_from_tool`, else `vulnerability_ids`, else `CWE-<cwe>` |
| Tool | test type name (`test.test_type`), else `found_by` |
| Component | `component_name` `component_version` |

A finding with no usable repository is reviewed from its own evidence (`checkout` explains why), or pass `--repo-url`.

## Resolve

The report is attached **first**, so a finding is never closed without its evidence. Notes are the exact texts
`threatlint avit resolve` uses.

| Verdict | DefectDojo changes |
| --- | --- |
| FALSE POSITIVE | `POST /api/v2/findings/{id}/files/` (`<ref>-threatlint-fp-review.docx`), note *“Closed by Threatlint as a false positive, see attached report.”*, `PATCH` `false_p=true, active=false, verified=false` |
| TRUE POSITIVE | file, note *“True positive, see attached report.”*, `PATCH verified=true` (and `false_p=false, active=true` if it had been marked false positive) |
| AMBIGUOUS | file and note *“Ambiguous, see attached report. Left open pending the evidence the report names.”*; nothing else |

DefectDojo API v2 supports per-finding file uploads (`/findings/{id}/files/`), so the report is attached to the
finding itself. A file whose title is already attached is not uploaded again.

**Semgrep.** When the finding's tool is Semgrep and the verdict is FALSE POSITIVE, `resolve` (without
`--skip-semgrep`) ignores the matching open Semgrep finding and, with `--checkout`, tunes the rule exactly as the
AVIT flow does. Tuned rules are enabled only in `MODE_MONITOR` with the original disabled (enforced in
`semgrep_platform`).

## API calls

| Call | Purpose |
| --- | --- |
| `GET /api/v2/findings/{id}/` | one finding |
| `GET /api/v2/findings/?…&limit&offset` | filtered list |
| `GET /api/v2/tests/{id}/`, `/engagements/{id}/`, `/test_types/{id}/` | repository, branch, commit, tool |
| `GET`/`POST /api/v2/findings/{id}/files/` | existing files / attach the Word report |
| `POST /api/v2/findings/{id}/notes/` | the Threatlint note |
| `PATCH /api/v2/findings/{id}/` | status |

## Workbench

- **Settings → DefectDojo**: URL and token (masked; saved to the shared config only after the server accepts it).
- **DefectDojo review**: finding ids or a filter; each finding is fetched, checked out, triaged with the model from
  Settings, and saved to **Findings**. Nothing is written during the run. Each result has **Post to DefectDojo…**,
  which shows every change and posts only after you confirm (`POST /api/scanners/dojo/resolve` with `confirm: true`).
- **Import scan report** accepts a DefectDojo findings JSON (`/api/v2/findings/` response). **Post to DefectDojo…**
  posts each imported finding back to itself, or to a reference you enter for uploads from other tools.

## Limits

Verified only against mocked HTTP using DefectDojo's documented API v2 shapes. Custom DefectDojo deployments that
require `verified` to stay set, or deduplication rules that reopen findings, can change what is stored; `resolve`
reports what DefectDojo returned.
