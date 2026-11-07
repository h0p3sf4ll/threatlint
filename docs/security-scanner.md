# Scan source and review a bounded fix

Open a repository in Workbench, choose **Test → Security scanner**, and run the
baseline. It combines the existing Guard source and secret rules with selected
infrastructure checks and dependency lockfile hygiene. It works without installing
another scanner. A result with zero findings means those checks found no matches;
it does not certify the repository as secure.

For CLI use:

```bash
threatlint security-scanner scan --repo /path/to/repository
threatlint security-scanner scan --repo /path/to/repository --engine semgrep --engine trivy
```

Optional engines must already be installed. Semgrep adds its `p/security-audit`
rules using the existing shared **Semgrep Pro** engine policy and configured
authentication. A missing matching Pro engine is reported as unavailable; there
is no silent Community Edition fallback. Trivy adds vulnerability-database,
infrastructure, and secret checks.
Opting in can download rules or vulnerability databases. Threatlint does not
install packages, run project build hooks, validate discovered credentials, or
execute scanned application code. It runs engines on a bounded text snapshot.
Engine output is limited to 20 MB and each engine to five minutes.

The engine cards distinguish `completed`, `partial`, `not_requested`,
`unavailable`, and `failed`. Overall coverage remains `partial`: generated and
binary artifacts, excluded directories, git history, unsupported files, files
over 1 MB, and content beyond the 10,000-file/30 MB budget are outside this scan.
At most 2,000 findings are retained; reaching that limit is reported explicitly.
Skipped counts and limits are included in the result. Built-in dependency checks
identify floating npm versions without a captured lockfile; they do **not** claim
to identify known CVEs. That requires a successful Trivy run and its database.

**Cancel scan** requests cancellation while a scan is running. Workbench waits
for a terminal scanner result before releasing the controls; cancellation never
turns an incomplete run into a clean result. This control does not cancel an edit
that has already been applied.

Findings have stable IDs, engine attribution, category, severity, reported
confidence, path/line evidence, impact, remediation, and optional package/fixed
version metadata. They remain reported observations until independently reviewed.
Secret matches are redacted in findings and exports. Findings history can retain
each repository/branch/commit/content snapshot through the completion callback.

## Review and apply

**Propose fix** prepares an exact before/after edit. The initial allowlist contains
one transformation: a plain Python module-level `DEBUG = True` becomes
`DEBUG = False`. Other findings retain advisory remediation. Even this small
change can alter application behavior, so review is the default.

Each proposal is bound to the canonical repository path, branch, commit, captured
content digest, and current file hash. Application regenerates the allowed edit;
the browser cannot supply replacement code. Stale plans, symlinks, traversal,
workflow/agent directories, credential/secret files, and secret-bearing proposal
lines are rejected. Directory-relative replacement is required; hosts without
that filesystem support retain manual review instead of an unsafe write fallback.

Application parses Python syntax without importing it, writes only the eligible
file, and rescans. A failed baseline validation restores the original content
unless another process has changed it. Application tests are explicitly
`not_run`. Interrupted operations require inspection and a fresh scan; the UI
does not assume that cancellation proves rollback. Closing Workbench aborts and
drains native scanner/fix operations.

Automation requires an explicit policy such as
`{"autoApply":true,"rules":["TL-DEBUG-ENABLED"]}` for the requested operation.
An empty or unknown rule policy grants no write permission. Policy does not waive
revision/path checks, syntax validation, rescanning, or review before merge.

## GitHub review and rescan

The [Security scanner workflow](../.github/workflows/security-scanner.yml) checks
out the trusted scanner implementation separately from the exact target revision.
It scans target files as data and uploads JSON evidence. Same-repository PRs also
receive a compact comment sorted by severity: issue, impact, vulnerable code, and
proposed fix. Fork scans do not publish comments with elevated credentials.

For an eligible newly added diff line, the publisher creates a **native GitHub
suggestion** bound to that PR's current head commit. GitHub's **Commit suggestion**
action changes the PR branch; its `pull_request: synchronize` event runs the scan
again. The publisher checks the live head before publishing, rejects stale heads,
and limits native suggestions to ten per run. This is GitHub's supported
[suggestion workflow](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/incorporating-feedback-in-your-pull-request),
using the [review-comment API](https://docs.github.com/en/rest/pulls/comments).
There is no HTML action button or issue-comment-to-shell command.

The comment also links to
[Apply security fix and rescan](../.github/workflows/appsec-auto-fix.yml).
The maintainer supplies a base branch, full expected SHA, and exact eligible
finding ID from the scan artifact. Without either application checkbox the
workflow only prepares a proposal. The reviewed-edit checkbox authorizes that
edit; the separate false-by-default policy checkbox explicitly permits only the
`DEBUG` transformation without per-edit approval. Applying validates and rescans,
checks the remote base head again before publication, and opens a **draft PR**.
It never merges. Configure required reviewers on the `security-fixes` GitHub
environment and normal branch protection for your organization.

The introduction PR is a bootstrap exception: its trusted base/default revision
does not yet contain this scanner. Readiness checks fail explicitly with **not
evaluated**, rather than importing code from that PR or calling the scan clean.
Validate the introduction locally with synthetic tests, review and deploy the
implementation to the trusted branch, then enable/rerun PR scans and remediation.

These repository workflows use the trusted Python package in the separate
`scanner-tool` checkout; the mirrored scripts are entry points, not standalone
scanner distributions. When adapting the workflows to an application repository,
point the tool checkout at a reviewed, pinned Threatlint revision containing this
feature. Keep the application checkout separate. No repository installation or
target test script belongs in the credential-bearing publishing step. A PR
opened with `GITHUB_TOKEN` may not trigger other workflows automatically; the
explicit rescan evidence is preserved, and application CI must be run through
your approved workflow/token configuration before merging.

## Integration contract

`createSecurityScanner({store, integrations, onScanComplete, isSessionBusy})`
resolves repositories from existing sessions. Mount its route module behind the
Workbench same-origin loopback middleware. The optional busy callback prevents
scanner/fix work while another review owns that repository; expose scanner
`isBusy(sessionId)` back to review admission for the reverse direction.

| Route | Request/result |
| --- | --- |
| `POST /api/security-scanner/scans` | `{sessionId, engines?:[]}` → `{id}` |
| `GET /api/security-scanner/scans?sessionId=…` | Current process's bounded scan history |
| `GET /api/security-scanner/scans/:id` | Status, binding, findings, engines, coverage, summary |
| `POST /api/security-scanner/scans/:id/cancel` | Cancel and drain the active scan |
| `POST /api/security-scanner/scans/:id/fixes` | `{findingId}` → server-owned proposal and ID |
| `POST /api/security-scanner/fixes/:id/apply` | `{confirm:true}` or explicit narrow policy → validation and new scan |

The store keeps at most 25 scan snapshots and 100 proposals in memory. Persistent
findings history is an explicit consumer of `onScanComplete(scan, session)`, not
an implicit write to a remote tracker. No PR comments or external changes occur
from the local scan API.
