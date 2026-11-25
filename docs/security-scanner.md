---
title: Run a security scan
description: Scan source without a model, check engine coverage, and review supported fixes.
---

Use the security scanner to find source, secret, infrastructure, and dependency-hygiene patterns. The built-in baseline needs no model provider or additional scanner installation.

## Before you start

Open an authorized repository in the [Workbench](workbench.md). Install Semgrep or Trivy only if you want their additional checks. A hosted web scan uses tools and files inside your web profile, rather than tools installed on your laptop.

## Run the scan

1. Open **Review code → Run scanners**.
2. Leave optional engines unchecked for a baseline scan, or select the installed **Semgrep** and/or **Trivy** engines you want.
3. Choose **Scan my code** and wait for the terminal result.
4. Read each engine card before reviewing the findings.

Optional engines can download public rules or vulnerability databases. Scanner jobs do not use model credentials, install project packages, run build hooks, validate discovered credentials, or execute the scanned application. They inspect a bounded text snapshot.

For CLI use:

```bash
threatlint security-scanner scan --repo /path/to/repository
threatlint security-scanner scan --repo /path/to/repository --engine semgrep --engine trivy
```

The CLI prints JSON evidence. Optional engines must already be installed.

## Read the engine cards

| Status | Meaning |
| --- | --- |
| `completed` | That engine returned results for the captured scope |
| `partial` | The engine reported incomplete coverage |
| `not_requested` | An available engine was not selected |
| `unavailable` | The engine could not run, for example because it is not installed |
| `failed` | No successful result from that engine is claimed |

A completed **baseline** card does not establish that Semgrep or Trivy ran. Check the selected engine's own status and reported version. Missing provenance fields remain `unrecorded`.

Semgrep uses `p/security-audit`. Threatlint selects Pro only when the current authentication and installed Pro engine pass verification; otherwise it explicitly selects Community Edition and explains that choice. A selected Pro scan that fails is not retried as Community Edition. Community scanning needs no Semgrep login.

Trivy adds vulnerability-database, infrastructure, and secret checks. Its card records available database schema and update/download timestamps. The baseline's npm lockfile checks do not identify known CVEs; that requires a successful Trivy run and its database.

Overall coverage remains **partial**, even when the selected engines complete. Scans exclude git history, generated/binary content, excluded directories, unsupported files, and files over 1 MB. The snapshot is limited to 10,000 files and 30 MB; at most 2,000 findings are retained. Engines have a five-minute/20 MB output budget. The result records skipped content and reached limits. Rule sources are recorded, but an immutable registry rule revision is not pinned.

Zero findings means no matches in the checks that ran. It is not a security certification.

## Semgrep on Windows desktop

[Semgrep Community Edition](https://semgrep.dev/products/community-edition/) supports native Windows scanning without an account. The pinned [Semgrep 1.186.0 package](https://pypi.org/project/semgrep/1.186.0/) provides Windows x64 wheels for Python 3.10–3.14.

1. Use a supported 64-bit Python to create a dedicated environment:

   ```powershell
   $semgrepTools = Join-Path $env:LOCALAPPDATA 'ThreatlintTools\Semgrep-1.186.0'
   py -3 -m venv $semgrepTools
   & "$semgrepTools\Scripts\python.exe" -m pip install 'semgrep==1.186.0'
   & "$semgrepTools\Scripts\python.exe" -m pip check
   & "$semgrepTools\Scripts\semgrep.exe" --version
   ```

2. Add its `Scripts` directory to User PATH:

   ```powershell
   $semgrepScripts = Join-Path $semgrepTools 'Scripts'
   $userToolPath = [string][Environment]::GetEnvironmentVariable('Path', 'User')
   if ($semgrepScripts -notin ($userToolPath -split ';')) {
       [Environment]::SetEnvironmentVariable('Path', ($userToolPath.TrimEnd(';') + ';' + $semgrepScripts).TrimStart(';'), 'User')
   }
   ```

3. Close and reopen Threatlint through its usual shortcut, then run a scan with **Semgrep** selected.

Threatlint refreshes User PATH on startup while retaining inherited command precedence; OS sign-out is unnecessary. Expect the Semgrep card to show **completed**, Community Edition, and its version. Neither Auth0 nor Semgrep login is required for this local scan. Public rules still require network access.

## Review and apply

1. Open a finding and inspect its issue, impact, file/line, and suggested correction. Scanner matches remain unverified observations until reviewed.
2. If **Review suggested change** is available, inspect the exact before/after diff and its compatibility effects.
3. Confirm **Apply** only when the host supports it and you intend the edit. Otherwise make the reviewed change in your editor.
4. Read the rescan result, then run the application's relevant tests yourself.

Supported automatic source changes are limited to these Python rule families:

| Rule | Proposed correction |
| --- | --- |
| `TL-DEBUG-ENABLED` | Plain module-level `DEBUG = True` → `False` |
| `TL-PY-YAML` | Eligible direct PyYAML calls → safe loading, or a supported standard unsafe loader → its safe counterpart |
| `TL-TLS-VERIFY-OFF` | Eligible direct `requests` calls with literal `verify=False` → `True` |

Ambiguous calls, custom loaders, aliases, multiline shapes, local modules shadowing these libraries, and changed source remain manual. Safe YAML loading rejects custom Python object tags; TLS verification may require your private CA; disabling debug changes diagnostics. Dependency upgrades, secret rotation, and infrastructure changes remain advisory.

Proposals belong to the scanned repository revision and file content. Stale or unsafe paths are rejected. Current Windows Python hosts do not support this adapter's safe local replacement method: they show the diff and manual instructions instead of an Apply button.

Applying a supported edit rescans; it does not run application tests. Failed validation restores the original content unless another process changed it. After an interruption, inspect the file and scan again rather than assuming rollback. **Cancel scan** waits for a terminal result and does not undo an already applied edit.

Advanced automatic application is optional: its checkbox authorizes the three named source-rule families for that scan, up to 12 edits. It does not waive source checks or validation. Approved Trivy exceptions expire after 90 days and apply only to the exact reviewed file bytes.

## GitHub review and rescan

1. Read the [Security scanner workflow](https://github.com/h0p3sf4ll/threatlint/actions/workflows/security-scanner.yml) result and JSON evidence for the exact target revision.
2. Review a native suggestion before using GitHub's **Commit suggestion** action. A new PR head triggers another scan. Same-repository PRs can receive comments; fork scans do not publish elevated comments. At most ten native suggestions are published per run.
3. For a separate fix proposal, open [Apply security fix and rescan](https://github.com/h0p3sf4ll/threatlint/actions/workflows/appsec-auto-fix.yml). Supply the base branch, full expected SHA, and eligible finding ID from the artifact.
4. Leave application options unchecked for a proposal only. The reviewed-edit checkbox authorizes that edit; the debug checkbox and `auto_apply_rule` selector provide separate narrow authorizations. The workflow's `security_scanner_fix.py` script accepts repeatable `--auto-apply-rule`; `--auto-apply-debug` remains compatible.
5. Review the validation evidence and resulting **draft PR**. The workflow does not merge it. Required reviews and application CI still apply; a `GITHUB_TOKEN` PR may need CI started through your approved process.

See GitHub's [suggestion workflow](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/incorporating-feedback-in-your-pull-request) and [review-comment API](https://docs.github.com/en/rest/pulls/comments).

## Check the result

A useful result identifies which engines ran, their limits, and each finding's source and location. Secret matches are redacted in findings and exports. Saved finding history retains the observed scope; absence on a later scan alone does not prove remediation.

**Next:** review [Finding intelligence](finding-intelligence.md), share [Reports](reports.md), or follow the [Quickstart](learning.md).
