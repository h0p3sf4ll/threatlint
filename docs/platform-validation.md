# Security platform branch validation

Date: 2026-11-07. Branch: `codex/security-platform-foundation`.
Base: `02ac0fd96420d20c3a78ed08209a84f3d5409cfb`, plus the integrated handoff at `0441452`.
Historical implementation commit: `1f7ee07` (the original preview checks below).
The completion-audit results appear first; the earlier baseline is retained for comparison.
This record distinguishes executed checks from future live validation.

## Completion-audit validation

Updated 2026-11-07 after auditing the recovered original request.

Tested implementation: `d5c5a29`; documentation-only updates follow it. Checks use Python
3.13.2, installed Google Chrome and the local Node runtime. The three implementation/review
subagents used requested Astra/ultra settings. Live provider smoke below uses native default
effort and records the model as requested, not a server-reported identity.

| Check | Actual result |
| --- | --- |
| Final Python suite | **1,606 passed** in 87.64 seconds; includes the final import-shadowing, process-cleanup and platform-capability regressions |
| Final Node suite | **743 passed**, 76 suites, zero failures/cancellations/skips; 3.80 seconds |
| Browser acceptance | All three passed: threat-model source/branch/docs; scanner proposal/apply/rescan/ledger; intelligence review/reopening/chains/filters/coaching/export. Screenshots refreshed and visually inspected. |
| Real scanner adapters | Semgrep **1.183.0 Pro** completed with 3 findings; Trivy **0.76.1** completed with 8; baseline 3. Generated synthetic Python/Docker/dependency fixture, 14 total observations, explicit partial coverage, 5.39 seconds on warmed databases. |
| Engine/database provenance | Semgrep rule pack identified but unpinned; Trivy DB schema 2, updated `2026-11-07T12:52:01.765289267Z`; database and check-bundle download metadata recorded. No immutable rule revision asserted. |
| Actual guarded fixes | Debug True→False, recognized YAML Loader→SafeLoader, requests verify=False→True all applied and passed Python parsing plus fresh baseline rescans. Application tests remain not run. |
| Live Codex, one worker | Requested `gpt-6-astra`; 2 real calls (assessment/challenge), 95.257 seconds, 4 verified citations, 1 retained candidate. |
| Live Codex, two workers | Same synthetic fixture/requested model; 3 calls, 90.038 seconds, 4 verified citations, 2 retained candidates; assessment calls visibly overlapped. |
| macOS arm64 desktop | Unsigned Electron package built successfully; packaged-app smoke passed startup, 22 agents/26 skills, report preview, sandbox/isolation and settings across relaunch on a changed port. Build fingerprint `a1a8736b23e3ba87`, source `d5c5a29`. |
| Python wheel and desktop resources | Both packaged all **159 Python modules** byte-for-byte matching source. Wheel built using isolated `pip wheel --no-deps`. |
| Static/quality | Organization-reference check and diff whitespace passed. 13 genuine dead-binding diagnostics removed; 149 intentional compatibility/facade warnings remain documented, so repository-wide Pyflakes is not labeled clean. |
| Peer review | Fixed same-import alias shadowing in guarded edits and POSIX descendants surviving an exited CLI leader; dedicated regressions passed. |
| Windows portability | Corrected platform-dependent PATH parsing/casing, POSIX-only permission assertions, and UTF-8/LF synthetic fixtures; exact Git patch matching remains enforced for LF/CRLF/autocrlf cases. |
| Unsupported local writes | All 62 scanner tests passed with required directory-relative capabilities disabled. Reports/proposals retain manual diffs; UI and host refuse automatic/apply writes explicitly. The normal scanner browser acceptance passed again. |

GitHub CI verified implementation `d5c5a29186421d02b8e22f8eb0c8c428b0c59a63`:
[Python/Workbench tests](https://github.com/h0p3sf4ll/threatlint/actions/runs/42394902516)
and [unsigned desktop builds](https://github.com/h0p3sf4ll/threatlint/actions/runs/42394902496)
both passed on **macOS, Linux and Windows**. The first branch CI run exposed fixture
line-ending/encoding and POSIX permission assumptions, plus unclear unsupported-writer
behavior. These were corrected and the complete matrix rerun; no security gate was relaxed.
The final documentation-only commit follows this tested implementation.

The live runs use generated synthetic source and the existing signed-in Codex client;
no production repository, separate paid API credential, ServiceNow write, PR comment or
suggestion was used. Two workers saved about five seconds in this single tiny comparison
and cost one extra call. Candidate grouping differed. This is contract/concurrency evidence,
not a statistically meaningful speedup, accuracy or cost benchmark. Both runs use one
provider, so they do not establish independent-provider consensus.

The reproducible opt-in harness is `web/scripts/live-review-smoke.cjs`. It records per-stage
wall times, requested model, scope counts, literal citation validation and attribution in
`acceptance.json`, `report.md` and `provenance.json`. Automatic tests remain synthetic/offline.
Native runtime smoke is local macOS arm64 only; CI also builds unsigned packages for
macOS, Linux and Windows. Signing/notarization and Windows/Linux runtime execution are
separate release checks. The full request mapping is in
[request completion](request-completion.md).


## Historical preview checks

| Check | Result and evidence scope |
| --- | --- |
| Handoff baseline, Python | 1,516 passed before the new platform changes |
| Handoff baseline, Node | 676 passed before the new platform changes |
| Final integrated Python suite | **1,539 passed** in 90.87 seconds; `PYTHONPATH=src .../.venv/bin/python -m pytest -q` |
| Final integrated Node suite | **727 passed**, no failed/cancelled/skipped tests; `node --test web/tests/*.test.cjs` |
| Threat-model browser | Passed repository/branch selection, displayed commit, actual document upload/extraction, busy controls, document removal and mobile layout |
| Security platform browser | Passed actual Python baseline, visible partial coverage, proposal before mutation, apply/rescan, persistent ledger ingestion, advanced controls and mobile layout |
| Finding intelligence browser | Passed explicit reviews, false-positive reopening rejection and new-evidence acceptance, causal chain, ServiceNow preview download and insufficient-data coaching |
| Static checks | New scanner/scripts passed Pyflakes; `git diff --check` and `scripts/check-org-references.sh tree` passed |
| Media | Current PNGs captured from the running Workbench using synthetic fixtures; architecture SVG parsed and rendered; captured pixels inspected |
| Python package | Wheel built successfully with isolated `pip wheel --no-deps`; packaged scanner modules match the tested source byte-for-byte |

The final suites include the lifecycle, cancellation, provider controls, chain-priority and
stale-workspace regression changes. Documentation links, SVG XML and duplicate in-app media
hashes were checked separately.

Tests use Python 3.13 from the existing development environment, Node from the local machine,
and installed Google Chrome through Playwright. Playwright's default bundled Chromium was
missing; the actual browser checks passed after selecting the installed Chrome executable.

For the historical preview checks, no paid model calls, production repositories, ServiceNow
writes or live PR comments were used. External scanner adapters and GitHub APIs used synthetic responses. The scanner
browser test executes the real baseline and real guarded source edit in a temporary repository.
The source/document browser test uses synthetic source-manager and model collaborators.

## Reproduce

From the branch checkout, install the development prerequisites normally, then run:

```bash
PYTHONPATH=src python3 -m pytest -q
node --test web/tests/*.test.cjs
node web/tests/threat-model-browser-smoke.cjs
node web/tests/security-platform-browser-smoke.cjs
node web/tests/finding-intelligence-browser-smoke.cjs
bash scripts/check-org-references.sh tree
git diff --check
```

Use `THREATLINT_BROWSER_EXECUTABLE=/absolute/path/to/chromium` when the default Playwright
browser is unavailable. `THREATLINT_TEST_PYTHON` selects the interpreter for the scanner
browser check. `THREATLINT_SCREENSHOTS=docs/media` enables the source/scanner captures.
See [media provenance](media/README.md) before replacing documentation or in-app screenshots.

## Peer review and corrected issues

Cross-review identified and corrected credential-bearing debug-comment previews, fix-process
shutdown draining, stale automatic-fix UI state after a workspace switch, unknown engine
severity ingestion, severity escalation/history preservation, and invalid duplicate coaching
observations masking eligible evidence. Provider changes clear the old provider key. Changed
source after a scan or during validation cannot be reported as a successfully validated fix.

The reviewed boundaries include provider credential separation and consent, model budgets,
source scopes, literal-quote validation, deterministic consolidation, fix allowlists, GitHub
revision binding, ledger revision boundaries and explicit reviewer attestations. This is
evidence for these changes, not certification that the entire existing project has no defects.

## Remaining validation and next-phase boundaries

- Run a distinct-provider acceptance using authorized provider credentials; only signed-in
  Codex has received a real synthetic assessment/challenge test here. Compare repeated
  representative revisions, cost and finding quality before claiming performance gains.
- Validate broader real-repository engine coverage, pin immutable rule packs and benchmark
  precision/recall. Semgrep Pro and Trivy/database execution passed on synthetic source;
  the baseline remains limited and coverage is explicitly partial.
- Deploy trusted workflow code before testing the first scanner PR and native suggestion.
  The introducing PR cannot trust its own scanner implementation; missing trusted-base code
  reports **not evaluated**. No live PR comment, suggestion or draft remediation was published.
- Exercise the CI-built Windows/Linux applications and descendant cleanup. POSIX process-group cleanup
  has regression coverage. Safe automatic file replacement is unavailable on platforms
  without required directory descriptor/no-follow operations; use advisory/manual edits.
- Configure and validate ServiceNow mappings before implementing transport. Calibrate the
  coaching/chain priority rubric before broader use. Both requested stubs remain explicit
  offline previews and are not CVSS or employee-performance scores.

The [implementation provenance](security-platform.md#engineering-standards-and-model-provenance)
records Astra/ultra subagent configuration and the original handoff's unverified model history.
