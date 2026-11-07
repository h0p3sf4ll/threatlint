# Security platform branch validation

Date: 2026-11-07. Branch: `codex/security-platform-foundation`.
Base: `02ac0fd96420d20c3a78ed08209a84f3d5409cfb`, plus the integrated handoff at `0441452`.
Tested implementation commit: `1f7ee07` (documentation and captured media follow separately).
This record distinguishes executed checks from future live validation.

## Executed checks

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

No paid model calls, production repositories, ServiceNow writes or live PR comments were used
for validation. External scanner adapters and GitHub APIs use synthetic responses. The scanner
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

## Remaining live validation

- Exercise the advanced JSON assessment/challenge contract with the chosen real providers
  and models. Measure cost, elapsed time and coverage on the same revisions; no production
  performance improvement is claimed from synthetic concurrency tests.
- Validate installed Semgrep Pro and Trivy/database behavior on authorized repositories.
  Missing engines are explicitly unavailable; the baseline cannot replace their coverage.
- Deploy trusted workflow code before testing the first scanner PR and native suggestion.
  The introducing PR cannot trust its own scanner implementation; missing trusted-base code
  reports **not evaluated**. No live GitHub workflow or suggestion was exercised here.
- Package and exercise the Electron app on supported operating systems. The browser and
  desktop share the host, but browser checks do not establish desktop packaging success.
  Safe automatic file replacement is unavailable on platforms without required directory
  descriptor/no-follow operations; those platforms use manual edits.
- Configure and validate ServiceNow field/table mappings before implementing live export.
  Calibrate any coaching/chain priority rubric before broader organizational use. Both
  current previews are explicit about their limitations and are not CVSS or employee scores.

The [implementation provenance](security-platform.md#engineering-standards-and-model-provenance)
records Astra/ultra subagent configuration and the original handoff's unverified model history.
