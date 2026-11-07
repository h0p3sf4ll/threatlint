# Bounded source quality review

This review removes verified dead bindings while preserving compatibility imports
and public module surfaces. It does not claim that the entire repository is free
of code smells or replace an architecture, complexity or security review.

The earlier review log contained 163 Pyflakes diagnostics. A fresh scan of the
working branch before this cleanup contained **162**; other branch work was
already in progress. With Pyflakes **4.1.0**, Python **3.13.2**, running
`python -m pyflakes src/threatlint` after this cleanup reports **149** diagnostics.
The bounded cleanup therefore removes **13** diagnostics from its measured
starting state. The residual lint command exits nonzero; it is not advertised as
a clean repository-wide lint pass.

## Changes with no intended behavior change

| Change | Files | Why it is safe to remove |
| --- | --- | --- |
| Two unused exception bindings | `avit_pr.py`, `servicenow_credentials.py` | The handlers raise the same sanitized errors with `from None`; neither reads the caught exception. |
| Unused parser result variable | `sidekick/cli.py` | The `find` subcommand is still registered; only its unused local name is removed. |
| Two unnecessary f-string prefixes | `sidekick/reports.py`, `integrations/common.py` | These literal fragments contain no interpolation; resulting SQL and report text are unchanged. |
| Six unused imports | `servicenow.py` (`base64`), `avit_resolve.py` (`subprocess`, `sys`), `semgrep_platform.py` (`getpass`, ServiceNow alias), `data/scripts/threatlint_chat.py` (`urllib.request`) | No implementation or inspected repository consumer uses these names. The helpers that perform these operations import their own dependencies. No domain-function reexports are removed. |
| Duplicate local import | `avit_resolve.py` | `remove_checkout` uses the existing module-level `shutil`; this also removes the unused-global/redefinition pair of diagnostics while preserving the module attribute. |

The shipped and repository copies of `threatlint_chat.py` remain identical.
Existing interfaces, error messages, parser registration and compatibility
facades remain in place. The concurrently owned `cli.py`, `inspection_batch.py`,
`bounded_work.py` and `agent_batch.py` are outside this cleanup's edit scope.

## Residual diagnostics and why they remain

| Category | Diagnostics | Disposition |
| --- | ---: | --- |
| Historical facade imports | 85 | Retain imports exposed through ServiceNow, GitHub App, DAST, AVIT, runtime, SCTASK, CLI, integrations and PR-chat module surfaces. Some are directly exercised by callers/tests; others are conservatively retained for compatibility with external consumers. |
| Guard package public exports | 27 | `guard/__init__.py` exposes the split package's models, scanners, CLI and output functions. Imports already express same-name reexports; deleting them would change its public API. |
| Prompt facade exports | 28 | `_appsec_prompts.py` provides named prompt constants from specialist modules. Consumers import these constants from the facade. |
| Deprecated wildcard adapter facades | 8 | Four `scanners/*` compatibility modules each produce an unused-star and an analysis-limit diagnostic. Their forwarding behavior remains available to legacy consumers. |
| Explicit compatibility/parity import | 1 | `semgrep_platform.py` deliberately retains `base64` with its existing documented parity comment. |
| **Total** | **149** | **Retained and explained; not silently suppressed.** |

For example, tests use `servicenow.shutil` to inject tool discovery, and
`tests/test_integrations.py` calls the historical `base.report_line` surface.
Those imports appear unused when a linter examines only their defining module.
This review therefore avoids blanket import deletion, broad alias churn and
wildcard-facade redesign. A future deprecation change can replace those surfaces
only with explicit consumer migration and compatibility tests.

## Validation

The directly cleaned exception/parser/report modules pass Pyflakes without
diagnostics. The changed facade modules retain only the compatibility diagnostics
listed above. `git diff --check` passes. Focused existing tests cover AVIT PRs,
ServiceNow credentials and resolution, Semgrep configuration, Sidekick reports,
integration adapters and PR chat: **301 passed in 43.91 seconds**. The tests use
existing synthetic fixtures; this cleanup
does not invoke paid models or publish changes to external services.
