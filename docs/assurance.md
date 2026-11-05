# Assurance gate

Pull a repository, run static analysis, then dynamically scan it, and return one verdict — with a deliberate
"did-not-finish" rule: a CRITICAL or HIGH finding in **any** stage loses the run on disqualification, but **no scan
is skipped because of it**. Every scan still runs to completion so the scanning platforms get their updates. Think
of a racer who leaves the track and still crosses the line: a finish on paper, a loss on disqualification.

```bash
threatlint assure run --repo https://github.com/acme/web.git --branch main
```

Output lands in a run directory: `assurance-report.md` and `assurance-state.json`. The exit code is `0` only when the
run is **QUALIFIED**; a **DISQUALIFIED** or **ERROR** verdict exits non-zero, so CI can gate on it.

## What it does

1. **Pull** the repository and branch into the configurable repo store (see
   [Where scanned repositories are cloned](setup.md#where-scanned-repositories-are-cloned)).
2. **Static analysis (SAST)** — run Semgrep over the checkout and normalize its findings. A CRITICAL or HIGH result
   trips the gate.
3. **Classify** the application as web/API or mobile from its project files.
4. **Dynamic analysis** — still runs even if the SAST gate already tripped:
   - **web/API:** build the app in the same bounded, **no-egress ephemeral environment** the runtime red team uses,
     probe it with the shared runtime engine (the real dynamic scan), tear it down, and submit the target to
     **Invicti**.
   - **mobile:** hand the build to **NowSecure**.
5. **Verdict** — computed once, from the gate each stage reported:

   | Verdict | Meaning | Exit |
   | --- | --- | --- |
   | QUALIFIED | every stage ran and none tripped the gate | `0` |
   | DISQUALIFIED | all scans ran, but a stage had a CRITICAL or HIGH finding (`disqualified_at` names the first) | `1` |
   | ERROR | a stage could not run to produce a verdict (for example Semgrep was not installed) | `1` |

## Fail fast, finish anyway

The gate decision is immediate — a CRITICAL or HIGH in SAST already loses the run — but the pipeline does not stop:
it goes on to build and dynamically scan the app so the data is still produced and the platforms are updated. The
verdict names the first stage that went out of bounds; the report lists every stage's findings regardless.

## Vendors are injectable

Invicti (web/API) and NowSecure (mobile) are **not called by Threatlint**. Each is a single injectable hook,
mirroring the runtime red team's ServiceNow stub: by default the submission is **stubbed** (recorded, not sent), so
the run completes and the report states what it *would* submit. A real integration registers a provider:

```python
from threatlint.assurance import vendors
vendors.set_invicti_provider(lambda context: {"reference": "INV-123", "findings": [...]})
vendors.set_nowsecure_provider(lambda context: {"reference": "NS-456", "findings": [...]})
```

Any findings a provider returns flow into the gate like any other stage's.

## Scope and authorization

Run this only against applications you are authorized to test. The web/API dynamic stage builds and executes the
target in an internal Docker network with no route out, resource limits, and no host mounts, and tears it down
afterward; Docker is required for the default environment provider. Static analysis needs Semgrep Community Edition
on the PATH.
