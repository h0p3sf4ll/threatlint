---
title: Assurance gate
description: Run static and dynamic checks from the CLI and use the combined verdict in CI.
---

# Assurance gate

The assurance command checks out a repository, runs static analysis, and performs the applicable dynamic stage. Use its combined verdict as a CI gate. A Critical or High finding disqualifies the run, but does not skip later scans.

```bash
threatlint assure run --repo https://github.com/acme/web.git --branch main
```

## Requirements

Run only against applications you are authorized to test. Install Semgrep Community Edition on PATH. The default web/API environment requires Docker and builds and executes the target in a bounded internal network with no external route, resource limits, and no host mounts.

See [repository storage](setup.md#where-scanned-repositories-are-cloned) and [Runtime red team](runtime-redteam.md) for the checkout and runtime workflow.

## Read the result

The run directory contains `assurance-report.md` and `assurance-state.json`.

| Verdict | Meaning | Exit code |
| --- | --- | --- |
| `QUALIFIED` | Every stage ran and none tripped the gate | `0` |
| `DISQUALIFIED` | All scans ran, with a Critical or High finding in at least one stage | `1` |
| `ERROR` | A stage could not produce a verdict, such as when Semgrep is unavailable | `1` |

The report lists findings from every stage and identifies the first disqualifying stage. Read stage coverage and limitations alongside the verdict.

## Vendor submissions

Invicti and NowSecure submissions are **stubbed by default**: the report records the proposed submission without contacting either vendor. A real integration must register the appropriate provider hook. Findings returned by a registered provider participate in the gate.

For extension code, see the [assurance providers in the repository](../src/threatlint/assurance/).
