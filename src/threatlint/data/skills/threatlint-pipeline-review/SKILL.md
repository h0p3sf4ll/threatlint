---
name: threatlint-pipeline-review
description: "Use for GitHub Actions, Azure Pipelines, GitLab, Jenkins, and CI/CD audits: event trust, script injection, token permissions, runner isolation, artifacts, and release provenance."
---

# CI/CD trust and artifact review

1. Map event → branch/ref → checkout → runner → token/secrets → build → artifact → deployment.
   Include reusable workflows/templates and permissions inherited from organization settings.
2. Trace untrusted PR/issue/comment/ref data into scripts and action inputs. Distinguish workflow
   expression interpolation from a value safely passed through a quoted environment variable.
3. Verify fork, privileged-trigger, and reusable-workflow boundaries. A privileged event with a
   trusted checkout can still execute untrusted downloaded artifacts, scripts, or build metadata.
4. Evaluate job-level token permissions and environment approvals. Missing explicit permissions
   means **default permissions unknown**, not automatically write-all; cite the actual override.
5. Inspect self-hosted runner persistence, caches/artifact poisoning, dependency installation,
   mutable action/image refs, release signing/provenance, and secret exposure in logs.
6. Propose pinned trusted refs, least-privilege jobs, untrusted-data isolation, integrity checks,
   and staged release gates. Explain update maintenance and compatibility implications.

## Deliverables

CI findings cite workflow/job/step lines, triggering actor, token and secret reachability,
concrete abuse path, smallest YAML proposal, and safe fixture-based regression checks.
Never trigger pipelines, publish artifacts, or run repository scripts during static analysis.