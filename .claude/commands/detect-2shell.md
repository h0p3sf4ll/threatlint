---
description: "Detect React2Shell and related 2Shell-family RCE exposure: resolved vulnerable React Server Components and Next.js versions, App Router exposure, upgrade paths, and secret-rotation triggers."
argument-hint: "Optional package root, app directory, or redacted detector output path"
model: claude-opus-5-5
---

Delegate to `appsec-2shell-detector`. Pass `$ARGUMENTS` as the scope and supplied evidence locations.

Load `threatlint-evidence-analysis`, `threatlint-actionable-reporting`, then `threatlint-2shell-detection`. Run the read-only deterministic detector first when it is installed (`threatlint detect-2shell scan --path . --format markdown`), then verify and extend its findings from lockfiles, App Router evidence, and deploy configuration.

Never install or upgrade packages, send traffic to live hosts, run exploit payloads, or execute tests. Upgrade and regression checks are proposals **NOT RUN**.

Return the complete TS-NNN review as text with lockfile evidence, package-root inventory, advisory upgrades, owners/effort, rotation guidance, and acceptance criteria. Report persistence is host-owned; the delegated agent must not write files or export reports.
