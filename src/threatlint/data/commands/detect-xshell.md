---
description: "Detect *-Shell exposures: *-2Shell (React2Shell, Next.js, PHP2Shell, WP2Shell, Node2Shell) and *-4Shell (Log4Shell, Spring4Shell, Text4Shell, Java4Shell): resolved vulnerable versions and runtime pins, exposure context, impacted lines with no fix, upgrade paths, and rotation triggers."
argument-hint: "Optional package root, app or module directory, or redacted detector output path"
model: claude-opus-5-5
---

Delegate to `appsec-xshell-detector`. Pass `$ARGUMENTS` as the scope and supplied evidence locations.

Load `threatlint-evidence-analysis`, `threatlint-actionable-reporting`, then `threatlint-xshell-detection`. Run the read-only deterministic detector first when it is installed (`threatlint detect-xshell scan --path . --format markdown`), then verify and extend its findings from lockfiles, Maven/Gradle builds, vendored jars, App Router, WAR packaging and StringSubstitutor evidence, and deploy configuration.

Never install or upgrade packages, send traffic to live hosts, run exploit payloads, or execute tests. Upgrade and regression checks are proposals **NOT RUN**.

Return the complete TS-NNN review (each finding labelled *-2Shell or *-4Shell; impacted lines with no fix marked "No fix on this line") as text with lockfile or build evidence, package-root inventory, advisory upgrades, owners/effort, rotation guidance, and acceptance criteria. Report persistence is host-owned; the delegated agent must not write files or export reports.
