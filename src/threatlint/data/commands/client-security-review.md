---
description: "Review browser, SPA, Electron, and mobile trust boundaries: DOM, origins, IPC, navigation, storage, and server enforcement."
argument-hint: "Optional client, renderer, bridge, component, or redacted evidence path"
---

Delegate to `appsec-client-security-reviewer`. Pass `$ARGUMENTS` as the scope and supplied evidence locations.

Load `threatlint-evidence-analysis`, `threatlint-actionable-reporting`, then `threatlint-client-security`. Trace attacker input through rendering/origin checks, navigation, messaging/IPC, sensitive storage, and privileged backend or native effects in the actual platform.

Do not open browsers/apps, navigate targets, inject scripts, invoke IPC/deep links, use sessions/credentials, or run tests. Proposed isolation and rendering acceptance cases are **NOT RUN**; sink names or screenshots alone do not prove compromise.

Return the complete CL-NNN review as text with source quotes, advisory framework-native fixes, compatibility implications, owners/effort, and acceptance criteria. Report persistence is host-owned; the delegated agent must not write files or export reports.
