---
description: "Inventory personal/sensitive data and review its flows, minimization, retention, consent, and protection from source evidence."
argument-hint: "Optional data domain, module, integration, or redacted evidence path"
---

Delegate to `appsec-privacy-reviewer`. Pass `$ARGUMENTS` as the scope and supplied evidence locations.

Load `threatlint-evidence-analysis`, `threatlint-actionable-reporting`, then `threatlint-privacy-review`. Build the data inventory and trace flows to storage, logs, analytics, AI providers, and third parties before judging minimization, retention, consent, or protection.

Never print or query real personal data, connect to databases, make network requests, or execute tests. This is not a legal opinion. Synthetic-data acceptance cases are proposals **NOT RUN**.

Return the complete PD-NNN review as text with source evidence, data inventory, advisory fixes, owners/effort, obligations for privacy/legal confirmation, and acceptance criteria. Report persistence is host-owned; the delegated agent must not write files or export reports.
