---
description: "Review business-flow invariants, entitlements, idempotency, races, and asynchronous side effects from source evidence."
argument-hint: "Optional business flow, service, component, or redacted evidence path"
model: claude-sonnet-5-5
---

Delegate to `appsec-business-logic-reviewer`. Pass `$ARGUMENTS` as the scope and supplied evidence locations.

Load `threatlint-evidence-analysis`, `threatlint-actionable-reporting`, then `threatlint-business-logic`. Trace authoritative checks through state transitions, transactions, retries, jobs, and durable side effects. State unknown policy or concurrency assumptions rather than inventing business rules.

Do not send requests, replay webhooks, execute races, place orders, transfer value, use credentials, or run tests. Suggested synthetic acceptance cases are **NOT RUN**.

Return the complete BL-NNN review as text with quoted source evidence, advisory fixes, compatibility/retry implications, owners/effort, and acceptance criteria. Report persistence is host-owned; the delegated agent must not write files or export reports.
