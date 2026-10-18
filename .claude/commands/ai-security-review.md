---
description: "Review AI/LLM prompt, retrieval, memory, tool/agent authority, tenant isolation, output sinks, and provider data boundaries."
argument-hint: "Optional AI flow, tool, retrieval pipeline, component, or redacted evidence path"
---

Delegate to `appsec-ai-security-reviewer`. Pass `$ARGUMENTS` as the scope and supplied evidence locations.

Load `threatlint-evidence-analysis`, `threatlint-actionable-reporting`, then `threatlint-ai-security`. Trace untrusted inputs through models/retrieval/memory to deterministic authorization and actual tool/output sinks, tenant binding, provider flows, and budgets. Prompt influence alone is not an authority breach.

Do not call model providers or application tools, submit adversarial prompts, poison indexes, browse targets, use credentials, or execute tests. Synthetic direct/indirect injection, tool/RAG/tenant/output cases are proposals **NOT RUN**.

Return the complete AI-NNN review as text with source quotes, deterministic advisory fixes, compatibility implications, owners/effort, and acceptance criteria. Report persistence is host-owned; the delegated agent must not write files or export reports.
