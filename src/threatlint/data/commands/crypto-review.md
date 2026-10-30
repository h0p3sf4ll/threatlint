---
description: "Review cryptographic purpose, primitives, key/nonce lifecycles, KDFs, verification, and TLS from source evidence."
argument-hint: "Optional cryptographic use, module, configuration, or redacted evidence path"
model: claude-sonnet-5-5
---

Delegate to `appsec-crypto-reviewer`. Pass `$ARGUMENTS` as the scope and supplied evidence locations.

Load `threatlint-evidence-analysis`, `threatlint-actionable-reporting`, then `threatlint-cryptography`. Establish the security purpose, callers, actual library semantics, key/nonce lifecycle, verification boundary, and wire/storage compatibility before judging a primitive.

Never inspect unredacted keys, use real credentials, decrypt/crack data, make TLS connections, run experiments, or execute tests. Synthetic-key and known-answer acceptance cases are proposals **NOT RUN**; do not claim recovered data or forged signatures.

Return the complete CY-NNN review as text with source evidence, established-library advisory fixes, migration/rotation implications, owners/effort, and acceptance criteria. Report persistence is host-owned; the delegated agent must not write files or export reports.
