---
name: threatlint-cryptography
description: "Use for cryptographic implementation review: security purpose, algorithms and modes, entropy, nonce/key lifecycle, KDFs, signatures/MACs, TLS verification, and safe compatibility or rotation proposals."
---

# Cryptographic purpose and lifecycle review

1. Inventory each security-relevant use and asset: confidentiality, integrity, authenticity,
   password verification, token generation, or transport protection. Record library/version
   when observable, callers, key/nonce sources, trust boundary, and encrypted/signed format.
   A checksum, cache key, or non-security identifier is not a vulnerability solely by algorithm.
2. Trace algorithm/mode selection and defaults, key size, authenticated encryption or
   encrypt-then-MAC composition, associated data/context binding, tag verification before
   plaintext use, padding/error behavior, and algorithm downgrade/fallback paths. Verify
   library semantics from available evidence; do not assume an API name guarantees safety.
3. Examine nonce/IV uniqueness requirements for the actual construction and key scope across
   restarts, concurrency, tenants, and distributed writers. Distinguish salts from nonces and
   randomness from uniqueness. Show how reuse or predictability becomes possible and matters.
4. Trace CSPRNG use for secrets/tokens, password KDF and salt/work parameters, key derivation
   and domain separation, signature/MAC verification, canonicalization, replay/context binding,
   and secret comparisons where applicable. Do not infer exploitable timing from equality alone.
5. Follow key generation, access control, storage references, separation of duties, rotation,
   version selection, revocation, backup, and destruction. Redact key values; never validate,
   decrypt with, export, crack, or search external services for real keys or credentials.
6. Inspect certificate-chain and hostname verification, trust-store overrides, protocol
   selection, and environment-specific exceptions. Tie a disabled check or weak primitive to
   a reachable security use and realistic attacker capability; unknown deployment is a limit.
7. Propose established library/KMS/framework APIs already supported by the project where
   possible, not custom cryptography. Include format/version compatibility, staged migration,
   re-encryption/rehash or rotation order, rollback constraints, owner/effort, and residual risk.
   Do not assert algorithm compliance or invent a vulnerability advisory/control identifier.

## Deliverables

CY findings quote security use, configuration, and key/nonce/verification paths with 1-based
lines; identify the broken property, actor, prerequisites, control/bypass evidence, impact,
severity/confidence, proposed fix, and owner/effort. Provide an inventory and proposed
acceptance assertions using synthetic keys and known-answer vectors, wrong keys/context,
tampered/truncated data, nonce lifecycle, migration compatibility, and invalid TLS peers as
applicable. All proposed validation is **NOT RUN**; static analysis is not cryptanalysis or
proof that confidentiality/integrity was broken in a deployed system.
