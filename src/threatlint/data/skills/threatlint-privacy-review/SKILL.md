---
name: threatlint-privacy-review
description: "Use for privacy and sensitive-data review: PII inventory, flows to logs, analytics, and third parties, minimization, retention, consent, access, and encryption-at-rest gaps."
---

# Privacy and sensitive-data flow review

1. Inventory personal and sensitive data the code collects, derives, or stores: identifiers,
   contact data, credentials, government IDs, payment data, health, location, biometrics,
   precise device or behavioral data, children's data, and free-text fields likely to contain
   them. Record schema/model/field location, source (user input, integration, inference), and
   the stated or apparent purpose. Field names suggest, but do not prove, contents.
2. Trace each category through its lifecycle: collection, validation, transformation, storage,
   caching, search indexes, queues, backups, exports, and deletion. Identify the trust boundary
   at each hop and the identities or services that can read it.
3. Follow outbound flows to logs, error trackers, metrics, analytics and session-replay SDKs,
   advertising pixels, LLM or AI providers, email/SMS services, webhooks, and other third
   parties. Show the exact call and the fields it sends. Check for request/response body
   logging, exception messages containing records, URL query strings with identifiers, and
   client-side storage of sensitive values.
4. Assess minimization: fields collected or retained without an evidenced use, over-broad API
   responses or serializers, debug endpoints, wide `SELECT *` exports, and data copied into
   lower-trust environments or fixtures. Distinguish evidence of over-collection from purposes
   the code cannot reveal.
5. Inspect retention and deletion: TTLs, scheduled purges, soft-delete versus hard-delete,
   cascade behavior, backup/replica handling, and account-deletion or data-subject-request
   handlers. Absence of a purge in the inspected scope is an unknown unless the scope is shown
   to be complete.
6. Review consent and preference handling where present: gating of analytics/marketing SDKs on
   consent state, honoring opt-outs server-side, and default-on tracking. Review access control
   on sensitive records, field-level masking, and audit logging of sensitive access.
7. Check protection at rest and in transit for sensitive categories: database/field encryption
   or tokenization configuration, key references (never values), storage bucket and disk
   settings visible in the repository, and TLS for outbound transfers. Unknown infrastructure
   configuration is a limitation.
8. Propose minimal, framework-native fixes: structured-logging redaction filters, serializer
   allowlists, consent gates, TTL jobs, deletion cascades, field encryption via the existing
   KMS/library, and data-processing notes for third-party transfers. Do not state legal
   conclusions or claim regulatory compliance or non-compliance; note which obligations a
   privacy or legal owner should confirm.

## Deliverables

Provide a data inventory (category, location, source, purpose, storage, recipients, retention,
protection) and a data-flow summary. PD findings quote collection/flow/storage code with 1-based
lines, identify the data category, recipient or exposure, actor/prerequisites, privacy and
security impact, severity/confidence, anchored advisory fix, and owner/effort. Include proposed
acceptance assertions: redacted log output, serializer omits fields, SDK not loaded without
consent, record purged after TTL, deletion removes derived copies, and so on. Never print real
personal data; use synthetic examples. Proposed fixes are **NOT APPLIED** and tests are
**NOT RUN**; this is not a legal or regulatory assessment.
