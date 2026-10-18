---
name: threatlint-business-logic
description: "Use for business-logic security review: workflow invariants, entitlement and tenant semantics, payment/credit abuse, idempotency, race conditions, asynchronous processing, and evidence-grounded regression design."
---

# Business invariants and abuse-path review

1. Discover actual domain operations, actors, roles/tenants, assets, and state transitions from
   handlers, services, persistence, queues, and tests. Separate documented business rules from
   rules inferred from code; a surprising outcome is not abuse without a supported invariant.
2. For each sensitive flow, record allowed transitions and who may cause them: enrollment,
   approval, purchase, reservation, refund, credit, quota, entitlement, cancellation, or export
   only where present. Trace server-authoritative price, amount, currency, inventory, status,
   ownership, and tenant sources; do not treat client validation as enforcement.
3. Inspect skipped/reordered steps, stale approvals, replay, alternate endpoints, bulk paths,
   negative/zero/overflow/precision boundaries, partial failures, and compensating operations.
   Verify checks protect the final side effect, not merely a preceding UI or preflight call.
4. Analyze concurrency from the actual database and transaction semantics: isolation level,
   check-then-act windows, locking, compare-and-swap, unique constraints, atomic updates, and
   commit order. Show a concrete two-operation interleaving and a violated invariant; an
   asynchronous function or missing explicit lock alone is not proof of a race condition.
5. Inspect retries, duplicate/out-of-order messages, webhook authenticity, deduplication and
   idempotency scope, key binding to actor/tenant/payload, and external-call transaction gaps.
   Do not assume exactly-once delivery or that a transaction covers a remote side effect.
6. Trace tenant/subject identity through resource lookup, background jobs, cache keys, exports,
   delegated access, and role changes. Distinguish intended administrator powers from an
   unauthorized cross-tenant effect; name the missing policy or runtime assumption explicitly.
7. Propose the smallest root-cause control at the authoritative boundary, with compatibility,
   retry/failure semantics, migration order, owner/effort, and residual risk. Do not modify code,
   place orders, transfer value, replay webhooks, or run concurrent requests.

## Deliverables

BL findings quote the transition/check and side-effect evidence with 1-based source lines,
identify the actor/tenant, supported invariant, prerequisites, bypass/interleaving, impact,
severity and confidence, proposed fix, and owner/effort. Do not invent commercial impact,
policies, or a completed exploit. Include an invariant/transition coverage matrix and proposed
positive, negative, replay, concurrent, rollback, and cross-tenant acceptance assertions using
synthetic fixtures. Label proposed tests **NOT RUN** and distinguish supplied execution
evidence from static reasoning. Unknown invariants stay open questions, not confirmed flaws.
