---
name: threatlint-api-security
description: "Use for REST, GraphQL, gRPC, and WebSocket API reviews: object/property/function authorization, resource limits, business flows, SSRF, and response contracts."
---

# API boundary and contract review

1. Inventory routes, methods/procedures, versions, subscriptions/messages, public/internal
   exposure, authentication registration, and service-to-service callers. Include legacy aliases.
2. Trace request parsing → authenticated identity → tenant/object selection → property binding
   → authorization → data access → serialized response. Check write and read paths separately.
3. Build a role × operation × object/tenant matrix. Verify explicit ownership/scoping at the
   point of access, including nested objects, bulk operations, exports, and alternate protocols.
4. Check allowlisted writable/readable properties, pagination and query complexity, upload
   size, concurrency, expensive third-party calls, and abuse-sensitive business transitions.
5. For outbound URLs, follow scheme/host validation, redirects, DNS/IP handling, and network
   controls. Do not call endpoints; identify runtime assumptions needing authorized verification.
6. Map only supported findings to OWASP API Top 10 (2023). Propose code-specific authorization,
   schema, resource-budget, or outbound-request fixes without inventing infrastructure controls.

## Deliverables

AR findings identify method/endpoint or message type, required role, affected object/data,
caller-to-sink evidence, proposed fix, compatibility impact, and cross-tenant/role regression
assertions. Include expected denial and allowed-success responses, not just a happy-path test.