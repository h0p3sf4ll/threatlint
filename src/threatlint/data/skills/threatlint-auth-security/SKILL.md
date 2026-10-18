---
name: threatlint-auth-security
description: "Use for authentication and authorization deep dives: OAuth/OIDC, JWT, sessions, CSRF, MFA/recovery, password flows, RBAC/ABAC, and multi-tenant isolation."
---

# Identity lifecycle and authorization review

1. Map enrollment, login, federation, refresh, recovery, step-up, role changes, logout, and
   revocation. Identify where trust moves between browser, backend, identity provider, and store.
2. Trace each credential/token from issuance to validation. Check signature algorithm/key
   selection, issuer/audience/time claims, token purpose, rotation, revocation, and failure paths.
3. For OAuth/OIDC, verify state/nonce/PKCE as applicable to the flow, exact redirect policies,
   code binding, account linking, and client type. Do not assume all flows share requirements.
4. Review cookie/session fixation, CSRF within the actual authentication mode, cross-origin
   handling, MFA enrollment/recovery bypasses, throttling, and account enumeration.
5. Trace permissions to object/tenant access and privileged state changes. A UI restriction or
   role assertion from a request/token is not enforcement without trusted verification.
6. Propose framework-native controls, migration/rotation order, session invalidation effects,
   compatibility considerations, and least-privilege authorization. Do not test live credentials.

## Deliverables

AU findings cite issuance/verification/enforcement evidence, actor and prerequisite, concrete
boundary failure, proposed fix, owner/effort, and negative assertions for replay, wrong tenant,
wrong issuer/audience, expired/revoked tokens, recovery, and alternate paths as applicable.