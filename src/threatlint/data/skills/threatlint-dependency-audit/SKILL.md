---
name: threatlint-dependency-audit
description: "Use for dependency and supply-chain audits: resolved versions, advisory applicability, reachability, registries, integrity, dependency confusion, and safe upgrades."
---

# Dependency evidence and upgrade planning

1. Locate manifests, lockfiles, workspace overrides, private-registry settings, install scripts,
   and vendored artifacts. Distinguish direct/transitive and build/test/runtime dependencies.
2. Resolve versions from the actual lockfile, not just a broad manifest constraint. Identify
   whether install commands enforce that lockfile and whether integrity metadata is present.
3. For a CVE claim, require a verifiable advisory identifier, affected version range, resolved
   installed version, and applicability conditions. If current advisory data is unavailable,
   say **advisory status unverified**; do not invent current vulnerability counts or fixed versions.
4. Trace the vulnerable feature's import/use and deployment reachability where visible.
   "Not found in static search" is not proof of unreachability, especially for plugins/build tools.
5. Review registry precedence, internal names published to public registries, lifecycle scripts,
   mutable source references, integrity verification, and evidence of package provenance.
   An unfamiliar name or old release is a research lead, not proof of a malicious package.
6. Propose the smallest supported patched upgrade, lockfile refresh, breaking-change review,
   test plan, rollback, and any temporary mitigation. Never install or execute dependency code.

## Deliverables

DA findings identify package/ecosystem, direct or transitive path, exact version evidence,
advisory source/verification date when known, applicability, proposed version/alternative,
owner/effort, and acceptance tests. Redact registry credentials and authentication headers.