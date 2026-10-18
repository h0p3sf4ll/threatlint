---
name: threatlint-client-security
description: "Use for browser, SPA, Electron, and mobile-client security review: DOM/data flows, origins, navigation, messages and IPC, storage, service workers, deep links, and privileged client/server boundaries."
---

# Client-side trust and privilege boundaries

1. Identify actual clients, frameworks, renderers/webviews, origins, privileged processes,
   backend APIs, platform configuration, and build settings. Review only applicable platforms;
   do not assume Electron, a native bridge, or production exposure from a browser dependency.
2. Trace URL/query/fragment, API, message, storage, local-file, and third-party data through
   decoding, templates, sanitizers, and DOM/HTML/JavaScript/navigation sinks. Establish attacker
   control and execution context. Framework escaping or a dangerous sink name alone settles
   neither exploitability nor safety; inspect sanitizer configuration and post-sanitize changes.
3. Check effective CSP/Trusted Types, frame/embed policy, cross-origin requests, messaging
   origin/source validation, redirect/navigation allowlists, and popup/opener boundaries.
   Missing headers are observations until applicable content and a boundary failure are shown.
   Wildcard messaging requires a sensitive payload or unsafe receiver path to establish impact.
4. Trace tokens and sensitive state in browser/native storage, URLs, logs, analytics, caches,
   service workers, offline data, and logout/account switching. Do not equate localStorage use
   with demonstrated credential theft; identify the read capability, persistence, and impact.
5. For Electron/native bridges, inspect preload exposure, context isolation, sandbox and node
   integration, IPC sender/frame/origin checks, argument schemas, file/shell privileges,
   navigation/window creation, deep links, and certificate handling where present. Verify a
   reachable untrusted renderer can cross the bridge before claiming privileged execution.
6. Trace client-side role/feature/payment gates to authoritative server checks. Inspect
   cross-account/tenant caches and deep-link handoffs. A public build-time configuration value
   is not automatically a secret, and UI visibility is not authorization enforcement.
7. Propose context-correct rendering, narrow origin/capability checks, secure storage/lifecycle,
   or framework-native isolation fixes. Explain compatibility, rollout, owner/effort, and
   residual risk. Do not launch clients, browse targets, inject scripts, or access sessions.

## Deliverables

CL findings include source-to-sink quotes and 1-based lines, platform/build assumptions,
origin and privilege boundaries, attacker control, effective defenses and bypass assessment,
impact, severity/confidence, proposed fix, and owner/effort. Add a client boundary coverage
matrix and positive/negative assertions for encoding, untrusted origin/frame, alternate
navigation, IPC schema, and account/tenant switching as applicable. Proposed tests are
**NOT RUN**; supplied screenshots or scans do not alone prove script or native-code execution.
