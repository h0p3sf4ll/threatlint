---
name: threatlint-2shell-detection
description: "Use for 2Shell-family RCE exposure analysis: React2Shell (CVE-2025-55182), Next.js App Router (CVE-2025-66478), React Server Components follow-up DoS and source-exposure CVEs, resolved-version evidence, exposure context, and upgrade plus rotation planning."
---

# 2Shell exposure detection

## Verified advisory catalog

Sources: react.dev security posts of 2025-12-03 and 2025-12-11, nextjs.org/blog/CVE-2025-66478,
GHSA-fv66-9v8q-g76r, and GHSA-9qr9-h5gf-34mp. Use only these ranges for CONFIRMED findings.

| Advisory | Packages | Affected | First fixed on each line | Severity |
| --- | --- | --- | --- | --- |
| CVE-2025-55182 React2Shell, unauthenticated RCE (CWE-502) | `react-server-dom-webpack`, `-parcel`, `-turbopack` | 19.0.0, 19.1.0, 19.1.1, 19.2.0 | 19.0.1, 19.1.2, 19.2.1 | CRITICAL, CVSS 10.0 |
| CVE-2025-55184, CVE-2025-67779, CVE-2026-23864 (DoS); CVE-2025-55183 (source exposure) | same packages | 19.0.0 to 19.2.3 | 19.0.4, 19.1.5, 19.2.4 | HIGH (7.5); source exposure MEDIUM (5.3) |
| CVE-2025-66478 Next.js App Router RCE | `next` | 14.3.0-canary.77 and later canaries; 15.x and 16.x before the fix | 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7; canaries 15.6.0-canary.58, 16.1.0-canary.12; 14.3 canaries move to the latest 14.x stable | CRITICAL, CVSS 10.0 |
| Next.js RSC DoS and source-exposure follow-ups | `next` | 13.3 and later before the fix | 14.2.35, 15.0.8, 15.1.12, 15.2.9, 15.3.9, 15.4.11, 15.5.10, 16.0.11, 16.1.5 | HIGH |
| RedwoodSDK before the fix | `rwsdk` | below 1.0.0-alpha.0 | 1.0.0-alpha.0 | CRITICAL |

Not affected by the RCE: Next.js 13.x, Next.js 14.x stable, Pages Router-only applications, the
Edge Runtime, and apps with no server or no RSC-capable framework, bundler, or plugin. An app can
be vulnerable without defining any Server Function if it serves React Server Components.

## Procedure

1. Run `threatlint detect-2shell scan --path . --format markdown` when it is installed. It parses
   lockfiles deterministically and reports each package root. Verify its output against source;
   extend it to monorepo roots, vendored copies, Dockerfiles, and deploy manifests it cannot see.
2. Treat a resolved lockfile version inside an affected range as a CONFIRMED vulnerable version.
   A manifest range that admits an affected version, with no lockfile, is PLAUSIBLE. A version
   that only matches through an unknown or unparsed source is THEORETICAL.
3. Severity follows the advisory, then adjusts for exposure: an App Router or RSC app that is
   internet-facing keeps CRITICAL; a Pages Router-only Next.js app is not affected by the RCE;
   internal-only or build-time-only use lowers severity and the reason must be stated.
4. Establish exposure with evidence: `app/` route files, `"use server"` directives, RSC framework
   markers (Waku, React Router RSC APIs, `@vitejs/plugin-rsc`, `@parcel/rsc`, Expo Router server
   components, RedwoodSDK), `output: 'export'` static builds, runtime selection, and ingress.
5. Never send requests to live hosts, run exploit payloads, or claim compromise. Recommend
   incident review and secret rotation when an internet-facing app was vulnerable after
   2025-12-04 13:00 PT; rotation is a recommendation, not an action this role performs.
6. Propose the smallest upgrade that closes every applicable CVE on the current release line,
   with the package-manager command (`npm install next@<fixed>`, `pnpm up`, `yarn up`) and the
   official helper `npx fix-react2shell-next` for Next.js. Lockfiles must be regenerated.
7. Other 2Shell-family flaws (for example PHP2Shell, WP2Shell, HTTP2Shell) are reported only with
   cited vendor advisories and exact versions. Without them, list them under coverage gaps.

## Deliverables

TS findings cite the lockfile `path:line` of the resolved version, the CVEs, the fixed version on
the same line, exposure evidence, impact, severity/confidence, anchored upgrade, owner/effort, and
acceptance checks: lockfile no longer resolves an affected version, CI detector gate passes, App
Router smoke test passes. Proposed fixes are **NOT APPLIED** and tests are **NOT RUN**.
