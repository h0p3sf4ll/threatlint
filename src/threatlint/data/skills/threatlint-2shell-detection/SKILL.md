---
name: threatlint-2shell-detection
description: "Use for *-2Shell and *-4Shell RCE exposure analysis: React2Shell (CVE-2025-55182), Next.js App Router (CVE-2025-66478) and RSC follow-ups, Log4Shell (CVE-2021-44228 and follow-ups), Spring4Shell (CVE-2022-22965), Text4Shell (CVE-2022-42889), resolved-version evidence, exposure context, and upgrade, log-hunting, and rotation planning."
---

# *-2Shell and *-4Shell exposure detection

## Verified advisory catalog: *-2Shell (JavaScript)

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

## Verified advisory catalog: *-4Shell (Java)

Sources: logging.apache.org/security.html, spring.io/security/cve-2022-22965, the Spring Framework
RCE early-announcement blog post of 2022-03-31, commons.apache.org/proper/commons-text/security.html,
and GHSA-599f-7c49-w659. Use only these ranges for CONFIRMED findings.

| Advisory | Maven package | Affected | First fixed | Severity |
| --- | --- | --- | --- | --- |
| CVE-2021-44228 Log4Shell, JNDI lookup RCE (CWE-917) | `org.apache.logging.log4j:log4j-core` | 2.0-beta9 to before 2.3.1; 2.4 to before 2.12.2; 2.13.0 to before 2.15.0 | 2.3.1 (Java 6), 2.12.2 (Java 7), 2.15.0 (Java 8+) | CRITICAL, CVSS 10.0 |
| CVE-2021-45046 Thread Context lookup RCE (incomplete fix) | `log4j-core` | 2.0-beta9 to before 2.3.1; 2.4 to before 2.12.3; 2.13.0 to before 2.16.0 | 2.3.1, 2.12.3, 2.16.0 | CRITICAL, CVSS 9.0 |
| CVE-2021-45105 recursive lookup DoS; CVE-2021-44832 JDBC Appender RCE (needs config write access) | `log4j-core` | up to before 2.3.1; 2.4 to before 2.12.3; 2.13.0 to before 2.17.0 | 2.3.1, 2.12.3, 2.17.0 | MEDIUM (5.9; 6.6) |
| CVE-2022-22965 Spring4Shell, data-binding RCE | `org.springframework:spring-beans`, `spring-webmvc`, `spring-webflux` | 5.3.0 to 5.3.17; 5.2.19.RELEASE and earlier (older unsupported lines included) | 5.3.18, 5.2.20.RELEASE; Spring Boot 2.6.6 and 2.5.12 depend on 5.3.18 | CRITICAL |
| CVE-2022-42889 Text4Shell, interpolation RCE | `org.apache.commons:commons-text` | 1.5 to before 1.10.0 | 1.10.0 | CRITICAL, CVSS 9.8 |

Recommended Log4j targets: 2.17.0 or later on Java 8+, 2.12.3 on Java 7, 2.3.1 on Java 6 (these
close all four Log4j CVEs). `log4j-api` without `log4j-core` is not affected.

Exploit preconditions to evidence before keeping CRITICAL/CONFIRMED:
- Log4Shell: attacker-influenced data reaches a log message or parameter (almost always true for
  request-handling services). CVE-2021-45046/45105 need non-default Pattern Layouts with Context
  lookups such as `$${ctx:loginId}`.
- Spring4Shell: JDK 9+, a WAR deployed to Apache Tomcat or another servlet container, and
  spring-webmvc or spring-webflux. Spring Boot executable jars are not vulnerable to the known
  exploit; report them as PLAUSIBLE with an upgrade, not CRITICAL/CONFIRMED.
- Text4Shell: untrusted input reaches `StringSubstitutor` interpolation with the default
  `script`, `dns`, and `url` lookups. Apache was not aware of applications doing this; without
  source evidence of such a path, the finding is PLAUSIBLE.

## Procedure

1. Run `threatlint detect-2shell scan --path . --format markdown` (alias `detect-4shell`) when it
   is installed. It parses npm/Yarn/pnpm/Bun lockfiles, `pom.xml`, Gradle builds and version
   catalogs, `gradle.lockfile`, and vendored jar names deterministically. Verify its output against
   source; extend it to monorepo roots, shaded or fat jars, application-server `lib/` folders,
   Dockerfiles, and deploy manifests it cannot see.
2. Evidence strength:
   - CONFIRMED: a resolved lockfile version (npm, Yarn, pnpm, Bun, `gradle.lockfile`), a direct
     Maven dependency (Maven resolves the nearest declaration), or a vendored jar inside an
     affected range.
   - PLAUSIBLE: a manifest range with no lockfile, a Gradle build or version-catalog declaration
     (Gradle resolves the highest requested version), or a Spring Boot version that only implies
     the managed Spring Framework.
   - THEORETICAL: a version that only matches through an unknown or unparsed source, or an
     affected version whose exposure precondition is shown to be absent.
3. Severity follows the advisory, then adjusts for exposure, and the reason must be stated:
   - An App Router or RSC app that is internet-facing keeps CRITICAL; a Pages Router-only Next.js
     app is not affected by the RCE.
   - A WAR on a servlet container keeps Spring4Shell CRITICAL; an executable jar lowers confidence.
   - Internal-only or build-time-only use lowers severity.
4. Establish exposure with evidence:
   - *-2Shell: `app/` route files, `"use server"` directives, RSC framework markers (Waku, React
     Router RSC APIs, `@vitejs/plugin-rsc`, `@parcel/rsc`, Expo Router server components,
     RedwoodSDK), `output: 'export'` static builds, runtime selection, and ingress.
   - *-4Shell: logging of request data, `log4j2.xml` layouts, `<packaging>war</packaging>` or the
     Gradle `war` plugin, servlet container and JDK version in Dockerfiles, `StringSubstitutor`
     and `StringLookupFactory` usage.
5. Never send requests to live hosts, run exploit payloads, or claim compromise. Recommend incident
   review and secret rotation when an internet-facing app ran a vulnerable version (React2Shell:
   after 2025-12-04 13:00 PT). Recommend log hunting for `${jndi:` strings (including obfuscated
   forms such as `${${lower:j}ndi:`), `class.module.classLoader` request parameters, and
   unexpected Server Function requests. Rotation is a recommendation, not an action this role
   performs.
6. Propose the smallest upgrade that closes every applicable CVE on the current release line, with
   the build-tool change: `npm install next@<fixed>`, `pnpm up`, `yarn up`, or the official helper
   `npx fix-react2shell-next`; a Maven property or `dependencyManagement` pin (or Spring Boot
   parent bump); a Gradle constraint followed by `gradle dependencies --write-locks`. Lockfiles
   must be regenerated.
7. Other *-2Shell or *-4Shell names (for example PHP2Shell, WP2Shell, HTTP2Shell) are reported only
   with cited vendor advisories and exact versions. Without them, list them under coverage gaps.

## Deliverables

TS findings name the family (*-2Shell or *-4Shell) and cite the evidence `path:line` of the
resolved version, the CVEs, the fixed version on the same line, exposure evidence, impact,
severity/confidence, anchored upgrade, owner/effort, and acceptance checks: the lockfile or
dependency report no longer resolves an affected version, the CI detector gate passes, and an App
Router or application smoke test passes. Proposed fixes are **NOT APPLIED** and tests are **NOT RUN**.
