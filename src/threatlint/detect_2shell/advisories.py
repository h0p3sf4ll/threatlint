"""Verified advisory catalog for the "*-2Shell" and "*-4Shell" families of framework RCE flaws.

Every entry here is copied from the vendor advisory it cites. Do not add an entry
without an authoritative source URL and exact fixed versions: this catalog drives
CONFIRMED findings, so an unverified range would produce a false certainty.

Sources (read 2026-11-28):
  https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
  https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components
  https://nextjs.org/blog/CVE-2025-66478
  https://github.com/advisories/GHSA-fv66-9v8q-g76r
  https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp
  https://logging.apache.org/security.html
  https://spring.io/security/cve-2022-22965
  https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement
  https://commons.apache.org/proper/commons-text/security.html
  https://github.com/advisories/GHSA-599f-7c49-w659

Maven packages are keyed "groupId:artifactId"; npm packages by name.
"""
from __future__ import annotations

from dataclasses import dataclass, field

REACT_RSC_PACKAGES = (
    "react-server-dom-webpack",
    "react-server-dom-parcel",
    "react-server-dom-turbopack",
)


@dataclass(frozen=True)
class FixLine:
    """One release line: versions >= ``introduced`` and < ``fixed`` are affected.

    ``introduced`` and ``fixed`` are full versions, prereleases included
    (for example ``15.6.0-canary.0`` / ``15.6.0-canary.58``). ``fixed`` of ``None``
    means the whole line is affected and the remedy is to move to another line.
    """

    introduced: str
    fixed: str | None


@dataclass(frozen=True)
class Advisory:
    key: str
    title: str
    cves: tuple[str, ...]
    severity: str  # CRITICAL / HIGH / MEDIUM
    cvss: str
    packages: tuple[str, ...]
    lines: tuple[FixLine, ...]
    impact: str
    exposure: str
    remediation: str
    sources: tuple[str, ...]
    cwe: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)
    family: str = "2Shell"  # "2Shell" (React2Shell family) or "4Shell" (Log4Shell family)


_REACT_SOURCES = (
    "https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components",
    "https://github.com/advisories/GHSA-fv66-9v8q-g76r",
)
_REACT_FOLLOWUP_SOURCES = (
    "https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components",
)
_NEXT_SOURCES = (
    "https://nextjs.org/blog/CVE-2025-66478",
    "https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp",
)

ADVISORIES: tuple[Advisory, ...] = (
    Advisory(
        key="react2shell-rce",
        title="React2Shell: unauthenticated remote code execution in React Server Components",
        cves=("CVE-2025-55182",),
        severity="CRITICAL",
        cvss="10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)",
        cwe="CWE-502",
        packages=REACT_RSC_PACKAGES,
        lines=(
            FixLine("19.0.0", "19.0.1"),
            FixLine("19.1.0", "19.1.2"),
            FixLine("19.2.0", "19.2.1"),
        ),
        impact=(
            "A single crafted HTTP request to a Server Function endpoint can execute "
            "arbitrary code on the server, with no authentication."
        ),
        exposure=(
            "Exploitable when the app serves React Server Components. An app can be "
            "vulnerable even if it defines no Server Functions. Apps with no server, or "
            "no RSC-capable framework, bundler or plugin, are not affected."
        ),
        remediation=(
            "Upgrade react-server-dom-* to 19.0.4, 19.1.5 or 19.2.4 (these also close the "
            "follow-up DoS and source-exposure CVEs). If the app was internet-facing and "
            "unpatched after 2025-12-04, rotate the secrets it can read."
        ),
        sources=_REACT_SOURCES,
        tags=("rce", "rsc"),
    ),
    Advisory(
        key="react-rsc-followups",
        title="React Server Components denial of service and source code exposure",
        cves=("CVE-2025-55184", "CVE-2025-67779", "CVE-2026-23864", "CVE-2025-55183"),
        severity="HIGH",
        cvss="7.5 (DoS); 5.3 (source exposure, CVE-2025-55183)",
        cwe="CWE-400",
        packages=REACT_RSC_PACKAGES,
        lines=(
            FixLine("19.0.0", "19.0.4"),
            FixLine("19.1.0", "19.1.5"),
            FixLine("19.2.0", "19.2.4"),
        ),
        impact=(
            "A malicious request to any Server Function endpoint can hang the server. "
            "A Server Function that stringifies an argument can leak source code, "
            "including secrets hardcoded in it."
        ),
        exposure="Same packages and deployment conditions as React2Shell.",
        remediation="Upgrade react-server-dom-* to 19.0.4, 19.1.5 or 19.2.4.",
        sources=_REACT_FOLLOWUP_SOURCES,
        tags=("dos", "rsc"),
    ),
    Advisory(
        key="next-react2shell",
        title="Next.js App Router remote code execution (React2Shell downstream)",
        cves=("CVE-2025-66478", "CVE-2025-55182"),
        severity="CRITICAL",
        cvss="10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)",
        cwe="CWE-502",
        packages=("next",),
        lines=(
            FixLine("14.3.0-canary.77", None),  # canary-only line: move to 14.x stable
            FixLine("15.0.0-0", "15.0.5"),
            FixLine("15.1.0-0", "15.1.9"),
            FixLine("15.2.0-0", "15.2.6"),
            FixLine("15.3.0-0", "15.3.6"),
            FixLine("15.4.0-0", "15.4.8"),
            FixLine("15.5.0-0", "15.5.7"),
            FixLine("15.6.0-0", "15.6.0-canary.58"),
            FixLine("16.0.0-0", "16.0.7"),
            FixLine("16.1.0-0", "16.1.0-canary.12"),
        ),
        impact=(
            "Next.js vendors React Server Components, so the React2Shell request can "
            "execute arbitrary code on the Next.js server without authentication."
        ),
        exposure=(
            "App Router applications only. Next.js 13.x, 14.x stable, Pages Router "
            "applications and the Edge Runtime are not affected. No workaround exists."
        ),
        remediation=(
            "Upgrade next to the patched release on your line (`npx fix-react2shell-next` "
            "checks and bumps versions). 14.3 canary users move to the latest 14.x stable. "
            "Rotate secrets if the app was online and unpatched after 2025-12-04 13:00 PT."
        ),
        sources=_NEXT_SOURCES,
        tags=("rce", "rsc", "next"),
    ),
    Advisory(
        key="next-rsc-followups",
        title="Next.js React Server Components denial of service and source code exposure",
        cves=("CVE-2025-55184", "CVE-2025-67779", "CVE-2026-23864", "CVE-2025-55183"),
        severity="HIGH",
        cvss="7.5 (DoS); 5.3 (source exposure)",
        cwe="CWE-400",
        packages=("next",),
        lines=(
            FixLine("13.3.0-0", "14.2.35"),
            FixLine("15.0.0-0", "15.0.8"),
            FixLine("15.1.0-0", "15.1.12"),
            FixLine("15.2.0-0", "15.2.9"),
            FixLine("15.3.0-0", "15.3.9"),
            # The React post lists 15.4.10 in text and 15.4.11 in its install line;
            # use the later one so a "patched" result is never premature.
            FixLine("15.4.0-0", "15.4.11"),
            FixLine("15.5.0-0", "15.5.10"),
            FixLine("15.6.0-0", "15.6.0-canary.61"),
            FixLine("16.0.0-0", "16.0.11"),
            # Canaries are patched from 16.1.0-canary.19; stable from 16.1.5.
            FixLine("16.1.0-0", "16.1.0-canary.19"),
            FixLine("16.1.0", "16.1.5"),
        ),
        impact="Remote denial of service of the Next.js server; possible source code exposure.",
        exposure="Next.js App Router applications using React Server Components.",
        remediation=(
            "Upgrade next to 14.2.35, 15.0.8, 15.1.12, 15.2.9, 15.3.9, 15.4.11, 15.5.10, "
            "16.0.11 or 16.1.5 (or later on the same line)."
        ),
        sources=("https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components",),
        tags=("dos", "rsc", "next"),
    ),
    Advisory(
        key="rwsdk-react2shell",
        title="RedwoodSDK release predating the React2Shell fix",
        cves=("CVE-2025-55182",),
        severity="CRITICAL",
        cvss="10.0",
        cwe="CWE-502",
        packages=("rwsdk",),
        lines=(FixLine("0.0.0-0", "1.0.0-alpha.0"),),
        impact="RedwoodSDK serves React Server Components; old releases ship the vulnerable runtime.",
        exposure="RedwoodSDK applications.",
        remediation="Upgrade rwsdk to 1.0.0-alpha.0 or later (rwsdk@latest), and react-server-dom-* as above.",
        sources=("https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components",),
        tags=("rce", "rsc"),
    ),
)

# ─── *-4Shell family (Java) ─────────────────────────────────────────────────

LOG4J_CORE = "org.apache.logging.log4j:log4j-core"
SPRING_WEB_PACKAGES = (
    "org.springframework:spring-beans",
    "org.springframework:spring-webmvc",
    "org.springframework:spring-webflux",
)
# A Spring Boot parent/BOM/plugin version stands in for the Spring Framework it manages.
SPRING_BOOT = "org.springframework.boot:spring-boot"
COMMONS_TEXT = "org.apache.commons:commons-text"
_LOG4J_SOURCES = ("https://logging.apache.org/security.html",)
_SPRING_SOURCES = (
    "https://spring.io/security/cve-2022-22965",
    "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement",
)

ADVISORIES += (
    Advisory(
        key="log4shell-rce",
        title="Log4Shell: remote code execution through JNDI lookups in Log4j",
        cves=("CVE-2021-44228",),
        severity="CRITICAL",
        cvss="10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)",
        cwe="CWE-917",
        packages=(LOG4J_CORE,),
        lines=(FixLine("2.0-beta9", "2.3.1"), FixLine("2.4", "2.12.2"), FixLine("2.13.0", "2.15.0")),
        impact="An attacker who controls a logged message or parameter can make the server load and run code from an LDAP server.",
        exposure="Any application that logs attacker-influenced data with log4j-core. log4j-api alone is not affected.",
        remediation=("Upgrade log4j-core to 2.17.0 or later (Java 8+), 2.12.3 (Java 7) or 2.3.1 (Java 6); these also "
                     "close CVE-2021-45046, CVE-2021-45105 and CVE-2021-44832. Hunt for JNDI lookup strings in logs."),
        sources=_LOG4J_SOURCES,
        tags=("rce", "java"),
        family="4Shell",
    ),
    Advisory(
        key="log4j-context-lookup-rce",
        title="Log4j Thread Context lookup remote code execution (incomplete Log4Shell fix)",
        cves=("CVE-2021-45046",),
        severity="CRITICAL",
        cvss="9.0 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)",
        cwe="CWE-917",
        packages=(LOG4J_CORE,),
        lines=(FixLine("2.0-beta9", "2.3.1"), FixLine("2.4", "2.12.3"), FixLine("2.13.0", "2.16.0")),
        impact="With a non-default Pattern Layout using a Thread Context lookup, attacker-controlled MDC input can lead to code execution.",
        exposure="log4j-core with Pattern Layouts that use Context lookups (for example $${ctx:loginId}).",
        remediation="Upgrade log4j-core to 2.17.0 or later (Java 8+), 2.12.3 (Java 7) or 2.3.1 (Java 6).",
        sources=_LOG4J_SOURCES,
        tags=("rce", "java"),
        family="4Shell",
    ),
    Advisory(
        key="log4j-followups",
        title="Log4j recursive lookup denial of service and JDBC Appender code execution",
        cves=("CVE-2021-45105", "CVE-2021-44832"),
        severity="MEDIUM",
        cvss="5.9 (DoS); 6.6 (JDBC Appender, needs write access to logging configuration)",
        cwe="CWE-674",
        packages=(LOG4J_CORE,),
        lines=(FixLine("2.0-alpha1", "2.3.1"), FixLine("2.4", "2.12.3"), FixLine("2.13.0", "2.17.0")),
        impact="Recursive Context lookups can crash the application; an attacker who can edit logging configuration can run code.",
        exposure="log4j-core with Context lookups in non-default layouts, or attacker write access to logging configuration.",
        remediation="Upgrade log4j-core to 2.17.0 or later (Java 8+), 2.12.3 (Java 7) or 2.3.1 (Java 6).",
        sources=_LOG4J_SOURCES,
        tags=("dos", "java"),
        family="4Shell",
    ),
    Advisory(
        key="spring4shell-rce",
        title="Spring4Shell: remote code execution through Spring MVC / WebFlux data binding",
        cves=("CVE-2022-22965",),
        severity="CRITICAL",
        cvss="CRITICAL (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
        cwe="CWE-94",
        packages=SPRING_WEB_PACKAGES,
        # "5.2.19.RELEASE and earlier" (older, unsupported lines included) and 5.3.0-5.3.17.
        lines=(FixLine("0.0.0-0", "5.2.20"), FixLine("5.3.0-0", "5.3.18")),
        impact="A crafted request bound to a controller parameter can write a web shell and run code on the server.",
        exposure=("The known exploit needs JDK 9+, a WAR deployed to Apache Tomcat (other servlet containers are also "
                  "named), and spring-webmvc or spring-webflux. Spring Boot executable jars are not vulnerable to it."),
        remediation="Upgrade Spring Framework to 5.3.18+ or 5.2.20.RELEASE+ (Spring Boot 2.6.6+ or 2.5.12+).",
        sources=_SPRING_SOURCES,
        tags=("rce", "java"),
        family="4Shell",
    ),
    Advisory(
        key="spring-boot-spring4shell",
        title="Spring Boot release that manages a Spring4Shell-vulnerable Spring Framework",
        cves=("CVE-2022-22965",),
        severity="CRITICAL",
        cvss="CRITICAL",
        cwe="CWE-94",
        packages=(SPRING_BOOT,),
        lines=(FixLine("0.0.0-0", "2.5.12"), FixLine("2.6.0-0", "2.6.6")),
        impact="Spring Boot releases before 2.5.12 / 2.6.6 manage a Spring Framework version affected by Spring4Shell.",
        exposure="Same conditions as Spring4Shell; the managed Spring version can be overridden, so confirm the resolved version.",
        remediation="Upgrade Spring Boot to 2.6.6+ or 2.5.12+ (both depend on Spring Framework 5.3.18).",
        sources=_SPRING_SOURCES,
        tags=("rce", "java"),
        family="4Shell",
    ),
    Advisory(
        key="text4shell-rce",
        title="Text4Shell: code execution through Apache Commons Text interpolation",
        cves=("CVE-2022-42889",),
        severity="CRITICAL",
        cvss="9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
        cwe="CWE-94",
        packages=(COMMONS_TEXT,),
        lines=(FixLine("1.5", "1.10.0"),),
        impact="The default script, dns and url lookups let untrusted interpolation input run code or reach remote servers.",
        exposure=("Exploitable only when untrusted input reaches StringSubstitutor interpolation (the defaults). Apache "
                  "was not aware of applications that do this; verify usage in source."),
        remediation="Upgrade commons-text to 1.10.0 or later.",
        sources=("https://commons.apache.org/proper/commons-text/security.html",
                 "https://github.com/advisories/GHSA-599f-7c49-w659"),
        tags=("rce", "java"),
        family="4Shell",
    ),
)

FAMILIES = ("2Shell", "4Shell")

# Frameworks whose presence means the app serves RSC through react-server-dom-*.
# They carry no version range of their own (the advisories give none); the vulnerable
# code is the react-server-dom-* dependency, which the lockfile check covers.
RSC_FRAMEWORK_MARKERS = (
    "next",
    "waku",
    "react-router",
    "@vitejs/plugin-rsc",
    "@parcel/rsc",
    "rwsdk",
    "expo-router",
)

WATCHED_PACKAGES = frozenset(
    {pkg for adv in ADVISORIES for pkg in adv.packages} | set(RSC_FRAMEWORK_MARKERS)
)
