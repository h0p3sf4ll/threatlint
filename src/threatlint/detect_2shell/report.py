"""JSON and Markdown renderings shared by single-repository and fleet scans.

The Markdown uses the ThreatLint two-tier layout and `#### [TS-NNN] — Title` headings
with **Severity** / **Confidence** lines, so gate_report.py, to_sarif.py and
create_issues.py treat it like any specialist report.
"""
from __future__ import annotations

import datetime as _dt

from .advisories import ADVISORIES, FAMILIES

SCHEMA = "threatlint.detect-2shell/v1"
TOOL = "threatlint detect-2shell"


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def target_result(scan, *, provider="local", organization="", project="", repository="", branch="", commit="",
                  error="") -> dict:
    if error:
        return {"provider": provider, "organization": organization, "project": project, "repository": repository,
                "branch": branch, "commit": commit, "status": "error", "findings": [], "inventory": [],
                "coverage": [], "error": error}
    return {"provider": provider, "organization": organization, "project": project, "repository": repository,
            "branch": branch, "commit": commit, "status": scan.status, "findings": scan.findings,
            "inventory": scan.inventory, "coverage": scan.coverage, "error": ""}


def summarize(results: list[dict]) -> dict:
    summary = {"targets": len(results), "scanned": 0, "vulnerable": 0, "clean": 0, "notApplicable": 0, "errors": 0,
               "critical": 0, "high": 0, "medium": 0, "families": {family: 0 for family in FAMILIES}}
    key = {"vulnerable": "vulnerable", "clean": "clean", "not-applicable": "notApplicable", "error": "errors"}
    for result in results:
        summary[key[result["status"]]] += 1
        if result["status"] != "error":
            summary["scanned"] += 1
        for finding in result["findings"]:
            summary[finding["severity"].lower()] = summary.get(finding["severity"].lower(), 0) + 1
            family = finding.get("family", "2Shell")
            summary["families"][family] = summary["families"].get(family, 0) + 1
    return summary


def document(results: list[dict], *, scope: str) -> dict:
    # Fleet-wide finding IDs so every heading in one report is unique.
    number = 0
    for result in results:
        for finding in result["findings"]:
            number += 1
            finding["id"] = f"TS-{number:03d}"
    return {"schema": SCHEMA, "tool": TOOL, "generatedAt": now(), "scope": scope, "summary": summarize(results),
            "results": results}


def _label(result: dict) -> str:
    repo = result["repository"] or "."
    where = "/".join(part for part in (result["organization"], result["project"]) if part)
    name = f"{where}/{repo}" if where and not repo.startswith(where) else repo
    return f"{name}@{result['branch']}" if result["branch"] else name


def _risk_level(summary: dict, results: list[dict]) -> str:
    confirmed = [f for r in results for f in r["findings"] if f["confidence"] in ("CONFIRMED", "PLAUSIBLE")]
    if any(f["severity"] == "CRITICAL" for f in confirmed):
        return "CRITICAL"
    if any(f["severity"] == "HIGH" for f in confirmed):
        return "HIGH"
    if summary["vulnerable"]:
        return "LOW"
    return "CLEAN"


def markdown(doc: dict) -> str:
    summary, results = doc["summary"], doc["results"]
    findings = [(r, f) for r in results for f in r["findings"]]
    level = _risk_level(summary, results)
    out = [
        f"# *-2Shell / *-4Shell Exposure Scan: {doc['scope']}",
        f"**Date**: {doc['generatedAt'][:10]}",
        f"**Scope**: {summary['targets']} repository/branch target(s)",
        "**Reviewed by**: appsec-2shell-detector (deterministic detector `threatlint detect-2shell`)",
        "",
        "---",
        "",
        "## TIER 1 — EXECUTIVE SUMMARY",
        "",
        "### *-2Shell / *-4Shell Risk Level",
        "",
        f"**{level}**",
        "",
    ]
    if level == "CLEAN":
        out.append("No scanned target resolves a version affected by the *-2Shell (React2Shell, Next.js) or *-4Shell "
                   "(Log4Shell, Spring4Shell, Text4Shell) families.")
    else:
        crit = sum(1 for _, f in findings if f["severity"] == "CRITICAL" and f["confidence"] != "THEORETICAL")
        out.append(f"{summary['vulnerable']} of {summary['scanned']} scanned target(s) ship an affected version; "
                   f"{crit} critical remote-code-execution exposure(s) need an upgrade now "
                   f"(*-2Shell: {summary['families'].get('2Shell', 0)} finding(s), *-4Shell: {summary['families'].get('4Shell', 0)}).")
    out += [
        "",
        "### Coverage",
        "",
        "| Targets | Scanned | Vulnerable | Clean | Not applicable | Errors |",
        "|---|---|---|---|---|---|",
        f"| {summary['targets']} | {summary['scanned']} | {summary['vulnerable']} | {summary['clean']} | "
        f"{summary['notApplicable']} | {summary['errors']} |",
        "",
        "### Finding Summary",
        "",
        "| Severity | Count | CONFIRMED | PLAUSIBLE | THEORETICAL |",
        "|----------|-------|-----------|-----------|-------------|",
    ]
    for severity in ("CRITICAL", "HIGH", "MEDIUM"):
        rows = [f for _, f in findings if f["severity"] == severity]
        counts = [sum(1 for f in rows if f["confidence"] == c) for c in ("CONFIRMED", "PLAUSIBLE", "THEORETICAL")]
        out.append(f"| {severity.title()} | {len(rows)} | {counts[0]} | {counts[1]} | {counts[2]} |")
    out += ["", "### Recommended Immediate Action", ""]
    if findings:
        out.append("Upgrade every CRITICAL target to the listed fixed version, redeploy, and rotate secrets on any "
                   "internet-facing app that ran an affected version after its flaw was public (React2Shell: "
                   "2025-12-04; Log4Shell: 2021-12; Spring4Shell: 2022-03; Text4Shell: 2022-10). THEORETICAL items "
                   "still need the upgrade but are not reachable as configured.")
    else:
        out.append("Keep this scan scheduled so new repositories and branches are checked as they appear.")
    out += ["", "### Targets Needing Action", "", "| Target | Top severity | Package | Installed | Fix to |", "|---|---|---|---|---|"]
    listed = 0
    for result in results:
        if not result["findings"]:
            continue
        top = result["findings"][0]
        out.append(f"| `{_label(result)}` | {top['severity']} ({top['confidence']}) | {top['package']} | "
                   f"{top['version']} | {top['fixedIn']} |")
        listed += 1
    if not listed:
        out.append("| — | — | — | — | — |")

    out += ["", "---", "", "## TIER 2 — TECHNICAL SCAN RESULTS", "", "### Scan Coverage", "",
            "- Method: resolved versions from npm, Yarn, pnpm and Bun lockfiles and gradle.lockfile; vendored jars; "
            "declared versions from package.json, pom.xml, Gradle builds and version catalogs; App Router layout "
            "(Next.js) and WAR packaging (Spring) for exposure.",
            "- Catalog: " + "; ".join(f"*-{fam}: " + ", ".join(dict.fromkeys(c for a in ADVISORIES if a.family == fam
                                                                 for c in a.cves)) for fam in FAMILIES) + ".",
            "- Not covered: running containers, copies shaded inside other artifacts, and live exploitation "
            "testing (never performed)."]
    errors = [r for r in results if r["status"] == "error"]
    for result in errors:
        out.append(f"- Error: `{_label(result)}` — {result['error']}")
    for result in results:
        for note in result.get("coverage", []):
            out.append(f"- `{_label(result)}`: {note}")
    out += ["", "### Findings", ""]
    if not findings:
        out.append("No findings.")
    for result, f in findings:
        location = f"`{f['file']}:{f['line']}`"
        out += [
            "---",
            "",
            f"#### [{f['id']}] — {f['title']} ({f['package']} {f['version']})",
            "",
            f"**Severity**: {f['severity']}",
            f"**Confidence**: {f['confidence']}",
            "",
            "| Field | Detail |",
            "|-------|--------|",
            f"| Target | `{_label(result)}`{' @ ' + result['commit'][:12] if result['commit'] else ''} |",
            f"| Location | {location} |",
            f"| Package | {f['package']} {f['version']} |",
            f"| Fixed in | {f['fixedIn']} |",
            f"| CVE | {', '.join(f['cves'])} |",
            f"| CVSS | {f['cvss']} |",
            f"| CWE | {f['cwe'] or '—'} |",
            f"| Exposure | {f['exposure']} |",
            f"| Evidence | {f['evidence']} |",
            "| Effort | Small: dependency upgrade, rebuild, redeploy |",
            "",
            f"**Impact**: {f['impact']}",
            "",
            f"**Remediation**: {f['remediation']}",
            "",
            "**Acceptance check**: the lockfile resolves the fixed version (or later on the same line) and a fresh "
            "`threatlint detect-2shell scan` reports no finding for this target. NOT RUN",
            "",
            "**Sources**: " + ", ".join(f["sources"]),
            "",
        ]
    out += ["### Residual Risk", "",
            "Version evidence shows exposure, not exploitation. Check web and WAF logs for Server Function requests, "
            "${jndi: lookups and class.module data-binding payloads from before the upgrade, and treat secrets "
            "reachable by an exposed server as compromised until rotated."]
    return "\n".join(out) + "\n"
