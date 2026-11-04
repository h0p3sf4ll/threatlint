"""Render the runtime red-team assessment as Markdown.

Observations are reported as candidate findings for a human or the FP reviewer to confirm, never as proven exploits.
The report states the isolation the assessment ran under, what the ruleset covered, what this run taught the ruleset,
and the AVIT drafts (and whether posting was stubbed).
"""

from __future__ import annotations

import datetime

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _table(rows: list[list[str]], header: list[str]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    lines += ["| " + " | ".join(cell.replace("|", r"\|") for cell in row) + " |" for row in rows]
    return lines


def render(state: dict, findings: list[dict], ruleset, drafts: list[dict], learned: dict) -> str:
    target, plan = state.get("target", {}), state.get("plan", {})
    findings = sorted(findings, key=lambda item: _SEVERITY_ORDER.get(item["severity"], 5))
    counts = {level: sum(1 for item in findings if item["severity"] == level) for level in _SEVERITY_ORDER}
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tests = state.get("tests", {})
    lines = [
        f"# Runtime Red Team Assessment: {target.get('name', 'application')}",
        "",
        f"- **Repository**: {target.get('web_url', '(local)')} · branch `{target.get('branch', '')}`",
        f"- **Stack**: {plan.get('stack', 'unknown')} · services: {', '.join(service.get('name', '') for service in plan.get('services', [])) or 'app only'}",
        f"- **Run**: `{state.get('run_id', '')}` · {now} · provider `{state.get('provider', 'docker')}`",
        f"- **Endpoints assessed**: {len(state.get('endpoints', []))} · **probe requests**: {state.get('probe_count', 0)}",
        f"- **Repository tests**: {tests.get('status', 'not run')}",
        "",
        "> Authorized, non-destructive assessment of an application built from its own repository in an isolated,"
        " no-egress ephemeral environment. Requests were bounded and sent only to the sandbox. Each observation below"
        " is a candidate finding for confirmation, not a proven exploit.",
        "",
        "## Tier 1 — Executive summary",
        "",
        f"Candidate findings: **{len(findings)}** "
        f"(Critical {counts['CRITICAL']}, High {counts['HIGH']}, Medium {counts['MEDIUM']}, Low {counts['LOW']}, Info {counts['INFO']}).",
        "",
    ]
    if findings:
        lines += _table([[item["severity"], item["title"], f"{item['method']} {item['path']}", item["cwe"]] for item in findings],
                        ["Severity", "Finding", "Endpoint", "CWE"])
    else:
        lines.append("No candidate findings. The deployed endpoints did not exhibit the behaviours the applied rules test for.")
    lines += ["", f"ServiceNow AVIT drafts: **{len(drafts)}** "
              + ("(posting is stubbed; drafts are below and in `avits.json`)." if drafts and not drafts[0].get("posted")
                 else "(posted)." if drafts else "(none)."), ""]

    lines += ["## Tier 2 — Candidate findings", ""]
    if not findings:
        lines.append("None.")
    for index, item in enumerate(findings, start=1):
        lines += [f"### {index}. {item['title']} — {item['severity']}", "",
                  f"- **Endpoint**: `{item['method']} {item['path']}`" + (f" · parameter `{item['parameter']}`" if item.get("parameter") else ""),
                  f"- **Category**: {item['category']} · **CWE**: {item['cwe']} · **Rule**: `{item['rule_id']}`",
                  "- **Observed**:"]
        lines += [f"  - {signal}" for signal in item["signals"][:6]]
        lines += ["- **Confirm**: reproduce the request against an authorized deployment and confirm the behaviour before"
                  " acting. This is a runtime observation; the fix belongs in the code path that serves this endpoint.", ""]

    lines += ["## Deployment and isolation", "",
              f"- Built and deployed with the `{state.get('provider', 'docker')}` provider on an internal network with no"
              " default route; egress was possible only while building images.",
              f"- Backing services: {', '.join(service.get('name', '') for service in plan.get('services', []) if service.get('role') != 'app') or 'none'}"
              f" · credentials: {state.get('credential_mode', 'synthetic')}.",
              f"- Teardown: {state.get('teardown', {}).get('containers', '?')} container(s), "
              f"{state.get('teardown', {}).get('images', '?')} image(s) removed.", ""]

    lines += ["## Ruleset coverage and learning", "",
              "Threatlint provided the ruleset. The table shows what ran this assessment and the cumulative learned yield.", ""]
    lines += _table([[row["id"], row["kind"], row["severity"], str(row["runs"]), str(row["hits"]), f"{row['yield']:.0%}", row["source"]]
                     for row in ruleset.summary()], ["Rule", "Kind", "Severity", "Runs", "Hits", "Yield", "Source"])
    lines += ["", f"- Rules exercised this run: **{learned.get('rules_run', 0)}**; confirmed: **{learned.get('confirmed', 0)}**.",
              f"- Endpoint shapes learned as high-yield: {', '.join(learned.get('affinities', [])) or 'none yet'}.",
              "- The learned store ordered higher-yield rules and endpoint shapes first; it carries forward to the next"
              " assessment so coverage improves with each run.", ""]

    if drafts:
        lines += ["## ServiceNow AVIT drafts", ""]
        for draft in drafts:
            lines += [f"- **{draft['short_description']}**",
                      f"  - severity {draft['severity']} · {draft['category']} · {draft['cwe']} · rule `{draft['rule_id']}`",
                      f"  - {draft['note']}", ""]
    return "\n".join(lines) + "\n"
