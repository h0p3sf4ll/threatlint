"""`threatlint detect-2shell` — find React2Shell-family exposure in one repository or a whole fleet."""
from __future__ import annotations

import json
import os
import sys

from . import metrics
from .fleet import FleetError, run_fleet, stderr_progress
from .report import document, markdown, target_result
from .scanner import SEVERITY_RANK, scan_path

EPILOG = """examples:
  threatlint detect-2shell scan --path .
  threatlint detect-2shell scan --path . --format json --fail-on CRITICAL
  threatlint detect-2shell fleet --all
  threatlint detect-2shell fleet --all --branches all --format markdown --output 2shell.md
  threatlint detect-2shell fleet --repo "my-org/*" --repo "Payments/checkout-web" --branches "main,release/*"
  threatlint detect-2shell fleet --targets-file targets.json --progress

metrics:
  """ + metrics.NOTICE + "\n"


def add_detect_2shell_parser(sub) -> None:
    import argparse  # noqa: PLC0415

    parser = sub.add_parser(
        "detect-2shell", help="Find React2Shell (CVE-2025-55182 / CVE-2025-66478) exposure in one repo or across every connected SCM",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    actions = parser.add_subparsers(dest="action", required=True)

    scan = actions.add_parser("scan", help="Scan a local checkout")
    scan.add_argument("--path", default=".", help="Repository directory (default: current directory)")
    _output_args(scan)

    fleet = actions.add_parser("fleet", help="Scan repositories and branches through GitHub / Azure DevOps APIs (no clone)")
    which = fleet.add_mutually_exclusive_group(required=True)
    which.add_argument("--targets-file", metavar="FILE", help="JSON selection (connections, repositories, branches)")
    which.add_argument("--all", action="store_true", help="Every repository every available credential can read")
    which.add_argument("--repo", action="append", metavar="PATTERN", help="owner/name or project/repo; wildcards allowed; repeatable")
    fleet.add_argument("--branches", default="default", help='"default" (default), "all", or comma-separated names/patterns')
    fleet.add_argument("--connection", default="*", help="Limit --all/--repo to one credential id or provider (github, azure-devops)")
    fleet.add_argument("--max-repositories", type=int, default=0)
    fleet.add_argument("--workers", type=int, default=4, help="Parallel targets (1-16)")
    fleet.add_argument("--progress", action="store_true", help="Write NDJSON progress events to stderr")
    _output_args(fleet)
    parser.set_defaults(integration_handler=cmd_detect_2shell)


def _output_args(parser) -> None:
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", metavar="FILE", help="Write the report here instead of stdout")
    parser.add_argument("--fail-on", type=str.upper, choices=tuple(SEVERITY_RANK), metavar="SEVERITY",
                        help="Exit 3 when a CONFIRMED/PLAUSIBLE finding at or above this severity exists")


def _targets_from_args(args) -> dict:
    if args.targets_file:
        with open(args.targets_file, encoding="utf-8") as handle:
            return json.load(handle)
    branches = args.branches.strip()
    if branches not in ("default", "all"):
        branches = [b.strip() for b in branches.split(",") if b.strip()]
    data = {"connections": [{"connection": args.connection, "repositories": "all" if args.all else args.repo,
                             "branches": branches}]}
    if args.max_repositories:
        data["maxRepositories"] = args.max_repositories
    return data


def cmd_detect_2shell(args) -> int:
    try:
        if args.action == "scan":
            path = os.path.abspath(args.path)
            doc = document([target_result(scan_path(path), repository=os.path.basename(path))], scope=os.path.basename(path))
        else:
            doc = run_fleet(_targets_from_args(args), workers=args.workers,
                            progress=stderr_progress if args.progress else None)
    except (FleetError, ValueError, OSError) as exc:
        print(json.dumps({"error": str(exc)}) if args.format == "json" else f"detect-2shell: {exc}", file=sys.stderr)
        return 1
    metrics.record(doc, mode=args.action)
    text = json.dumps(doc, indent=2) if args.format == "json" else markdown(doc)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
        summary = doc["summary"]
        print(f"detect-2shell: {summary['vulnerable']} vulnerable / {summary['scanned']} scanned "
              f"({summary['errors']} errors) -> {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f["severity"]] >= threshold and f["confidence"] != "THEORETICAL"
               for r in doc["results"] for f in r["findings"]):
            return 3
    return 0
