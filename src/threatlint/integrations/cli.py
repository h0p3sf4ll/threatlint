"""CLI wiring for integrations.

  threatlint <command> fetch|checkout|resolve|note|login   one command per reviewable integration
                                                         (built in: `dojo` findings management, `sonar` scanning)
  threatlint integrations list [--kind KIND] [--json]    every registered integration, grouped by type

Commands come from the registry, so an installed community integration appears here without code changes.
"""

from __future__ import annotations

import json
import sys

from threatlint import integrations as registry
from threatlint.integrations import verbs

_HELP = {
    "findings-management": "{label} (findings management): fetch findings for FP review, check out, resolve, note",
    "scanning": "{label} (scanning tool): fetch issues for FP review, check out, resolve, note",
}


def add_parsers(sub) -> None:
    """Add every reviewable integration's command (skipping names already taken) and `threatlint integrations`."""
    for command, integration in registry.reviewable().items():
        if command in sub.choices:
            print(f"  ! threatlint plugin skipped: command {command!r} is already a Threatlint command", file=sys.stderr)
            continue
        verbs.add_parsers(sub, integration, help_text=_HELP[integration.kind].format(label=integration.label))
    parser = sub.add_parser("integrations", help="List integrations by type (findings management, scanning, secret validation)")
    parser.set_defaults(integration_handler=cmd_integrations)
    actions = parser.add_subparsers(dest="integrations_command", required=True)
    listing = actions.add_parser("list", help="Show built-in and installed plugin integrations")
    listing.add_argument("--kind", choices=sorted(registry.KINDS), help="Only this integration type")
    listing.add_argument("--json", action="store_true", help="Machine-readable output")


def cmd_integrations(args) -> int:
    rows = [integration.describe_integration() | {"command": getattr(integration, "command", "")}
            for integration in registry.integrations(args.kind)]
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    for kind, title in registry.KINDS.items():
        if args.kind and kind != args.kind:
            continue
        print(f"\n{title}")
        members = [row for row in rows if row["kind"] == kind]
        if not members:
            print("  (none installed)")
        for row in members:
            command = f"threatlint {row['command']}" if row["command"] else ""
            print(f"  {row['label']:<22} {command:<18} {row['source']:<12} {row['summary']}")
    if registry.plugins_disabled():
        print("\nPlugins are disabled (THREATLINT_DISABLE_PLUGINS); only built-ins are listed.")
    return 0
