"""`threatlint redteam …`: run a runtime red-team assessment, or inspect the ruleset.

  run    --repo URL --branch B [--routes FILE] [--credentials CONFIG] [--rules PATH]
         clone, build in an isolated ephemeral environment, probe with the ruleset, learn, draft AVITs, tear down
  rules  list [--rules PATH]
         show the built-in and learned ruleset with each rule's cumulative yield
"""

from __future__ import annotations

import argparse

from threatlint import runtime_env as rt
from threatlint.avit_resolve import ResolveError


def add_redteam_parser(sub) -> None:
    parser = sub.add_parser("redteam", help="Runtime red-team assessment of an app built from its repo in an isolated ephemeral environment",
                            formatter_class=argparse.RawDescriptionHelpFormatter)
    actions = parser.add_subparsers(dest="redteam_command", required=True)

    run = actions.add_parser("run", help="Build the app from its repository and assess the running application")
    run.add_argument("--repo", required=True, help="Repository to deploy: HTTPS Git URL or local repository path")
    run.add_argument("--branch", required=True, help="Branch to deploy")
    run.add_argument("--routes", metavar="FILE", help="Optional endpoints to assess (JSON list or `METHOD /path` lines) in addition to discovery")
    run.add_argument("--credentials", metavar="CONFIG", help="Opt in to real credentials: a JSON config naming a credential store and references (default: synthetic)")
    run.add_argument("--rules", metavar="PATH", help="Learned ruleset store (default: ~/.threatlint/redteam/ruleset.json)")
    run.add_argument("--work", metavar="DIR", help="Run directory for state, report and AVIT drafts (default: a new temporary directory)")
    run.add_argument("--env-provider", default="docker", choices=sorted(rt.PROVIDERS), help="Environment provider")
    run.add_argument("--service", help="Compose service that is the application")
    run.add_argument("--port", type=int, help="Application port inside the container")
    run.add_argument("--health-path", help="Health check path (default: /health, /healthz, then /)")
    run.add_argument("--start-command", help="Command that starts the app (default: detected)")
    run.add_argument("--keep-checkout", action="store_true", help="Keep the checkout after the run (default: deleted)")
    run.add_argument("--aws-profile", help="AWS CLI profile for --credentials references in Parameter Store")

    rules = actions.add_parser("rules", help="Inspect the ruleset")
    rules_actions = rules.add_subparsers(dest="rules_command", required=True)
    listing = rules_actions.add_parser("list", help="List the built-in and learned rules with their cumulative yield")
    listing.add_argument("--rules", metavar="PATH", help="Learned ruleset store (default: ~/.threatlint/redteam/ruleset.json)")
    listing.add_argument("--json", action="store_true", help="Machine-readable output")


def cmd_redteam(args) -> int:
    if args.redteam_command == "run":
        from threatlint.redteam import assessment  # noqa: PLC0415
        try:
            return assessment.run(args)
        except ResolveError as exc:
            print(f"ERROR: {exc}")
            return 1
    if args.redteam_command == "rules" and args.rules_command == "list":
        from threatlint.redteam.rules import load_ruleset  # noqa: PLC0415
        ruleset = load_ruleset(getattr(args, "rules", None))
        if getattr(args, "json", False):
            import json  # noqa: PLC0415
            print(json.dumps(ruleset.summary(), indent=2))
            return 0
        print(f"{'RULE':<16} {'KIND':<10} {'SEV':<9} {'RUNS':>5} {'HITS':>5} {'YIELD':>6}  SOURCE")
        for row in ruleset.summary():
            print(f"{row['id']:<16} {row['kind']:<10} {row['severity']:<9} {row['runs']:>5} {row['hits']:>5} {row['yield']:>6.0%}  {row['source']}")
        return 0
    return 1
