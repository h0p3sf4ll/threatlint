"""`threatlint assure …`: run the gated assurance pipeline over a repository.

  run  --repo URL --branch B
       pull the repo, run SAST (Semgrep), then build + dynamically scan a web/API app (Invicti) or hand a mobile
       app to NowSecure. A CRITICAL or HIGH finding in any stage disqualifies the run, but every scan still runs.
"""

from __future__ import annotations

import argparse

from threatlint.avit_resolve import ResolveError


def add_assure_parser(sub) -> None:
    parser = sub.add_parser("assure", help="Gated assurance run: SAST then DAST/MAST with fail-fast disqualification",
                            formatter_class=argparse.RawDescriptionHelpFormatter)
    actions = parser.add_subparsers(dest="assure_command", required=True)

    run = actions.add_parser("run", help="Pull the repo, run the static and dynamic gates, and report the verdict")
    run.add_argument("--repo", required=True, help="Repository to assess: HTTPS Git URL or local repository path")
    run.add_argument("--branch", required=True, help="Branch to assess")
    run.add_argument("--semgrep-config", default="auto", help="Semgrep config for the SAST stage (default: auto)")
    run.add_argument("--work", metavar="DIR", help="Run directory for state and report (default: a new directory in the repo store)")
    run.add_argument("--env-provider", default="docker", help="Ephemeral environment provider for the web/API dynamic stage")
    run.add_argument("--keep-checkout", action="store_true", help="Keep the checkout after the run (default: deleted)")


def cmd_assure(args) -> int:
    if args.assure_command == "run":
        from threatlint.assurance import pipeline  # noqa: PLC0415
        try:
            return pipeline.run(args)
        except ResolveError as exc:
            print(f"ERROR: {exc}")
            return 1
    return 1
