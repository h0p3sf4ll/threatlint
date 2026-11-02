"""Argument-parser construction for the DAST workflow."""

from __future__ import annotations

import argparse
import os

from threatlint import runtime_env as rt
from threatlint import servicenow as sn

STEPS = ("provision", "deploy", "test", "probe", "teardown", "review", "resolve")


def configure_parser(actions, description: str | None = None) -> None:
    dast = actions.add_parser("dast", help="Validate an Invicti (dynamic scan) AVIT in an ephemeral, isolated Docker deployment of the app",
                              description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    dast.add_argument("number", metavar="AVIT", nargs="?", help="AVIT number (read from ServiceNow unless --avit-file is given)")
    dast.add_argument("--avit-file", metavar="PATH", help="AVIT record as JSON (Table API row) or Markdown, instead of ServiceNow")
    dast.add_argument("--repo", help="Repository to deploy: HTTPS Git URL or local repository path (the finding names a URL, not a repo)")
    dast.add_argument("--branch", help="Branch to deploy")
    dast.add_argument("--work", metavar="DIR", help="Run directory for state, evidence and the report (default: a new temporary directory)")
    dast.add_argument("--step", choices=STEPS, help="Run one step against --work (default: provision, deploy, test, probe, teardown, review)")
    dast.add_argument("--env-provider", default="docker", choices=sorted(rt.PROVIDERS), help="Environment provider")
    dast.add_argument("--service", help="Compose service that is the application")
    dast.add_argument("--port", type=int, help="Application port inside the container")
    dast.add_argument("--health-path", help="Health check path (default: /health, /healthz, then /)")
    dast.add_argument("--test-command", help="Test command run in the app image against APP_URL (default: detected)")
    dast.add_argument("--start-command", help="Command that starts the app (default: detected)")
    dast.add_argument("--keep-env", action="store_true", help="Leave the environment running after the probe (teardown later with --step teardown)")
    dast.add_argument("--review-provider", choices=["lmstudio", "openai", "claude"], help="Run the FP review with this model provider (default: hand off to Claude Code)")
    dast.add_argument("--model", help="Review model ID")
    dast.add_argument("--base-url", default="http://localhost:1234/v1", help="LM Studio API base URL")
    dast.add_argument("--api-key", help="Provider API key (or OPENAI_API_KEY / ANTHROPIC_API_KEY)")
    dast.add_argument("--resolve", action="store_true", help="After the review, resolve the AVIT in ServiceNow (attach; close FP / note TP)")
    dast.add_argument("--report", help="FP review report for --step resolve (default: WORK/fp_review.md)")
    dast.add_argument("--docx", help="Word report to attach (default: converted from the report)")
    dast.add_argument("--yes", action="store_true", help="Apply ServiceNow changes without prompting")
    dast.add_argument("--snow-instance", default=os.environ.get(sn.INSTANCE_ENV, "") or sn.saved_config().get("instance", ""), help="ServiceNow instance URL")
    dast.add_argument("--aws-profile", help="AWS CLI profile with access to the ServiceNow parameters")
