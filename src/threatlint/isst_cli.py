"""ISST command arguments and terminal dispatch.

  threatlint isst avits <ISST>              list the AVIT numbers associated with the ISST (same SCM, repository, branch)
  threatlint isst summarize <ISST> [--yes]  attach each true-positive AVIT's report to the ISST and comment on it

Threatlint never closes the ISST: true positives need remediation, so closure stays with the owner. False-positive
reports stay on their own AVIT, which is closed and whose Semgrep rule is tuned by the AVIT review itself.
"""

from __future__ import annotations

import json
import sys

from threatlint import servicenow as sn
from threatlint.avit_report import ResolveError

_ISST_HELP = "ServiceNow ISST number (ISST followed by 7 to 15 digits, e.g. ISST0012345)"


def add_isst_parser(sub) -> None:
    p = sub.add_parser("isst", help="Review the AVITs associated with a ServiceNow ISST and summarize the outcome on it")
    actions = p.add_subparsers(dest="isst_command", required=True)
    for name, text in (("avits", "List the AVIT numbers associated with the ISST"),
                       ("summarize", "Attach each true-positive AVIT report to the ISST and comment (does not close the ISST)")):
        action = actions.add_parser(name, help=text)
        action.add_argument("number", metavar="ISST", help=_ISST_HELP)
        sn.add_avit_arguments(action)
        if name == "summarize":
            action.add_argument("--yes", action="store_true", help="Apply without prompting")


def cmd_isst(args) -> int:
    from threatlint import isst  # noqa: PLC0415
    from threatlint.avit_resolve import _session  # noqa: PLC0415
    try:
        number = str(args.number or "").strip().upper()
        instance, token = _session(args)
        if args.isst_command == "avits":
            record, avits = isst.discover(instance, token, number)
            for avit in avits:
                print(avit)
            print(json.dumps({"isst": record["number"], "avits": avits}))
            return 0 if avits else 1
        isst.summarize_number(instance, token, number, args.yes)
        return 0
    except (ResolveError, sn.ServiceNowError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
