"""Catalog-task command arguments and terminal dispatch."""

from __future__ import annotations

import json
import sys

from threatlint import servicenow as sn
from threatlint.avit_report import ResolveError


def add_sctask_parser(sub) -> None:
    p = sub.add_parser("sctask", help="Review the AVITs named in a ServiceNow catalog task (SCTASK) and close it")
    actions = p.add_subparsers(dest="sctask_command", required=True)
    for name, text in (("avits", "List the AVIT numbers in the task's description"), ("close", "Attach each AVIT's report, comment, and close the task")):
        action = actions.add_parser(name, help=text)
        action.add_argument("number", metavar="SCTASK")
        sn.add_avit_arguments(action)
        if name == "close":
            action.add_argument("--yes", action="store_true", help="Apply without prompting")
            action.add_argument("--leave-open", action="store_true", help="Attach the reports and comment that the task can be closed, but do not close it")


def cmd_sctask(args, *, session, parse_numbers, fetch, avits_in, close) -> int:
    try:
        numbers = parse_numbers(args.number)
        if len(numbers) != 1:
            raise ResolveError(f"Not an SCTASK number: {args.number} (expected e.g. SCTASK14120565)")
        instance, token = session(args)
        if args.sctask_command == "avits":
            task = fetch(instance, token, numbers[0])
            avits = avits_in(task.get("description", "") + "\n" + task.get("short_description", ""))
            for avit in avits:
                print(avit)
            print(json.dumps({"sctask": numbers[0], "state": task.get("state", ""), "avits": avits}))
            return 0 if avits else 1
        close(instance, token, numbers[0], args.yes, leave_open=args.leave_open)
        return 0
    except (ResolveError, sn.ServiceNowError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
