"""Argument parsing and presentation for orchestrator commands."""

from __future__ import annotations

import argparse
import json

from .models import AVITStatus
from .orchestrator import AVITOrchestrator


def add_orchestrator_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the existing orchestrator command surface."""
    orch = subparsers.add_parser("orchestrator", help="AVIT orchestrator: manage queue and batch processing")
    actions = orch.add_subparsers(dest="orch_command", help="Orchestrator command")
    queue = actions.add_parser("queue", help="Manage the AVIT queue")
    queue_actions = queue.add_subparsers(dest="queue_cmd", help="Queue command")
    add_queue = queue_actions.add_parser("add", help="Add AVITs to the queue")
    add_queue.add_argument("avits", nargs="+", metavar="AVIT", help="AVIT numbers to add")
    list_queue = queue_actions.add_parser("list", help="List AVITs in the queue")
    list_queue.add_argument("--status", choices=[status.value for status in AVITStatus], help="Filter by status")
    actions.add_parser("stats", help="Show orchestrator statistics")
    actions.add_parser("clear", help="Clear pending/in-progress/skipped AVITs; keep completed/failed")
    canary = actions.add_parser("canary", help="Run a canary test with 10 items")
    canary.add_argument("--size", type=int, default=10, help="Number of items for canary")
    actions.add_parser("pause", help="Pause queue processing")
    actions.add_parser("resume", help="Resume queue processing")


def cmd_orchestrator(args: argparse.Namespace) -> int:
    """Handle orchestrator commands."""
    orch = AVITOrchestrator()
    if args.orch_command == "queue":
        if args.queue_cmd == "add":
            orch.add_avits(args.avits)
            print(f"Added {len(args.avits)} AVIT(s)")
            return 0
        if args.queue_cmd == "list":
            status = AVITStatus(args.status) if args.status else None
            print(json.dumps([item.to_dict() for item in orch.list_queue(status)], indent=2))
            return 0
    elif args.orch_command == "stats":
        print(json.dumps(orch.get_stats(), indent=2))
        return 0
    elif args.orch_command == "clear":
        print(f"Cleared {orch.clear_queue()} item(s)")
        return 0
    elif args.orch_command == "canary":
        print("Canary mode: not implemented without handler")
        return 1
    elif args.orch_command == "pause":
        orch.pause()
        print("Orchestrator paused")
        return 0
    elif args.orch_command == "resume":
        orch.resume()
        print("Orchestrator resumed")
        return 0
    print("Unknown orchestrator command")
    return 1
