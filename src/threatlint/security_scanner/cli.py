"""JSON CLI shared by Workbench and trusted CI workflows."""

from __future__ import annotations

import json
import sys
import signal

from .fixes import apply_fix, propose_fix
from .scan import scan_repository
from .snapshot import ScannerError, ScannerCancelled


def add_security_scanner_parser(sub):
    parser = sub.add_parser("security-scanner", help="Scan SAST, dependency hygiene, secrets, and infrastructure")
    parser.add_argument("action", choices=("scan", "propose", "apply"))
    parser.add_argument("--repo", default=".")
    parser.add_argument("--engine", action="append", choices=("semgrep", "trivy"), default=[])
    parser.add_argument("--confirm", action="store_true", help="Apply a reviewed, snapshot-bound plan from stdin")
    parser.set_defaults(integration_handler=cmd_security_scanner)


def cmd_security_scanner(args):
    def stop(_signum, _frame):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise ScannerCancelled("Security scanner cancelled")
    previous_signal = signal.signal(signal.SIGTERM, stop)
    try:
        if args.action == "scan":
            result = scan_repository(args.repo, engines=args.engine)
        else:
            payload = json.loads(sys.stdin.read(10_000_001))
            if args.action == "propose":
                result = propose_fix(payload["scan"], payload["findingId"])
            else:
                result = apply_fix(payload["plan"], confirm=args.confirm, policy=payload.get("policy"),
                                   scan=lambda repo: scan_repository(repo, engines=args.engine))
        print(json.dumps(result))
        return 0
    except (ScannerError, ScannerCancelled, ValueError, KeyError, TypeError, OSError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous_signal)
