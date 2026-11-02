"""Guard CLI and post-tool hook adapters."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .models import SEVERITIES, _rank
from .rules import RULES
from .scanning import scan_paths
from .output import failing, to_json, to_sarif, to_text


HOOK_BLOCKING_SEVERITY = "medium"


def staged_files(cwd: str | None = None) -> list[str]:
    result = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
                            cwd=cwd, capture_output=True, text=True, check=True)
    return [name for name in result.stdout.split("\0") if name]


def run_hook(stdin_text: str) -> int:
    """Claude Code PostToolUse hook: exit 2 with findings on stderr so the model fixes them."""
    try:
        payload = json.loads(stdin_text or "{}")
    except json.JSONDecodeError:
        return 0
    tool_input = payload.get("tool_input") or {}
    paths = [p for p in [tool_input.get("file_path"), tool_input.get("notebook_path")] if isinstance(p, str)]
    findings = scan_paths(paths) if paths else []
    blocking = [f for f in findings if _rank(f.severity) >= _rank(HOOK_BLOCKING_SEVERITY)]
    if not blocking:
        return 0
    sys.stderr.write("threatlint guard found insecure patterns in the code you just wrote. "
                     "Rewrite them using the secure alternative (or add a justified "
                     "`threatlint-ignore: RULE-ID reason` comment if it is a verified false positive):\n"
                     + to_text(blocking) + "\n")
    return 2


def cmd_guard(args) -> int:
    if getattr(args, "hook", False):
        return run_hook(sys.stdin.read())
    if args.list_rules:
        for rule in RULES:
            print(f"{rule.id:30} {rule.severity:8} {rule.cwe:8} {rule.message}")
        return 0
    paths = list(args.paths)
    if args.staged:
        try:
            paths = staged_files()
        except (OSError, subprocess.CalledProcessError):
            print("threatlint guard: --staged requires a git repository", file=sys.stderr)
            return 2
    findings = scan_paths(paths or ["."])
    rendered = {"text": to_text, "json": to_json, "sarif": to_sarif}[args.format](findings)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 1 if failing(findings, args.fail_on) else 0


def add_guard_parser(sub) -> None:
    p = sub.add_parser("guard", help="Fast local secure-coding checks for IDE, AI-assistant hooks, and pre-commit")
    p.add_argument("paths", nargs="*", help="Files or directories (default: current directory)")
    p.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("--fail-on", choices=list(SEVERITIES) + ["none"], default="high",
                   help="Exit 1 when any finding is at or above this severity (default: high)")
    p.add_argument("--staged", action="store_true", help="Scan only files staged in git")
    p.add_argument("--hook", action="store_true", help="Claude Code PostToolUse hook mode (reads hook JSON on stdin)")
    p.add_argument("--list-rules", action="store_true", help="List rules and exit")
    p.add_argument("-o", "--output", metavar="FILE", help="Write output to FILE")
