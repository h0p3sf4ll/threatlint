"""threatlint CLI — install AppSec agents into Claude Code / project directories."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from threatlint import __version__

# ── Package data roots ────────────────────────────────────────────────────────

_DATA = Path(__file__).parent / "data"
_AGENTS_SRC = _DATA / "agents"
_COMMANDS_SRC = _DATA / "commands"
_SCRIPTS_SRC = _DATA / "scripts"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _green(s: str) -> str:
    return f"\033[32m{s}\033[0m" if sys.stdout.isatty() else s

def _yellow(s: str) -> str:
    return f"\033[33m{s}\033[0m" if sys.stdout.isatty() else s

def _red(s: str) -> str:
    return f"\033[31m{s}\033[0m" if sys.stdout.isatty() else s

def _bold(s: str) -> str:
    return f"\033[1m{s}\033[0m" if sys.stdout.isatty() else s


def _copy_tree(src: Path, dst: Path, label: str, verbose: bool) -> int:
    """Copy all files from src into dst, creating dst if needed. Returns count."""
    dst.mkdir(parents=True, exist_ok=True)
    count = 0
    for f in sorted(src.iterdir()):
        if f.is_file():
            target = dst / f.name
            existed = target.exists()
            shutil.copy2(f, target)
            count += 1
            if verbose:
                marker = _yellow("updated") if existed else _green("added  ")
                print(f"  {marker}  {label}/{f.name}")
    return count


def _confirm(prompt: str) -> bool:
    try:
        ans = input(f"{prompt} [y/N] ").strip().lower()
        return ans in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        print()
        return False


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_install(args: argparse.Namespace) -> int:
    """Install agents, commands, and scripts into a .claude directory."""

    if args.local:
        base = Path(args.directory or ".").resolve() / ".claude"
        location_label = f".claude/ (local — {base.parent})"
    else:
        base = Path.home() / ".claude"
        location_label = f"~/.claude/ (global)"

    agents_dst  = base / "agents"
    commands_dst = base / "commands"
    scripts_dst  = base / "scripts"

    print(_bold("\nthreatlint install"))
    print(f"  Destination : {location_label}")
    print(f"  Agents      : {len(list(_AGENTS_SRC.iterdir()))} files")
    print(f"  Commands    : {len(list(_COMMANDS_SRC.iterdir()))} files")
    print(f"  Scripts     : {len(list(_SCRIPTS_SRC.iterdir()))} files")
    print()

    if not args.yes and not _confirm("Proceed?"):
        print("Aborted.")
        return 1

    total = 0
    total += _copy_tree(_AGENTS_SRC,  agents_dst,  ".claude/agents",  verbose=not args.quiet)
    total += _copy_tree(_COMMANDS_SRC, commands_dst, ".claude/commands", verbose=not args.quiet)
    total += _copy_tree(_SCRIPTS_SRC,  scripts_dst,  ".claude/scripts",  verbose=not args.quiet)

    print()
    print(_green(f"✓ {total} files installed to {base}"))

    if not args.quiet:
        print()
        if args.local:
            print("  Restart Claude Code in this repository to pick up the agents.")
        else:
            print("  Restart Claude Code (or open a new session) to pick up the agents.")
            print()
            print("  Quick-start:")
            print("    /threat-model          — full two-tier threat model")
            print("    /security-review       — security code review of the current diff")
            print("    /secrets-scan          — scan for hardcoded credentials")
            print("    /dependency-audit      — supply-chain security audit")
    return 0


def cmd_list(_args: argparse.Namespace) -> int:
    """List all bundled agents and commands."""
    print(_bold("\nAgents"))
    for f in sorted(_AGENTS_SRC.iterdir()):
        print(f"  {f.stem}")

    print(_bold("\nSlash commands"))
    for f in sorted(_COMMANDS_SRC.iterdir()):
        print(f"  /{f.stem}")

    print(_bold("\nScripts"))
    for f in sorted(_SCRIPTS_SRC.iterdir()):
        print(f"  {f.name}")
    print()
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    """Remove installed agents, commands, and scripts."""
    if args.local:
        base = Path(args.directory or ".").resolve() / ".claude"
    else:
        base = Path.home() / ".claude"

    targets = [
        base / "agents",
        base / "commands",
        base / "scripts" / "md_to_docx.py",
    ]

    print(_bold("\nthreatlint uninstall"))
    print(f"  Removing from: {base}")

    if not args.yes and not _confirm("Proceed?"):
        print("Aborted.")
        return 1

    for t in targets:
        if t.exists():
            if t.is_dir():
                # Only remove files we own — leave other files untouched
                owned = set(f.name for f in (_AGENTS_SRC if t.name == "agents" else _COMMANDS_SRC).iterdir())
                removed = 0
                for f in list(t.iterdir()):
                    if f.name in owned:
                        f.unlink()
                        removed += 1
                        if not args.quiet:
                            print(f"  {_red('removed')}  {t.name}/{f.name}")
                if removed and not list(t.iterdir()):
                    t.rmdir()
            else:
                t.unlink()
                if not args.quiet:
                    print(f"  {_red('removed')}  scripts/md_to_docx.py")

    print()
    print(_green("✓ Uninstall complete"))
    return 0


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="threatlint",
        description="Manage threatlint AppSec agents for Claude Code",
    )
    parser.add_argument("--version", action="version", version=f"threatlint {__version__}")

    sub = parser.add_subparsers(dest="command")

    # install
    p_install = sub.add_parser("install", help="Install agents and commands into .claude/")
    p_install.add_argument("--local", action="store_true",
        help="Install into .claude/ in the current directory instead of ~/.claude/")
    p_install.add_argument("--directory", metavar="DIR",
        help="Target repo directory when using --local (default: current directory)")
    p_install.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    p_install.add_argument("-q", "--quiet", action="store_true", help="Suppress file-by-file output")

    # list
    sub.add_parser("list", help="List bundled agents and commands")

    # uninstall
    p_un = sub.add_parser("uninstall", help="Remove installed agents and commands")
    p_un.add_argument("--local", action="store_true", help="Target .claude/ in the current directory")
    p_un.add_argument("--directory", metavar="DIR", help="Target repo directory when using --local")
    p_un.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    p_un.add_argument("-q", "--quiet", action="store_true", help="Suppress file-by-file output")

    args = parser.parse_args()

    if args.command == "install":
        sys.exit(cmd_install(args))
    elif args.command == "list":
        sys.exit(cmd_list(args))
    elif args.command == "uninstall":
        sys.exit(cmd_uninstall(args))
    else:
        parser.print_help()
        sys.exit(0)
