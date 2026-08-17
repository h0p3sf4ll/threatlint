"""threatlint CLI — install AppSec agents into Claude Code / project directories."""

from __future__ import annotations

import argparse
import datetime
import os
import shutil
import subprocess
import sys
import tempfile
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
            print("  Claude Code quick-start (requires Claude license):")
            print("    /threat-model          — full two-tier threat model")
            print("    /security-review       — security code review of the current diff")
            print("    /secrets-scan          — scan for hardcoded credentials")
            print("    /dependency-audit      — supply-chain security audit")
            print()
            print("  Local analysis via LM Studio (no Claude required):")
            print("    threatlint run threat-model")
            print("    threatlint run secrets-scan")
            print("    threatlint run security-review --base HEAD~1 --head HEAD")
            print("    threatlint run dependency-audit")
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
        base / "scripts" / "appsec_api.py",
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
                    print(f"  {_red('removed')}  scripts/{t.name}")

    print()
    print(_green("✓ Uninstall complete"))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Run an AppSec analysis directly via LM Studio — no Claude required."""

    # Locate appsec_api.py: bundled in package data is authoritative
    appsec_script = _SCRIPTS_SRC / "appsec_api.py"
    if not appsec_script.exists():
        # Fallback: previously installed to ~/.claude/scripts
        appsec_script = Path.home() / ".claude" / "scripts" / "appsec_api.py"
    if not appsec_script.exists():
        print(_red("ERROR: appsec_api.py not found."))
        print("Run `threatlint install` or reinstall the package.")
        return 1

    docx_script = _SCRIPTS_SRC / "md_to_docx.py"
    if not docx_script.exists():
        docx_script = Path.home() / ".claude" / "scripts" / "md_to_docx.py"

    base_url = args.base_url

    # Verify LM Studio is reachable
    probe = subprocess.run(
        ["curl", "-sf", f"{base_url}/models"],
        capture_output=True, text=True,
    )
    if probe.returncode != 0 or not probe.stdout.strip() or probe.stdout.strip() == "{}":
        print(_red("ERROR: LM Studio is not running or no model is loaded."))
        print("Open LM Studio, load a model, and start the local server")
        print("(Developer › Local Server › Start Server), then retry.")
        return 1

    # Derive output filename from git context
    repo_root_result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True,
    )
    repo_root = repo_root_result.stdout.strip() or str(Path.cwd())
    repo_name = Path(repo_root).name.lower().replace(" ", "-")
    branch_result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True,
    )
    branch = (branch_result.stdout.strip() or "no-branch").lower().replace("/", "-")

    today = datetime.date.today().strftime("%Y-%m-%d")
    mode = args.mode
    target = getattr(args, "target", "") or ""
    sanitized = target.lower().replace(" ", "-")[:40] if target else ""

    base_name = f"{repo_name}-{branch}-{mode}-local"
    if sanitized:
        base_name += f"-{sanitized}"
    base_name += f"-{today}"

    # Build subprocess command — map CLI mode names to appsec_api.py mode names
    deep = getattr(args, "deep", False) or (mode == "threat-model-deep")
    api_mode = {
        "security-review": "pr-review",
        "threat-model-deep": "threat-model",
    }.get(mode, mode)

    with tempfile.NamedTemporaryFile(suffix=".md", delete=False, prefix=f"{mode}_") as tf:
        tmp_md = tf.name

    cmd = [
        sys.executable, str(appsec_script),
        "--mode", api_mode,
        "--provider", "lmstudio",
        "--output", tmp_md,
    ]
    if target:
        cmd += ["--target", target]
    if api_mode == "pr-review":
        base_sha = getattr(args, "base", "") or ""
        head_sha = getattr(args, "head", "") or ""
        if base_sha:
            cmd += ["--base", base_sha]
        if head_sha:
            cmd += ["--head", head_sha]
    if deep:
        cmd += ["--deep"]
    model = getattr(args, "model", "") or ""
    if model:
        cmd += ["--model", model]

    env = os.environ.copy()
    env["LMSTUDIO_BASE_URL"] = base_url

    print(_bold(f"\nthreatlint run {mode}"))
    print(f"  Provider  : LM Studio ({base_url})")
    if target:
        print(f"  Target    : {target}")
    print()

    result = subprocess.run(cmd, env=env)
    if result.returncode != 0:
        print(_red(f"\nERROR: Analysis failed (exit {result.returncode})."))
        Path(tmp_md).unlink(missing_ok=True)
        return 1

    out_dir = Path(getattr(args, "output_dir", None) or repo_root)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_docx = out_dir / f"{base_name}.docx"

    if docx_script.exists():
        r = subprocess.run([sys.executable, str(docx_script), tmp_md, str(out_docx)])
        if r.returncode == 0:
            Path(tmp_md).unlink(missing_ok=True)
            print(_green(f"\n✓ Report saved to {out_docx}"))
            return 0

    # Fallback: keep as Markdown
    out_md = out_dir / f"{base_name}.md"
    Path(tmp_md).rename(out_md)
    print(_green(f"\n✓ Report saved to {out_md}"))
    if not docx_script.exists():
        print(_yellow("  (Install python-docx for .docx output: pip install python-docx)"))
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

    # run
    _MODES = [
        "threat-model", "threat-model-deep", "security-review",
        "secrets-scan", "iac-review", "cicd-audit",
        "dependency-audit", "api-security", "auth-review",
        "red-team", "attack-tree",
    ]
    p_run = sub.add_parser("run", help="Run an AppSec analysis via LM Studio (no Claude required)")
    p_run.add_argument("mode", choices=_MODES, metavar="MODE",
        help=f"Analysis type: {{{', '.join(_MODES)}}}")
    p_run.add_argument("--target", metavar="TARGET",
        help="Component, path, or service name to analyze (default: auto-discover)")
    p_run.add_argument("--deep", action="store_true",
        help="Aggressive deep-dive mode (threat-model only)")
    p_run.add_argument("--base", metavar="SHA",
        help="Base commit SHA (security-review only)")
    p_run.add_argument("--head", metavar="SHA",
        help="Head commit SHA (security-review only)")
    p_run.add_argument("--model", metavar="MODEL",
        help="Override model name (default: auto-detect from LM Studio)")
    p_run.add_argument("--base-url", metavar="URL", default="http://localhost:1234/v1",
        help="LM Studio API base URL (default: http://localhost:1234/v1)")
    p_run.add_argument("--output-dir", metavar="DIR",
        help="Directory for the output report (default: repository root)")

    # list
    sub.add_parser("list", help="List bundled agents and commands")

    # uninstall
    p_un = sub.add_parser("uninstall", help="Remove installed agents and commands")
    p_un.add_argument("--local", action="store_true", help="Target .claude/ in the current directory")
    p_un.add_argument("--directory", metavar="DIR", help="Target repo directory when using --local")
    p_un.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    p_un.add_argument("-q", "--quiet", action="store_true", help="Suppress file-by-file output")

    args = parser.parse_args()

    if args.command == "run":
        sys.exit(cmd_run(args))
    elif args.command == "install":
        sys.exit(cmd_install(args))
    elif args.command == "list":
        sys.exit(cmd_list(args))
    elif args.command == "uninstall":
        sys.exit(cmd_uninstall(args))
    else:
        parser.print_help()
        sys.exit(0)
