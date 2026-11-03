"""CLI composition: register commands and coordinate an analysis run."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from threatlint import __version__
from threatlint import models as _models
from threatlint.servicenow import (
    ServiceNowError,
    add_avit_arguments,
    add_avit_parser,
    cmd_avit,
)
from threatlint.skills import agent_prompt

from . import run_context
from .agent_runner import (
    _StreamTurn as _StreamTurn,
    _lmstudio_models as _lmstudio_models,
    _run_agent as _run_agent,
    _stream_turn as _stream_turn,
)
from .agent_tools import (
    _tool_bash as _tool_bash,
    _tool_glob as _tool_glob,
    _tool_grep as _tool_grep,
    _tool_read as _tool_read,
    _validate_bash as _validate_bash,
)
from .installation import (
    cmd_install as cmd_install,
    cmd_list as cmd_list,
    cmd_uninstall as cmd_uninstall,
)
from .report_output import _git_output, _report_basename, _save_report
from .run_context import (
    _MODE_TO_AGENT,
    _OPENAI_DEFAULT_MODEL as _OPENAI_DEFAULT_MODEL,
    _RUN_PROVIDERS,
    _SEMGREP_AGENTS,
    _SEMGREP_INSTALL,
    _build_run_message,
    _default_run_model as _default_run_model,
    _load_requested_avits as _load_requested_avits,
    _print_run_header,
    _resolve_agent_file,
    _semgrep_version,
)
from .terminal import _green, _red


def _resolve_provider(args: argparse.Namespace) -> tuple[str, str, str] | None:
    return run_context._resolve_provider(args, list_models=_lmstudio_models)


def cmd_run(args: argparse.Namespace) -> int:
    """Run an AppSec analysis via a local or cloud LLM."""
    mode = args.mode
    resolved_provider = _resolve_provider(args)
    if resolved_provider is None:
        return 1
    provider, base_url, api_key = resolved_provider

    resolved = _resolve_agent_file(mode)
    if resolved is None:
        print(_red(f"ERROR: Agent file not found for mode '{mode}'."))
        print("Run `threatlint install` to install the agent files.")
        return 1
    agent_name, agent_file = resolved
    system_prompt = agent_prompt(agent_name, agent_file)

    if agent_name in _SEMGREP_AGENTS:
        args.semgrep_version = _semgrep_version()
        if not args.semgrep_version:
            print(_red("ERROR: Semgrep Community Edition is not installed."))
            print(_SEMGREP_INSTALL)
            return 1

    repo_root = _git_output("rev-parse", "--show-toplevel") or str(Path.cwd())
    try:
        avits = _load_requested_avits(args, mode)
        user_msg = _build_run_message(args, repo_root, avits)
    except ServiceNowError as exc:
        print(_red(f"ERROR: {exc}"))
        return 1
    except (OSError, ValueError) as exc:
        print(_red(f"ERROR: Cannot load findings: {exc}"))
        return 1

    try:
        from threatlint import design_inputs  # noqa: PLC0415
        design = design_inputs.load(args.design) if getattr(args, "design", None) else design_inputs.Bundle()
    except (design_inputs.DesignInputError, OSError) as exc:
        print(_red(f"ERROR: Cannot load design inputs: {exc}"))
        return 1
    user_msg += design_inputs.context(design, images_as_files=provider == "claude-code")

    model = _default_run_model(provider, getattr(args, "model", ""))
    _print_run_header(mode, provider, base_url, model, getattr(args, "target", "") or "")
    for document in design.documents:
        print(f"  Design    : {document.name} ({document.kind}{f', {document.truncated:,} characters truncated' if document.truncated else ''})")
    for image in design.images:
        print(f"  Design    : {image.name} (image)")

    try:
        if provider == "claude-code":
            from threatlint.claude_code import run_agent as run_claude_code  # noqa: PLC0415
            output = run_claude_code(system_prompt, user_msg, repo_root, model, images=design.images)
        else:
            output = _run_agent(base_url, model, system_prompt, user_msg, repo_root, api_key=api_key, images=design.images)
    except RuntimeError as exc:
        print(_red(f"\nERROR: {exc}"))
        return 1
    if not output.strip():
        print(_red("\nERROR: Agent produced no output."))
        return 1
    print()

    saved = _save_report(output, Path(getattr(args, "output_dir", None) or repo_root), _report_basename(repo_root, mode), mode)
    print(_green(f"✓ Report saved to {saved}"))
    return 0


# ── Main ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
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
    p_install.add_argument("--lmstudio", action="store_true",
        help="Install agents to ~/.lmstudio/agents/ for use in Bionic / LM Studio")
    p_install.add_argument("--copilot", action="store_true",
        help="Install Copilot agents and skills (.github/ with --local; ~/.copilot/ otherwise)")
    p_install.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    p_install.add_argument("-q", "--quiet", action="store_true", help="Suppress file-by-file output")

    # run
    _MODES = list(_MODE_TO_AGENT)
    p_run = sub.add_parser("run", help="Run an AppSec analysis via LM Studio (no Claude required)")
    p_run.add_argument("mode", choices=_MODES, metavar="MODE",
        help=f"Analysis type: {{{', '.join(_MODES)}}}")
    p_run.add_argument("--target", metavar="TARGET",
        help="Component, path, or service name to analyze (default: auto-discover)")
    p_run.add_argument("--design", metavar="PATH", nargs="+", action="extend",
        help="Design inputs for the threat model: diagrams (draw.io, Mermaid, PlantUML, Visio, SVG, Threat Dragon, "
             "Threat Modeling Tool), design docs (PDF, Word, PowerPoint, Markdown), OpenAPI specs, images, or folders of them")
    p_run.add_argument("--findings", metavar="PATH",
        help="SARIF, Semgrep JSON, Markdown, or text findings artifact (maximum 5 MB)")
    p_run.add_argument("--deep", action="store_true",
        help="Aggressive deep-dive mode (threat-model only)")
    p_run.add_argument("--base", metavar="SHA",
        help="Base commit SHA (security-review only)")
    p_run.add_argument("--head", metavar="SHA",
        help="Head commit SHA (security-review only)")
    p_run.add_argument("--model", metavar="MODEL",
        help="Model ID (default: auto-detect for lmstudio; gpt-5.6 for openai; "
             f"{_models.SCAN_MODEL} for claude, or THREATLINT_SCAN_MODEL)")
    p_run.add_argument("--provider", metavar="PROVIDER", default="lmstudio",
        choices=list(_RUN_PROVIDERS),
        help="LLM provider: lmstudio (default), openai, claude (API key), or claude-code (your Claude Code login)")
    p_run.add_argument("--api-key", metavar="KEY", dest="api_key",
        help="API key for the provider (or set OPENAI_API_KEY / ANTHROPIC_API_KEY)")
    p_run.add_argument("--base-url", metavar="URL", default="http://localhost:1234/v1",
        help="LM Studio API base URL (default: http://localhost:1234/v1)")
    p_run.add_argument("--output-dir", metavar="DIR",
        help="Directory for the output report (default: repository root)")
    add_avit_arguments(p_run)

    # list
    sub.add_parser("list", help="List bundled agents and commands")

    # uninstall
    p_un = sub.add_parser("uninstall", help="Remove installed agents and commands")
    p_un.add_argument("--local", action="store_true", help="Target .claude/ in the current directory")
    p_un.add_argument("--directory", metavar="DIR", help="Target repo directory when using --local")
    p_un.add_argument("--copilot", action="store_true", help="Remove owned Copilot agents and skills")
    p_un.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    p_un.add_argument("-q", "--quiet", action="store_true", help="Suppress file-by-file output")

    # guard / ide
    from threatlint.guard import add_guard_parser
    from threatlint.ide import add_ide_parser
    add_guard_parser(sub)
    add_ide_parser(sub)
    add_avit_parser(sub)
    from threatlint.avit_orchestrator import add_orchestrator_parser
    add_orchestrator_parser(sub)
    from threatlint.aws_login import add_aws_parser
    add_aws_parser(sub)
    from threatlint.ado_login import add_ado_parser
    add_ado_parser(sub)
    from threatlint.github_app import add_github_parser
    add_github_parser(sub)
    from threatlint.semgrep_platform import add_semgrep_parser
    add_semgrep_parser(sub)
    from threatlint.setup_wizard import add_setup_parser
    add_setup_parser(sub)
    from threatlint.sctask import add_sctask_parser
    add_sctask_parser(sub)
    from threatlint.sidekick.cli import add_sidekick_parser
    add_sidekick_parser(sub)
    from threatlint.integrations.cli import add_parsers as add_integration_parsers
    add_integration_parsers(sub)

    return parser


def _cmd_semgrep(args: argparse.Namespace) -> int:
    from threatlint.semgrep_platform import cmd_semgrep
    return cmd_semgrep(args)


def _cmd_setup(args: argparse.Namespace) -> int:
    from threatlint.setup_wizard import cmd_setup
    return cmd_setup(args)


def _cmd_sidekick(args: argparse.Namespace) -> int:
    from threatlint.sidekick.cli import cmd_sidekick
    return cmd_sidekick(args)


def _cmd_sctask(args: argparse.Namespace) -> int:
    from threatlint.sctask import cmd_sctask
    return cmd_sctask(args)


def _cmd_ado(args: argparse.Namespace) -> int:
    from threatlint.ado_login import cmd_ado
    return cmd_ado(args)


def _cmd_github(args: argparse.Namespace) -> int:
    from threatlint.github_app import cmd_github
    return cmd_github(args)


def _cmd_aws(args: argparse.Namespace) -> int:
    from threatlint.aws_login import cmd_aws
    return cmd_aws(args)


def _cmd_orchestrator(args: argparse.Namespace) -> int:
    from threatlint.avit_orchestrator import cmd_orchestrator
    return cmd_orchestrator(args)


def main() -> None:
    from threatlint.guard import cmd_guard
    from threatlint.ide import cmd_ide

    # Windows consoles on legacy code pages cannot encode ✓ / →; substitute rather than crash.
    # Pipes (the Workbench, CI) read UTF-8, so write UTF-8 to them rather than the ANSI code page.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            if stream.isatty():
                reconfigure(errors="replace")
            else:
                reconfigure(encoding="utf-8", errors="replace")

    parser = build_parser()
    args = parser.parse_args()
    commands = {"guard": cmd_guard, "ide": cmd_ide, "run": cmd_run, "install": cmd_install,
                "list": cmd_list, "uninstall": cmd_uninstall, "avit": cmd_avit, "aws": _cmd_aws, "ado": _cmd_ado, "github": _cmd_github, "semgrep": _cmd_semgrep, "setup": _cmd_setup, "sctask": _cmd_sctask, "sidekick": _cmd_sidekick, "orchestrator": _cmd_orchestrator}
    # Integration commands (built-in and plugin) register their own handler.
    handler = commands.get(args.command) or getattr(args, "integration_handler", None)
    if handler is None:
        parser.print_help()
        sys.exit(0)
    sys.exit(handler(args))


if __name__ == "__main__":
    main()
