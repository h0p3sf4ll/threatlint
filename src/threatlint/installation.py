"""Install and uninstall bundled agents, workflows, commands, and scripts."""

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path

from .skills import SKILLS as _SKILLS_SRC, agent_prompt, skill_map
from .terminal import _bold, _confirm, _green, _red, _yellow


_DATA = Path(__file__).parent / "data"
_AGENTS_SRC = _DATA / "agents"
_COMMANDS_SRC = _DATA / "commands"
_SCRIPTS_SRC = _DATA / "scripts"
_CLAUDE_DIR = ".claude"
_SKILL_MAP_FILE = "agent-skills.json"
_DOCX_SCRIPT = "md_to_docx.py"
_PROCEED_PROMPT = "Proceed?"
_ABORTED = "Aborted."


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


def _frontmatter(raw: str) -> dict[str, str]:
    """Simple ``key: value`` pairs from a Markdown frontmatter block (empty when absent)."""
    match = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", raw, re.DOTALL)
    meta: dict[str, str] = {}
    for line in (match.group(1).splitlines() if match else []):
        key, sep, value = line.partition(":")
        if sep and key.strip():
            meta[key.strip()] = value.strip()
    return meta


def _install_skills(destination: Path, verbose: bool = False) -> int:
    """Install complete workflows rather than repository discovery links."""
    count = 0
    for source in sorted(_SKILLS_SRC.rglob("*")):
        if not source.is_file():
            continue
        target = destination / source.relative_to(_SKILLS_SRC)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        count += 1
        if verbose:
            print(f"  {_green('added  ')}  skills/{source.relative_to(_SKILLS_SRC)}")
    return count


def _uninstall_skills(destination: Path, verbose: bool = False) -> None:
    """Remove bundled files only; preserve custom additions and third-party skills."""
    for source in sorted(_SKILLS_SRC.rglob("*")):
        if not source.is_file():
            continue
        target = destination / source.relative_to(_SKILLS_SRC)
        if target.is_file() and not target.is_symlink():
            target.unlink()
            if verbose:
                print(f"  {_red('removed')}  skills/{source.relative_to(_SKILLS_SRC)}")
        parent = target.parent
        while parent != destination and parent.is_dir() and not any(parent.iterdir()):
            parent.rmdir()
            parent = parent.parent


def _copilot_base(args: argparse.Namespace) -> Path:
    return ((Path(args.directory or ".").resolve() / ".github")
            if args.local else Path.home() / ".copilot")


def _cmd_install_copilot(args: argparse.Namespace) -> int:
    base = _copilot_base(args)
    print(_bold(f"\nthreatlint install --copilot → {base}"))
    if not args.yes and not _confirm("Install agents and complete skills?"):
        return 1
    destination = base / "agents"
    destination.mkdir(parents=True, exist_ok=True)
    agents = sorted(_AGENTS_SRC.glob("*.md"))
    for source in agents:
        raw = source.read_text(encoding="utf-8")
        description = _frontmatter(raw).get("description") or source.stem
        body = re.sub(r"^---\n[\s\S]*?\n---\n", "", raw).strip()
        header = (
            f"---\nname: {source.stem}\n"
            f"description: {description}\n"
            "tools: [read, search, execute]\nuser-invocable: true\n---\n\n"
        )
        (destination / f"{source.stem}.agent.md").write_text(header + body + "\n", encoding="utf-8")
    count = _install_skills(base / "skills", verbose=not args.quiet)
    print(_green(f"✓ {len(agents)} agents and {count} complete skills installed to {base}"))
    return 0


def _cmd_uninstall_copilot(args: argparse.Namespace) -> int:
    base = _copilot_base(args)
    print(_bold(f"\nthreatlint uninstall --copilot → {base}"))
    if not args.yes and not _confirm("Remove owned agents and skills?"):
        return 1
    for source in _AGENTS_SRC.glob("*.md"):
        target = base / "agents" / f"{source.stem}.agent.md"
        if target.is_file() and not target.is_symlink():
            target.unlink()
    _uninstall_skills(base / "skills", verbose=not args.quiet)
    print(_green("✓ Uninstall complete; unrelated files preserved"))
    return 0


def _cmd_install_lmstudio(args: argparse.Namespace) -> int:
    """Install all agents to ~/.lmstudio/agents/ as SKILL.md files."""
    dst = Path.home() / ".lmstudio" / "agents"

    print(_bold("\nthreatlint install --lmstudio"))
    print(f"  Destination : {dst}")
    print(f"  Agents      : {len(list(_AGENTS_SRC.iterdir()))} files")
    print()

    if not args.yes and not _confirm(_PROCEED_PROMPT):
        print(_ABORTED)
        return 1

    dst.mkdir(parents=True, exist_ok=True)
    count = 0

    for agent_file in sorted(_AGENTS_SRC.iterdir()):
        if agent_file.suffix != ".md":
            continue

        meta = _frontmatter(agent_file.read_text(encoding="utf-8", errors="replace"))
        if not meta:
            continue
        name = meta.get("name") or agent_file.stem
        description = meta.get("description", "")
        body = agent_prompt(agent_file.stem, agent_file)
        skill_dir = dst / agent_file.stem
        skill_dir.mkdir(exist_ok=True)
        skill_file = skill_dir / "SKILL.md"
        existed = skill_file.exists()
        skill_file.write_text(
            f"---\nname: {name}\ndescription: {description}\n---\n\n{body}\n",
            encoding="utf-8",
        )
        count += 1
        if not args.quiet:
            marker = _yellow("updated") if existed else _green("added  ")
            print(f"  {marker}  {agent_file.stem}/SKILL.md")

    print()
    print(_green(f"✓ {count} agents installed to {dst}"))
    if not args.quiet:
        print()
        print("  Restart Bionic (LM Studio) to pick up all agents.")
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    """Install agents, commands, and scripts into a .claude directory."""

    if getattr(args, "lmstudio", False):
        return _cmd_install_lmstudio(args)

    if getattr(args, "copilot", False):
        return _cmd_install_copilot(args)

    base = _claude_base(args)
    location_label = f".claude/ (local — {base.parent})" if args.local else "~/.claude/ (global)"

    agents_dst  = base / "agents"
    commands_dst = base / "commands"
    scripts_dst  = base / "scripts"

    print(_bold("\nthreatlint install"))
    print(f"  Destination : {location_label}")
    print(f"  Agents      : {len(list(_AGENTS_SRC.iterdir()))} files")
    print(f"  Commands    : {len(list(_COMMANDS_SRC.iterdir()))} files")
    print(f"  Scripts     : {len(list(_SCRIPTS_SRC.iterdir()))} files")
    print(f"  Skills      : {len(list(_SKILLS_SRC.iterdir()))} workflows")
    print()

    if not args.yes and not _confirm(_PROCEED_PROMPT):
        print(_ABORTED)
        return 1

    total = 0
    total += _copy_tree(_AGENTS_SRC,  agents_dst,  ".claude/agents",  verbose=not args.quiet)
    total += _copy_tree(_COMMANDS_SRC, commands_dst, ".claude/commands", verbose=not args.quiet)
    total += _copy_tree(_SCRIPTS_SRC,  scripts_dst,  ".claude/scripts",  verbose=not args.quiet)
    total += _install_skills(base / "skills", verbose=not args.quiet)
    shutil.copy2(_DATA / _SKILL_MAP_FILE, base / _SKILL_MAP_FILE)

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
    print(_bold("\nSkills"))
    for f in sorted(_SKILLS_SRC.iterdir()):
        users = [agent for agent, skills in skill_map().items() if f.name in skills]
        print(f"  {f.name} ({len(users)} agents)")
    print()
    return 0


def _claude_base(args: argparse.Namespace) -> Path:
    return (Path(args.directory or ".").resolve() if args.local else Path.home()) / _CLAUDE_DIR


def _remove_owned_files(directory: Path, owned: set[str], quiet: bool) -> None:
    """Remove only files threatlint installed, then the directory if that left it empty."""
    removed = 0
    for name in sorted(owned):
        installed = directory / name
        if installed.is_file() or installed.is_symlink():
            installed.unlink()
            removed += 1
            if not quiet:
                print(f"  {_red('removed')}  {directory.name}/{name}")
    if removed and not any(directory.iterdir()):
        directory.rmdir()


def _remove_target(target: Path, base: Path, quiet: bool) -> None:
    if not target.exists():
        return
    if target.is_dir():
        source = {
            "agents": _AGENTS_SRC,
            "commands": _COMMANDS_SRC,
            "scripts": _SCRIPTS_SRC,
        }[target.name]
        _remove_owned_files(target, {f.name for f in source.iterdir()}, quiet)
        return
    target.unlink()
    if not quiet:
        print(f"  {_red('removed')}  {target.relative_to(base)}")


def cmd_uninstall(args: argparse.Namespace) -> int:
    """Remove installed agents, commands, and scripts."""
    if getattr(args, "copilot", False):
        return _cmd_uninstall_copilot(args)
    base = _claude_base(args)
    targets = [
        base / "agents",
        base / "commands",
        base / "scripts",
        base / _SKILL_MAP_FILE,
    ]

    print(_bold("\nthreatlint uninstall"))
    print(f"  Removing from: {base}")
    if not args.yes and not _confirm(_PROCEED_PROMPT):
        print(_ABORTED)
        return 1

    for target in targets:
        _remove_target(target, base, args.quiet)
    print()
    _uninstall_skills(base / "skills", verbose=not args.quiet)
    print(_green("✓ Uninstall complete"))
    return 0
