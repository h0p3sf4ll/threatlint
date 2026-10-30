"""threatlint CLI — install AppSec agents into Claude Code / project directories."""

from __future__ import annotations

import argparse
import datetime
import glob as _glob_module
import http.client
import json as _json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from threatlint import __version__
from threatlint.skills import SKILLS as _SKILLS_SRC
from threatlint.servicenow import (
    ServiceNowError,
    add_avit_arguments,
    add_avit_parser,
    cmd_avit,
    collect_avits,
    requested_avits,
)
from threatlint.skills import agent_prompt, findings_context, findings_text, skill_map

# ── Package data roots ────────────────────────────────────────────────────────

_DATA = Path(__file__).parent / "data"
_AGENTS_SRC = _DATA / "agents"
_COMMANDS_SRC = _DATA / "commands"
_SCRIPTS_SRC = _DATA / "scripts"
_CLAUDE_DIR = ".claude"
_SKILL_MAP_FILE = "agent-skills.json"
_DOCX_SCRIPT = "md_to_docx.py"
_PROCEED_PROMPT = "Proceed?"
_ABORTED = "Aborted."


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


def _frontmatter(raw: str) -> dict[str, str]:
    """Simple ``key: value`` pairs from a Markdown frontmatter block (empty when absent)."""
    match = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", raw, re.DOTALL)
    meta: dict[str, str] = {}
    for line in (match.group(1).splitlines() if match else []):
        key, sep, value = line.partition(":")
        if sep and key.strip():
            meta[key.strip()] = value.strip()
    return meta


def _confirm(prompt: str) -> bool:
    try:
        ans = input(f"{prompt} [y/N] ").strip().lower()
        return ans in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        print()
        return False


# ── Mode → agent mapping ──────────────────────────────────────────────────────

_MODE_TO_AGENT: dict[str, str] = {
    "threat-model":      "appsec-threat-modeler",
    "threat-model-deep": "appsec-threat-modeler",
    "security-review":   "appsec-code-reviewer",
    "secrets-scan":      "appsec-secrets-scanner",
    "iac-review":        "appsec-iac-reviewer",
    "cicd-audit":        "appsec-cicd-auditor",
    "dependency-audit":  "appsec-dependency-auditor",
    "api-security":      "appsec-api-security-reviewer",
    "auth-review":       "appsec-auth-reviewer",
    "fp-review":         "appsec-fp-reviewer",
    "compliance-check":  "appsec-compliance-checker",
    "attack-tree":       "appsec-attack-tree",
    "red-team":          "appsec-red-team",
    "threat-delta":      "appsec-threat-delta",
    "verify-fix":        "appsec-verify-fix",
    "runtime-review":    "appsec-runtime-reviewer",
    "business-logic-review": "appsec-business-logic-reviewer",
    "client-security-review": "appsec-client-security-reviewer",
    "crypto-review":     "appsec-crypto-reviewer",
    "ai-security-review": "appsec-ai-security-reviewer",
    "security-test-plan": "appsec-security-test-planner",
    "secure-codegen-review": "appsec-secure-codegen-reviewer",
    "privacy-review": "appsec-privacy-reviewer",
}

# ── Tool definitions (OpenAI function format) ─────────────────────────────────

_TOOLS = [
    {"type": "function", "function": {
        "name": "Read",
        "description": "Read a file from the repository. Returns numbered lines.",
        "parameters": {"type": "object", "required": ["file_path"], "properties": {
            "file_path": {"type": "string"},
            "offset":    {"type": "integer"},
            "limit":     {"type": "integer"},
        }},
    }},
    {"type": "function", "function": {
        "name": "Bash",
        "description": "Run one read-only inspection command without shell syntax. Permitted: read-only git subcommands, find, grep, cat, head, tail, wc, ls, cut. No pipes, redirection, interpreters, or mutation. Prefer Read/Grep/Glob.",
        "parameters": {"type": "object", "required": ["command"], "properties": {
            "command": {"type": "string"},
        }},
    }},
    {"type": "function", "function": {
        "name": "Grep",
        "description": "Search files for a regex pattern.",
        "parameters": {"type": "object", "required": ["pattern"], "properties": {
            "pattern": {"type": "string"},
            "path":    {"type": "string"},
            "flags":   {"type": "string"},
        }},
    }},
    {"type": "function", "function": {
        "name": "Glob",
        "description": "Find files matching a glob pattern relative to repo root.",
        "parameters": {"type": "object", "required": ["pattern"], "properties": {
            "pattern": {"type": "string"},
        }},
    }},
]

# ── Tool execution ────────────────────────────────────────────────────────────

_MAX_READ_BYTES = 2 * 1024 * 1024
_MAX_READ_LINES = 2000
_MAX_TOOL_OUTPUT = 8000
_MAX_GLOB_RESULTS = 500
_TOOL_TIMEOUT_S = 30
_MAX_AGENT_ITERATIONS = 80
_MAX_OUTPUT_TOKENS = 16000
_MODEL_REQUEST_TIMEOUT_S = 600

# Single source of truth for the Bash tool policy; _validate_bash enforces it.
_BASH_COMMANDS = frozenset({"find", "grep", "cat", "head", "tail", "wc", "ls", "cut"})
_GIT_SUBCOMMANDS = frozenset({"log", "show", "ls-files", "status", "diff", "blame", "rev-parse",
                              "ls-tree", "describe", "shortlog", "grep", "rev-list"})
_SHELL_SYNTAX = (";", "|", "&", "`", "$", ">", "<", "\n", "\r", "\0")
_BLOCKED_OPTION_PREFIXES = ("-exec", "-ok", "-delete", "-fprint", "-fprintf", "-fls", "--output", "--out=",
                            "--ext-diff", "--textconv", "--no-index", "--files", "-L", "--dereference",
                            "--git-dir", "--work-tree")
_BLOCKED_OPTIONS = frozenset({"-o", "-f", "-C", "-c"})
_SAFE_ENV_KEYS = frozenset({"PATH", "HOME", "LANG", "SYSTEMROOT", "WINDIR"})


def _repository_path(repo_root: str, file_path: str) -> Path:
    root = Path(repo_root).resolve()
    candidate = (root / file_path).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("Access outside the selected repository is denied")
    return candidate


def _tool_read(repo_root: str, file_path: str, offset: int = 0, limit: int = _MAX_READ_LINES) -> str:
    try:
        source = _repository_path(repo_root, file_path)
        if source.stat().st_size > _MAX_READ_BYTES:
            return "Error: file exceeds the 2 MB inspection limit"
        with source.open("r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except (OSError, ValueError) as exc:
        return f"Error: {exc}"
    offset = max(0, offset)
    chunk = lines[offset: offset + min(_MAX_READ_LINES, max(1, limit))]
    return "".join(f"{i + offset + 1}\t{line}" for i, line in enumerate(chunk))


def _check_bash_command(args: list[str]) -> None:
    if args[0] == "git":
        if len(args) < 2 or args[1] not in _GIT_SUBCOMMANDS:
            raise ValueError("command not permitted — Git mutation is disabled")
    elif args[0] not in _BASH_COMMANDS:
        raise ValueError("command not permitted — use Read, Grep, or Glob for source inspection")


def _check_bash_argument(repo_root: str, argument: str) -> None:
    if argument.startswith(_BLOCKED_OPTION_PREFIXES) or argument in _BLOCKED_OPTIONS:
        raise ValueError("command not permitted — unsafe inspection option")
    looks_like_path = "/" in argument or argument in {".", ".."} or (Path(repo_root) / argument).exists()
    if not argument.startswith("-") and looks_like_path:
        _repository_path(repo_root, argument)


def _harden_git(args: list[str]) -> list[str]:
    subcommand, *rest = args[1:]
    hardened = ["git", "--no-pager", "--no-optional-locks", "-c", "core.fsmonitor=false", subcommand]
    if subcommand in {"log", "show", "diff"}:
        hardened += ["--no-ext-diff", "--no-textconv"]
    return hardened + rest


def _validate_bash(repo_root: str, command: str) -> list[str]:
    """Return the argv to execute, or raise ValueError when the command is outside policy."""
    if any(character in command for character in _SHELL_SYNTAX):
        raise ValueError("command not permitted — shell syntax is not allowed")
    args = shlex.split(command)
    if not args:
        raise ValueError("command not permitted")
    _check_bash_command(args)
    for argument in args[1:]:
        _check_bash_argument(repo_root, argument)
    return _harden_git(args) if args[0] == "git" else args


def _tool_bash(repo_root: str, command: str) -> str:
    try:
        args = _validate_bash(repo_root, command)
    except ValueError as exc:
        return f"Error: {exc}"
    env = {key: value for key, value in os.environ.items() if key in _SAFE_ENV_KEYS}
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        result = subprocess.run(args, capture_output=True, env=env, text=True, cwd=repo_root, timeout=_TOOL_TIMEOUT_S, check=False)
    except subprocess.TimeoutExpired:
        return "Error: command timed out"
    except OSError as exc:
        return f"Error: {exc}"
    return (result.stdout + result.stderr)[:_MAX_TOOL_OUTPUT]


def _tool_grep(repo_root: str, pattern: str, path: str = ".", flags: str = "-rn") -> str:
    try:
        search = _repository_path(repo_root, path)
        safe_flags = "-rnEi" if "i" in flags else "-rnE"
        result = subprocess.run(["grep", safe_flags, "-e", pattern, "--", str(search)], capture_output=True,
                                text=True, cwd=repo_root, timeout=_TOOL_TIMEOUT_S, check=False)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return f"Error: {exc}"
    return (result.stdout + result.stderr)[:_MAX_TOOL_OUTPUT]


def _tool_glob(repo_root: str, pattern: str) -> str:
    try:
        _repository_path(repo_root, pattern)
    except ValueError as exc:
        return f"Error: {exc}"
    matches = _glob_module.glob(os.path.join(repo_root, pattern), recursive=True)
    root = Path(repo_root).resolve()
    rel = [os.path.relpath(m, repo_root) for m in sorted(matches) if Path(m).resolve().is_relative_to(root)][:_MAX_GLOB_RESULTS]
    return "\n".join(rel) if rel else "(no matches)"


def _int_arg(args: dict, key: str, default: int) -> int:
    try:
        return int(args.get(key, default))
    except (TypeError, ValueError):
        return default


# Tool name → handler; arguments come from the model and are therefore defensively coerced.
_TOOL_HANDLERS = {
    "Read": lambda root, a: _tool_read(root, str(a.get("file_path", "")), _int_arg(a, "offset", 0), _int_arg(a, "limit", _MAX_READ_LINES)),
    "Bash": lambda root, a: _tool_bash(root, str(a.get("command", ""))),
    "Grep": lambda root, a: _tool_grep(root, str(a.get("pattern", "")), str(a.get("path", ".")), str(a.get("flags", "-rn"))),
    "Glob": lambda root, a: _tool_glob(root, str(a.get("pattern", ""))),
}


def _execute_tool(repo_root: str, name: str, args: dict) -> str:
    handler = _TOOL_HANDLERS.get(name)
    return handler(repo_root, args) if handler else f"Unknown tool: {name}"

# ── LM Studio agent runner ────────────────────────────────────────────────────

def _lmstudio_auto_model(base_url: str) -> str:
    models = _lmstudio_models(base_url)
    return models[0] if models else ""


def _lmstudio_models(base_url: str) -> list[str]:
    """Model IDs served by an OpenAI-compatible server; empty when unreachable or none loaded."""
    import urllib.request as _req
    try:
        with _req.urlopen(f"{base_url}/models", timeout=5) as resp:
            data = _json.loads(resp.read())
    except (OSError, ValueError):
        return []
    return [m["id"] for m in data.get("data", []) if isinstance(m, dict) and isinstance(m.get("id"), str)]


class _StreamTurn:
    """Accumulates one streamed chat-completions turn: text, tool calls, and finish reason."""

    def __init__(self) -> None:
        self.text = ""
        self.calls: dict[int, dict] = {}
        self.finish_reason = "stop"
        self.done = False

    def feed_line(self, line: str) -> None:
        if self.done or not line.startswith("data: "):
            return
        data = line[6:].strip()
        if data == "[DONE]":
            self.done = True
            return
        try:
            choice = _json.loads(data).get("choices", [{}])[0]
        except (_json.JSONDecodeError, IndexError, AttributeError):
            return  # Keep-alive or malformed chunk; the stream carries on.
        if choice.get("finish_reason"):
            self.finish_reason = choice["finish_reason"]
        delta = choice.get("delta") or {}
        if delta.get("content"):
            self.text += delta["content"]
            print(delta["content"], end="", flush=True)
        for call in delta.get("tool_calls") or []:
            self._merge_call(call)

    def _merge_call(self, call: dict) -> None:
        index = call.get("index", 0)
        current = self.calls.setdefault(index, {"id": call.get("id", f"call_{index}"), "name": "", "args": ""})
        if call.get("id"):
            current["id"] = call["id"]
        function = call.get("function") or {}
        current["name"] += function.get("name") or ""
        current["args"] += function.get("arguments") or ""

    def assistant_message(self) -> dict:
        message: dict = {"role": "assistant", "content": self.text or None}
        if self.calls:
            message["tool_calls"] = [{"id": call["id"], "type": "function",
                                      "function": {"name": call["name"], "arguments": call["args"]}}
                                     for call in self.calls.values()]
        return message


def _stream_turn(base_url: str, model: str, messages: list[dict], api_key: str) -> _StreamTurn:
    import urllib.request as _req

    body = _json.dumps({"model": model, "messages": messages, "tools": _TOOLS,
                        "stream": True, "max_tokens": _MAX_OUTPUT_TOKENS}).encode()
    headers = {"Content-Type": "application/json", **({"Authorization": f"Bearer {api_key}"} if api_key else {})}
    request = _req.Request(f"{base_url}/chat/completions", data=body, headers=headers)
    turn = _StreamTurn()
    try:
        with _req.urlopen(request, timeout=_MODEL_REQUEST_TIMEOUT_S) as resp:
            buffer = ""
            for raw in resp:
                buffer += raw.decode("utf-8", errors="replace")
                *lines, buffer = buffer.split("\n")
                for line in lines:
                    turn.feed_line(line)
    except (OSError, http.client.HTTPException) as exc:
        raise RuntimeError(f"LM Studio request failed: {exc}") from exc
    return turn


def _run_tool_calls(turn: _StreamTurn, repo_root: str) -> list[dict]:
    results = []
    for call in turn.calls.values():
        try:
            args = _json.loads(call["args"] or "{}")
        except _json.JSONDecodeError:
            args = {}
        short = ", ".join(f"{k}={repr(v)[:40]}" for k, v in list(args.items())[:2])
        print(f"  → {call['name']}({short})", flush=True)
        results.append({"role": "tool", "tool_call_id": call["id"], "content": str(_execute_tool(repo_root, call["name"], args))})
    return results


def _run_agent(base_url: str, model: str, system_prompt: str,
               user_message: str, repo_root: str, api_key: str = "") -> str:
    """Stream a full tool-use agentic loop against an OpenAI-compatible server. Returns output text."""
    model = model or _lmstudio_auto_model(base_url)
    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]
    full_text = ""
    for _iteration in range(_MAX_AGENT_ITERATIONS):
        turn = _stream_turn(base_url, model, messages, api_key)
        full_text += turn.text
        messages.append(turn.assistant_message())
        if turn.finish_reason != "tool_calls" or not turn.calls:
            break
        if turn.text:
            print()
        messages.extend(_run_tool_calls(turn, repo_root))
    return full_text


# ── Commands ──────────────────────────────────────────────────────────────────

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
        source = _AGENTS_SRC if target.name == "agents" else _COMMANDS_SRC
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
        base / "scripts" / _DOCX_SCRIPT,
        base / "scripts" / "appsec_api.py",
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


_OPENAI_BASE_URL = "https://api.openai.com/v1"
_OPENAI_DEFAULT_MODEL = "gpt-5.6"


def _resolve_agent_file(mode: str) -> tuple[str, Path] | None:
    """Bundled agent definition for ``mode``, falling back to a global Claude install."""
    agent_name = _MODE_TO_AGENT.get(mode)
    if not agent_name:
        return None
    for candidate in (_AGENTS_SRC / f"{agent_name}.md", Path.home() / _CLAUDE_DIR / "agents" / f"{agent_name}.md"):
        if candidate.exists():
            return agent_name, candidate
    return None


def _git_output(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=False).stdout.strip()


# Agents whose proposals are validated with Semgrep Community Edition.
_SEMGREP_AGENTS = frozenset({"appsec-fp-reviewer"})
_SEMGREP_INSTALL = ("Install Semgrep Community Edition before running this review, then retry:\n"
                    "  python3 -m pip install semgrep     (or: brew install semgrep)\n"
                    "  semgrep --version")


def _semgrep_version() -> str | None:
    """Installed Semgrep version, or None when the CLI is unavailable."""
    executable = shutil.which("semgrep")
    if not executable:
        return None
    try:
        result = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=_TOOL_TIMEOUT_S, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip().splitlines()[0] if result.returncode == 0 and result.stdout.strip() else None


def _build_run_message(args: argparse.Namespace, repo_root: str, avits: tuple[str, str] | None = None) -> str:
    """Assemble the user message; raises OSError/ValueError when a findings file is unusable."""
    mode = args.mode
    message = f"The repository to analyze is located at: {repo_root}\n"
    if getattr(args, "findings", None):
        message += findings_context(args.findings)
    if avits:
        message += findings_text(*avits)
        message += ("\nTriage every AVIT above as one finding in a single cohesive report, keeping each AVIT number"
                    " as the original finding ID. Locate the flagged code in this repository from the AVIT fields.\n")
    if getattr(args, "semgrep_version", None):
        message += f"\nSemgrep Community Edition is installed for the user ({args.semgrep_version}); write validation commands for it.\n"
    if getattr(args, "target", ""):
        message += f"\nFocus area / target: {args.target}\n"
    if getattr(args, "deep", False) or mode == "threat-model-deep":
        message += "\nPerform a thorough, deep-dive analysis.\n"
    if mode == "security-review" and getattr(args, "base", None):
        message += f"\nReview commit range: {args.base}..{getattr(args, 'head', None) or 'HEAD'}\n"
    return message + "\nBegin your full analysis now and produce the complete report as specified in your instructions."


def _report_basename(repo_root: str, mode: str) -> str:
    repo_name = Path(repo_root).name.lower().replace(" ", "-")
    branch = (_git_output("rev-parse", "--abbrev-ref", "HEAD") or "no-branch").lower().replace("/", "-")
    return f"{repo_name}-{branch}-{mode}-local-{datetime.date.today():%Y-%m-%d}"


def _save_report(output: str, out_dir: Path, base_name: str, mode: str) -> Path:
    """Save as Word when the converter succeeds, otherwise as Markdown."""
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(suffix=".md", delete=False, prefix=f"{mode}_") as tf:
        tf.write(output.encode())
        tmp_md = Path(tf.name)
    docx_script = _SCRIPTS_SRC / _DOCX_SCRIPT
    if not docx_script.exists():
        docx_script = Path.home() / _CLAUDE_DIR / "scripts" / _DOCX_SCRIPT
    out_docx = out_dir / f"{base_name}.docx"
    if docx_script.exists() and subprocess.run([sys.executable, str(docx_script), str(tmp_md), str(out_docx)], check=False).returncode == 0:
        tmp_md.unlink(missing_ok=True)
        return out_docx
    out_md = out_dir / f"{base_name}.md"
    shutil.move(str(tmp_md), out_md)
    return out_md


def _resolve_provider(args: argparse.Namespace) -> tuple[str, str, str] | None:
    """(provider, base_url, api_key), or None after printing why the provider is unusable."""
    provider = getattr(args, "provider", "lmstudio") or "lmstudio"
    api_key = getattr(args, "api_key", "") or ""
    if provider == "openai":
        api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            print(_red("ERROR: OpenAI API key required. Pass --api-key or set OPENAI_API_KEY."))
            return None
        return provider, _OPENAI_BASE_URL, api_key
    base_url = args.base_url.rstrip("/")
    if not _lmstudio_models(base_url):
        print(_red("ERROR: LM Studio (Bionic) is not running or no model is loaded."))
        print("Open LM Studio, load a model, and start the local server")
        print("(Developer › Local Server › Start Server), then retry.")
        return None
    return provider, base_url, api_key


def _print_run_header(mode: str, provider: str, base_url: str, model: str, target: str) -> None:
    print(_bold(f"\nthreatlint run {mode}"))
    print(f"  Provider  : {'OpenAI' if provider == 'openai' else f'LM Studio ({base_url})'}")
    if model:
        print(f"  Model     : {model}")
    if target:
        print(f"  Target    : {target}")
    print()


def _load_requested_avits(args: argparse.Namespace, mode: str) -> tuple[str, str] | None:
    """ServiceNow AVITs requested for an FP review, as (label, content); None when none were requested."""
    numbers = requested_avits(args)
    if not numbers:
        return None
    if mode != "fp-review":
        raise ServiceNowError("--avit and --avit-file are only supported with `threatlint run fp-review`")
    return collect_avits(args, numbers)


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

    model = getattr(args, "model", "") or (_OPENAI_DEFAULT_MODEL if provider == "openai" else "")
    _print_run_header(mode, provider, base_url, model, getattr(args, "target", "") or "")

    try:
        output = _run_agent(base_url, model, system_prompt, user_msg, repo_root, api_key=api_key)
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
    p_run.add_argument("--findings", metavar="PATH",
        help="SARIF, Semgrep JSON, Markdown, or text findings artifact (maximum 5 MB)")
    p_run.add_argument("--deep", action="store_true",
        help="Aggressive deep-dive mode (threat-model only)")
    p_run.add_argument("--base", metavar="SHA",
        help="Base commit SHA (security-review only)")
    p_run.add_argument("--head", metavar="SHA",
        help="Head commit SHA (security-review only)")
    p_run.add_argument("--model", metavar="MODEL",
        help="Model ID (default: auto-detect for lmstudio; gpt-5.6 for openai)")
    p_run.add_argument("--provider", metavar="PROVIDER", default="lmstudio",
        choices=["lmstudio", "openai"],
        help="LLM provider: lmstudio (default) or openai")
    p_run.add_argument("--api-key", metavar="KEY", dest="api_key",
        help="API key for the provider (for OpenAI; or set OPENAI_API_KEY env var)")
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
    from threatlint.scanners.cli import add_parsers as add_scanner_parsers
    add_scanner_parsers(sub)

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


def _cmd_scanner(args: argparse.Namespace) -> int:
    from threatlint.scanners.cli import cmd_scanner
    return cmd_scanner(args)


def _cmd_aws(args: argparse.Namespace) -> int:
    from threatlint.aws_login import cmd_aws
    return cmd_aws(args)


def main() -> None:
    from threatlint.guard import cmd_guard
    from threatlint.ide import cmd_ide

    # Windows consoles on legacy code pages cannot encode ✓ / →; substitute rather than crash.
    # Pipes (the Workbench, CI) read UTF-8, so write UTF-8 to them rather than the ANSI code page.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            if stream.isatty():
                stream.reconfigure(errors="replace")
            else:
                stream.reconfigure(encoding="utf-8", errors="replace")

    parser = build_parser()
    args = parser.parse_args()
    commands = {"guard": cmd_guard, "ide": cmd_ide, "run": cmd_run, "install": cmd_install,
                "list": cmd_list, "uninstall": cmd_uninstall, "avit": cmd_avit, "aws": _cmd_aws, "ado": _cmd_ado, "github": _cmd_github, "semgrep": _cmd_semgrep, "setup": _cmd_setup, "sctask": _cmd_sctask, "sidekick": _cmd_sidekick,
                "dojo": _cmd_scanner, "sonar": _cmd_scanner}
    handler = commands.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(0)
    sys.exit(handler(args))


if __name__ == "__main__":
    main()
