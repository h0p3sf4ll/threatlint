"""Bounded read-only repository inspection tools for model-driven analysis."""

from __future__ import annotations

import glob as _glob_module
import os
import shlex
import subprocess
from pathlib import Path


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


_MAX_READ_BYTES = 2 * 1024 * 1024
_MAX_READ_LINES = 2000
_MAX_TOOL_OUTPUT = 8000
_MAX_GLOB_RESULTS = 500
_TOOL_TIMEOUT_S = 30
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


_TOOL_HANDLERS = {
    "Read": lambda root, a: _tool_read(root, str(a.get("file_path", "")), _int_arg(a, "offset", 0), _int_arg(a, "limit", _MAX_READ_LINES)),
    "Bash": lambda root, a: _tool_bash(root, str(a.get("command", ""))),
    "Grep": lambda root, a: _tool_grep(root, str(a.get("pattern", "")), str(a.get("path", ".")), str(a.get("flags", "-rn"))),
    "Glob": lambda root, a: _tool_glob(root, str(a.get("pattern", ""))),
}


def _execute_tool(repo_root: str, name: str, args: dict) -> str:
    handler = _TOOL_HANDLERS.get(name)
    return handler(repo_root, args) if handler else f"Unknown tool: {name}"
