"""threatlint CLI — install AppSec agents into Claude Code / project directories."""

from __future__ import annotations

import argparse
import datetime
import glob as _glob_module
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
    "compliance-check":  "appsec-compliance-checker",
    "attack-tree":       "appsec-attack-tree",
    "red-team":          "appsec-red-team",
    "threat-delta":      "appsec-threat-delta",
    "verify-fix":        "appsec-verify-fix",
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
        "description": "Run a read-only shell command. Permitted: git, find, grep, cat, head, tail, wc, ls, sort, uniq, awk, cut, jq.",
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

_BASH_ALLOWED = ("git ", "find ", "grep ", "cat ", "head ", "tail ",
                 "wc ", "ls ", "sort ", "uniq ", "awk ", "cut ", "jq ")


def _tool_read(repo_root: str, file_path: str, offset: int = 0, limit: int = 2000) -> str:
    if not os.path.isabs(file_path):
        file_path = os.path.join(repo_root, file_path)
    try:
        with open(file_path, "r", errors="replace") as fh:
            lines = fh.readlines()
        chunk = lines[offset: offset + limit]
        return "".join(f"{i + offset + 1}\t{l}" for i, l in enumerate(chunk))
    except Exception as exc:
        return f"Error: {exc}"


def _tool_bash(repo_root: str, command: str) -> str:
    if not any(command.strip().startswith(p) for p in _BASH_ALLOWED):
        return "Error: command not permitted — only read-only tools allowed"
    try:
        r = subprocess.run(command, shell=True, capture_output=True,
                           text=True, cwd=repo_root, timeout=30)
        return (r.stdout + r.stderr)[:8000]
    except subprocess.TimeoutExpired:
        return "Error: command timed out"
    except Exception as exc:
        return f"Error: {exc}"


def _tool_grep(repo_root: str, pattern: str, path: str = ".", flags: str = "-rn") -> str:
    search = path if os.path.isabs(path) else os.path.join(repo_root, path)
    cmd = f"grep {flags} {shlex.quote(pattern)} {shlex.quote(search)}"
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, cwd=repo_root, timeout=30)
        return (r.stdout + r.stderr)[:8000]
    except Exception as exc:
        return f"Error: {exc}"


def _tool_glob(repo_root: str, pattern: str) -> str:
    matches = _glob_module.glob(os.path.join(repo_root, pattern), recursive=True)
    rel = [os.path.relpath(m, repo_root) for m in sorted(matches)[:500]]
    return "\n".join(rel) if rel else "(no matches)"


def _execute_tool(repo_root: str, name: str, args: dict) -> str:
    if name == "Read":
        return _tool_read(repo_root, args.get("file_path", ""),
                          int(args.get("offset", 0)), int(args.get("limit", 2000)))
    if name == "Bash":
        return _tool_bash(repo_root, args.get("command", ""))
    if name == "Grep":
        return _tool_grep(repo_root, args.get("pattern", ""),
                          args.get("path", "."), args.get("flags", "-rn"))
    if name == "Glob":
        return _tool_glob(repo_root, args.get("pattern", ""))
    return f"Unknown tool: {name}"

# ── LM Studio agent runner ────────────────────────────────────────────────────

def _lmstudio_auto_model(base_url: str) -> str:
    import urllib.request as _req
    try:
        with _req.urlopen(f"{base_url}/models", timeout=5) as resp:
            data = _json.loads(resp.read())
        models = [m["id"] for m in data.get("data", [])]
        return models[0] if models else ""
    except Exception:
        return ""


def _run_agent(base_url: str, model: str, system_prompt: str,
               user_message: str, repo_root: str, api_key: str = "") -> str:
    """Stream a full tool-use agentic loop against an OpenAI-compatible server. Returns output text."""
    import urllib.request as _req

    if not model:
        model = _lmstudio_auto_model(base_url)

    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]
    full_text = ""

    for _iteration in range(80):
        body = _json.dumps({
            "model": model, "messages": messages,
            "tools": _TOOLS, "stream": True, "max_tokens": 16000,
        }).encode()
        hdrs = {"Content-Type": "application/json"}
        if api_key:
            hdrs["Authorization"] = f"Bearer {api_key}"
        req = _req.Request(
            f"{base_url}/chat/completions", data=body,
            headers=hdrs,
        )

        iter_text = ""
        tc_map: dict[int, dict] = {}
        finish_reason = "stop"

        try:
            with _req.urlopen(req, timeout=600) as resp:
                buf = ""
                for raw in resp:
                    buf += raw.decode("utf-8", errors="replace")
                    lines = buf.split("\n")
                    buf = lines[-1]
                    for line in lines[:-1]:
                        if not line.startswith("data: "):
                            continue
                        data = line[6:].strip()
                        if data == "[DONE]":
                            break
                        try:
                            p = _json.loads(data)
                            choice = p.get("choices", [{}])[0]
                            if choice.get("finish_reason"):
                                finish_reason = choice["finish_reason"]
                            delta = choice.get("delta", {})
                            if delta.get("content"):
                                iter_text += delta["content"]
                                print(delta["content"], end="", flush=True)
                            for tc in delta.get("tool_calls", []):
                                idx = tc.get("index", 0)
                                if idx not in tc_map:
                                    tc_map[idx] = {"id": tc.get("id", f"call_{idx}"), "name": "", "args": ""}
                                if tc.get("id"):
                                    tc_map[idx]["id"] = tc["id"]
                                fn = tc.get("function", {})
                                if fn.get("name"):
                                    tc_map[idx]["name"] += fn["name"]
                                if fn.get("arguments"):
                                    tc_map[idx]["args"] += fn["arguments"]
                        except (_json.JSONDecodeError, IndexError, KeyError):
                            pass
        except Exception as exc:
            raise RuntimeError(f"LM Studio request failed: {exc}") from exc

        full_text += iter_text
        assistant_msg: dict = {"role": "assistant", "content": iter_text or None}
        if tc_map:
            assistant_msg["tool_calls"] = [
                {"id": tc["id"], "type": "function",
                 "function": {"name": tc["name"], "arguments": tc["args"]}}
                for tc in tc_map.values()
            ]
        messages.append(assistant_msg)

        if finish_reason != "tool_calls" or not tc_map:
            break

        if iter_text:
            print()

        for tc in tc_map.values():
            try:
                args = _json.loads(tc["args"] or "{}")
            except _json.JSONDecodeError:
                args = {}
            short = ", ".join(f"{k}={repr(v)[:40]}" for k, v in list(args.items())[:2])
            print(f"  → {tc['name']}({short})", flush=True)
            result = _execute_tool(repo_root, tc["name"], args)
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": str(result)})

    return full_text


# ── Commands ──────────────────────────────────────────────────────────────────

def _cmd_install_lmstudio(args: argparse.Namespace) -> int:
    """Install all agents to ~/.lmstudio/agents/ as SKILL.md files."""
    dst = Path.home() / ".lmstudio" / "agents"

    print(_bold("\nthreatlint install --lmstudio"))
    print(f"  Destination : {dst}")
    print(f"  Agents      : {len(list(_AGENTS_SRC.iterdir()))} files")
    print()

    if not args.yes and not _confirm("Proceed?"):
        print("Aborted.")
        return 1

    dst.mkdir(parents=True, exist_ok=True)
    count = 0

    for agent_file in sorted(_AGENTS_SRC.iterdir()):
        if not agent_file.suffix == ".md":
            continue

        raw = agent_file.read_text(encoding="utf-8", errors="replace")
        m = re.match(r"^---\n(.*?)\n---\n(.*)", raw, re.DOTALL)
        if not m:
            continue

        name = description = ""
        for line in m.group(1).split("\n"):
            c = line.find(":")
            if c > 0:
                k, v = line[:c].strip(), line[c + 1:].strip()
                if k == "name":
                    name = v
                elif k == "description":
                    description = v

        name = name or agent_file.stem
        body = m.group(2).strip()
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
    """Run an AppSec analysis via a local or cloud LLM."""
    import os as _os

    provider = getattr(args, "provider", "lmstudio") or "lmstudio"
    api_key = getattr(args, "api_key", "") or ""

    if provider == "openai":
        if not api_key:
            api_key = _os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            print(_red("ERROR: OpenAI API key required. Pass --api-key or set OPENAI_API_KEY."))
            return 1
        base_url = "https://api.openai.com/v1"
    else:
        base_url = args.base_url.rstrip("/")

    mode = args.mode

    # For local LM Studio, verify the server is reachable
    if provider == "lmstudio":
        probe = subprocess.run(
            ["curl", "-sf", f"{base_url}/models"],
            capture_output=True, text=True,
        )
        if probe.returncode != 0 or not probe.stdout.strip() or probe.stdout.strip() == "{}":
            print(_red("ERROR: LM Studio (Bionic) is not running or no model is loaded."))
            print("Open LM Studio, load a model, and start the local server")
            print("(Developer › Local Server › Start Server), then retry.")
            return 1

    # Load agent system prompt from the installed agent file
    agent_name = _MODE_TO_AGENT.get(mode)
    agent_file: Path | None = None
    if agent_name:
        agent_file = _AGENTS_SRC / f"{agent_name}.md"
        if not agent_file.exists():
            agent_file = Path.home() / ".claude" / "agents" / f"{agent_name}.md"
        if not agent_file.exists():
            agent_file = None

    if agent_file is None:
        print(_red(f"ERROR: Agent file not found for mode '{mode}'."))
        print("Run `threatlint install` to install the agent files.")
        return 1

    raw = agent_file.read_text(encoding="utf-8", errors="replace")
    m = re.match(r"^---\n.*?\n---\n(.*)", raw, re.DOTALL)
    system_prompt = m.group(1).strip() if m else raw.strip()

    # Resolve repo root and build user message
    repo_root_result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True,
    )
    repo_root = repo_root_result.stdout.strip() or str(Path.cwd())

    target = getattr(args, "target", "") or ""
    deep = getattr(args, "deep", False) or (mode == "threat-model-deep")

    user_msg = f"The repository to analyze is located at: {repo_root}\n"
    if target:
        user_msg += f"\nFocus area / target: {target}\n"
    if deep:
        user_msg += "\nPerform a thorough, deep-dive analysis.\n"
    user_msg += "\nBegin your full analysis now and produce the complete report as specified in your instructions."

    # Build output filename
    repo_name = Path(repo_root).name.lower().replace(" ", "-")
    branch_result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True,
    )
    branch = (branch_result.stdout.strip() or "no-branch").lower().replace("/", "-")
    today = datetime.date.today().strftime("%Y-%m-%d")
    base_name = f"{repo_name}-{branch}-{mode}-local-{today}"

    model = getattr(args, "model", "") or ""

    print(_bold(f"\nthreatlint run {mode}"))
    provider_label = "OpenAI" if provider == "openai" else f"LM Studio ({base_url})"
    print(f"  Provider  : {provider_label}")
    if model:
        print(f"  Model     : {model}")
    if target:
        print(f"  Target    : {target}")
    print()

    # Run the agent loop
    try:
        output = _run_agent(base_url, model, system_prompt, user_msg, repo_root, api_key=api_key)
    except RuntimeError as exc:
        print(_red(f"\nERROR: {exc}"))
        return 1

    if not output.strip():
        print(_red("\nERROR: Agent produced no output."))
        return 1

    print()

    # Save output — prefer .docx, fall back to .md
    out_dir = Path(getattr(args, "output_dir", None) or repo_root)
    out_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(suffix=".md", delete=False, prefix=f"{mode}_") as tf:
        tf.write(output.encode())
        tmp_md = tf.name

    docx_script = _SCRIPTS_SRC / "md_to_docx.py"
    if not docx_script.exists():
        docx_script = Path.home() / ".claude" / "scripts" / "md_to_docx.py"

    out_docx = out_dir / f"{base_name}.docx"
    if docx_script.exists():
        r = subprocess.run([sys.executable, str(docx_script), tmp_md, str(out_docx)])
        if r.returncode == 0:
            Path(tmp_md).unlink(missing_ok=True)
            print(_green(f"✓ Report saved to {out_docx}"))
            return 0

    out_md = out_dir / f"{base_name}.md"
    Path(tmp_md).rename(out_md)
    print(_green(f"✓ Report saved to {out_md}"))
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
    p_install.add_argument("--lmstudio", action="store_true",
        help="Install agents to ~/.lmstudio/agents/ for use in Bionic / LM Studio")
    p_install.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    p_install.add_argument("-q", "--quiet", action="store_true", help="Suppress file-by-file output")

    # run
    _MODES = [
        "threat-model", "threat-model-deep", "security-review",
        "secrets-scan", "iac-review", "cicd-audit",
        "dependency-audit", "api-security", "auth-review",
        "compliance-check", "attack-tree", "red-team",
        "threat-delta", "verify-fix",
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
