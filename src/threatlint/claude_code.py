"""Claude Code provider: run an agent through the user's own Claude Code login (``claude -p``) instead of an API key.

Threatlint never reads or handles the login: it starts the installed ``claude`` CLI, which authenticates itself.
The repository under review is untrusted, so every run is locked down (mirrors web/lib/claude-code.cjs):

  --restricted              no command- or code-running tools; user, project, and local settings files are ignored
                            (a scanned repo's .claude/settings.json hooks never run); file tools stay inside cwd
  --tools Read,Grep,Glob    the only tools available, so nothing can be written
  --strict-mcp-config       no MCP servers
  --permission-mode dontAsk anything not allowed is denied instead of prompting
  --no-session-persistence  nothing is saved to Claude Code's session history

API keys, provider route flags, and endpoint overrides are removed from the child environment so this provider
uses the Claude Code subscription login even when the parent shell is configured for Bedrock, Mantle, Vertex, or Foundry.
Global settings cannot reintroduce provider/auth/endpoint overrides into a run because --restricted ignores settings files.
CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST is never set: it tells the CLI the host owns authentication, so it ignores the user's claude.ai login.
CLAUDE_CODE_OAUTH_TOKEN and normal operating-system, proxy, and certificate settings are preserved.
The system prompt goes through a 0600 temp file and the user message through stdin, so neither appears in argv.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

READ_ONLY_TOOLS = ("Read", "Grep", "Glob")
STRIPPED_ENV = (
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_MANTLE", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY", "CLAUDE_CODE_USE_ANTHROPIC_AWS",
    "AWS_BEARER_TOKEN_BEDROCK", "BEDROCK_API_KEY", "AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "AWS_ENDPOINT_URL_BEDROCK_MANTLE",
)
STATUS_TIMEOUT_S = 15
RUN_TIMEOUT_S = int(os.environ.get("THREATLINT_CLAUDE_CODE_TIMEOUT_S", str(60 * 60)))


class ClaudeCodeError(RuntimeError):
    """A user-actionable failure (not installed, not signed in, or the run failed)."""


@dataclass(frozen=True)
class LoginStatus:
    installed: bool
    logged_in: bool = False
    auth_method: str = ""

    @property
    def label(self) -> str:
        return f"Claude Code login ({self.auth_method or 'signed in'})"


def executable() -> str | None:
    """The ``claude`` CLI: PATH first, then the installer's usual locations."""
    home = Path.home()
    return shutil.which("claude") or next(
        (str(path) for path in (home / ".local/bin/claude", home / ".claude/local/claude", Path("/opt/homebrew/bin/claude"),
                                Path("/usr/local/bin/claude")) if path.is_file() and os.access(path, os.X_OK)), None)


def child_env(env: dict[str, str] | None = None) -> dict[str, str]:
    # Never pass CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST: with it the CLI ignores the user's claude.ai login. Settings-file
    # overrides are already excluded from runs by --restricted.
    dropped = {*STRIPPED_ENV, "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST"}
    return {name: value for name, value in (env if env is not None else os.environ).items() if name not in dropped}


def login_status(claude: str | None = None) -> LoginStatus:
    """Whether Claude Code is installed and signed in, from ``claude auth status`` (never raises)."""
    claude = claude or executable()
    if not claude:
        return LoginStatus(installed=False)
    try:
        result = subprocess.run([claude, "auth", "status"], capture_output=True, text=True, timeout=STATUS_TIMEOUT_S, check=False, env=child_env())
        payload = json.loads(result.stdout or "{}")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return LoginStatus(installed=True)
    return LoginStatus(installed=True, logged_in=payload.get("loggedIn") is True, auth_method=str(payload.get("authMethod") or ""))


def command(claude: str, model: str, system_prompt_file: str, extra_dirs: Iterable[str] = ()) -> list[str]:
    """argv for one locked-down headless run; ``extra_dirs`` are added read-only for the file tools."""
    return [claude, "-p", "--output-format", "stream-json", "--verbose", "--restricted", "--tools", ",".join(READ_ONLY_TOOLS),
            "--strict-mcp-config", "--permission-mode", "dontAsk", "--no-session-persistence",
            "--system-prompt-file", system_prompt_file, *(arg for directory in extra_dirs for arg in ("--add-dir", directory)),
            *(["--model", model] if model else [])]


def _describe(tool: dict) -> str:
    """'Grep(pattern='app.get')' for the progress line; values are clipped."""
    arguments = ", ".join(f"{key}={str(value)[:40]!r}" for key, value in list((tool.get("input") or {}).items())[:2])
    return f"{tool.get('name', 'tool')}({arguments})"


def _events(lines: Iterable[str]):
    for line in lines:
        try:
            yield json.loads(line)
        except ValueError:
            continue


def run_agent(system_prompt: str, user_message: str, repo_root: str, model: str = "", *, images=(),
              claude: str | None = None, progress: Callable[[str], None] = lambda line: print(line, flush=True),
              popen: Callable[..., subprocess.Popen] = subprocess.Popen) -> str:
    """Run one agent in ``repo_root`` and return its final report text."""
    claude = claude or executable()
    if not claude:
        raise ClaudeCodeError("Claude Code is not installed. Install it (https://claude.com/claude-code), run `claude` once to sign in, then retry.")
    with tempfile.TemporaryDirectory(prefix="threatlint-claude-code-") as temp:
        prompt_file = Path(temp, "system-prompt.md")
        prompt_file.touch(mode=0o600)
        prompt_file.write_text(system_prompt, encoding="utf-8")
        # Images become files in their own directory, added with --add-dir so the restricted Read tool may open them.
        image_dir = Path(temp, "images")
        image_paths = []
        for index, image in enumerate(images, start=1):
            image_dir.mkdir(mode=0o700, exist_ok=True)
            target = image_dir / f"{index}-{re.sub(r'[^\w.-]', '_', Path(image.name).name)}"
            target.write_bytes(base64.b64decode(image.data))
            target.chmod(0o600)
            image_paths.append(target)
        if image_paths:
            user_message += "\n\nImage files (open each with the Read tool):\n" + "\n".join(f"{n}. {path}" for n, path in enumerate(image_paths, 1))
        # stderr goes to a file: a full stderr pipe would block the child while stdout is still being read.
        errors = Path(temp, "stderr.log").open("w+", encoding="utf-8")
        process = popen(command(claude, model, str(prompt_file), [str(image_dir)] if image_paths else ()), cwd=repo_root, env=child_env(), text=True,
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
        process.stdin.write(user_message)
        process.stdin.close()
        result: dict = {}
        try:
            for event in _events(process.stdout):
                if event.get("type") == "assistant":
                    for block in (event.get("message") or {}).get("content") or []:
                        if block.get("type") == "tool_use":
                            progress(f"  → {_describe(block)}")
                elif event.get("type") == "result":
                    result = event
            process.wait(timeout=RUN_TIMEOUT_S)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            raise ClaudeCodeError(f"Claude Code did not finish within {RUN_TIMEOUT_S // 60} minutes") from exc
        errors.seek(0)
        stderr = errors.read()
        errors.close()
    if result.get("subtype") == "success" and not result.get("is_error"):
        return str(result.get("result") or "")
    reason = str(result.get("result") or (stderr.strip().splitlines() or [f"exit code {process.returncode}"])[-1])[:300]
    hint = " Run `claude` in a terminal to sign in, then retry." if any(word in reason.lower() for word in ("login", "log in", "auth", "credential", "unauthorized")) else ""
    raise ClaudeCodeError(f"Claude Code run failed: {reason}.{hint}")
