"""Analysis modes, provider/model selection, and user-message assembly."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from . import models as _models
from .agent_tools import _TOOL_TIMEOUT_S
from .agent_runner import _lmstudio_models
from .installation import _AGENTS_SRC, _CLAUDE_DIR
from .servicenow import ServiceNowError, collect_avits, requested_avits
from .skills import findings_context, findings_text
from .terminal import _bold, _red


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


_OPENAI_BASE_URL = "https://api.openai.com/v1"


_OPENAI_DEFAULT_MODEL = "gpt-5.6"


_ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1"


_RUN_PROVIDERS = ("lmstudio", "openai", "claude", "claude-code")


_API_KEY_ENV = {"openai": "OPENAI_API_KEY", "claude": "ANTHROPIC_API_KEY"}


_PROVIDER_LABEL = {"openai": "OpenAI", "claude": "Anthropic (Claude)", "claude-code": "Claude Code (your login)"}


def _default_run_model(provider: str, explicit: str | None = "") -> str:
    """Model for an analysis run: an explicit --model wins; Claude follows the scanning policy (threatlint.models)."""
    if explicit:
        return explicit
    if provider in ("claude", "claude-code"):
        return _models.scan_model()
    return _OPENAI_DEFAULT_MODEL if provider == "openai" else ""


def _resolve_agent_file(mode: str) -> tuple[str, Path] | None:
    """Bundled agent definition for ``mode``, falling back to a global Claude install."""
    agent_name = _MODE_TO_AGENT.get(mode)
    if not agent_name:
        return None
    for candidate in (_AGENTS_SRC / f"{agent_name}.md", Path.home() / _CLAUDE_DIR / "agents" / f"{agent_name}.md"):
        if candidate.exists():
            return agent_name, candidate
    return None


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
        # Fixed arguments and no shell: no external input is interpreted as a command.
        result = subprocess.run(
            ["semgrep", "--version"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT_S,
            check=False,
        )
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


def _resolve_provider(
    args: argparse.Namespace,
    *,
    list_models: Callable[[str], list[str]] | None = None,
) -> tuple[str, str, str] | None:
    """(provider, base_url, api_key), or None after printing why the provider is unusable."""
    provider = getattr(args, "provider", "lmstudio") or "lmstudio"
    api_key = getattr(args, "api_key", "") or ""
    if provider == "claude-code":
        from . import claude_code  # noqa: PLC0415
        status = claude_code.login_status()
        if not status.installed:
            print(_red("ERROR: Claude Code is not installed. Install it, run `claude` once to sign in, then retry."))
            return None
        if not status.logged_in:
            print(_red("ERROR: Claude Code is not signed in. Run `claude` in a terminal and sign in, then retry."))
            return None
        return provider, "", ""
    if provider in _API_KEY_ENV:
        api_key = api_key or os.environ.get(_API_KEY_ENV[provider], "")
        if not api_key:
            print(_red(f"ERROR: {_PROVIDER_LABEL[provider]} API key required. Pass --api-key or set {_API_KEY_ENV[provider]}."))
            return None
        return provider, _OPENAI_BASE_URL if provider == "openai" else _ANTHROPIC_BASE_URL, api_key
    base_url = args.base_url.rstrip("/")
    if not (list_models or _lmstudio_models)(base_url):
        print(_red("ERROR: LM Studio (Bionic) is not running or no model is loaded."))
        print("Open LM Studio, load a model, and start the local server")
        print("(Developer › Local Server › Start Server), then retry.")
        return None
    return provider, base_url, api_key


def _print_run_header(mode: str, provider: str, base_url: str, model: str, target: str) -> None:
    print(_bold(f"\nthreatlint run {mode}"))
    print(f"  Provider  : {_PROVIDER_LABEL.get(provider) or f'LM Studio ({base_url})'}")
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
