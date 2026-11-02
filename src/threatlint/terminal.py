"""Terminal presentation and confirmation shared by CLI commands."""

from __future__ import annotations

import sys


def _green(s: str) -> str:
    return f"\033[32m{s}\033[0m" if sys.stdout.isatty() else s


def _yellow(s: str) -> str:
    return f"\033[33m{s}\033[0m" if sys.stdout.isatty() else s


def _red(s: str) -> str:
    return f"\033[31m{s}\033[0m" if sys.stdout.isatty() else s


def _bold(s: str) -> str:
    return f"\033[1m{s}\033[0m" if sys.stdout.isatty() else s


def _confirm(prompt: str) -> bool:
    try:
        ans = input(f"{prompt} [y/N] ").strip().lower()
        return ans in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        print()
        return False
