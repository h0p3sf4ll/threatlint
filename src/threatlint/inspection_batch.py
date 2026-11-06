"""Bounded parallel execution of independent, read-only calls from one model turn.

Providers remain sequential between turns. Tool identities and result order are
preserved, all inputs are checked before dispatch, and running workers are joined
before an error escapes. Native coding clients own their own tool scheduling.
"""

from __future__ import annotations

import os
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Callable

from .agent_tools import _TOOLS

MAX_TOOL_CALLS = 64
TOOL_NAMES = frozenset(tool["function"]["name"] for tool in _TOOLS)


def run_inspections(calls: list[tuple[str, str, dict]], repo_root: str,
                    execute: Callable, progress: Callable[[str], None]) -> list[str]:
    """Return results in request order, bounded by THREATLINT_TOOL_CONCURRENCY (1–16, default 4)."""
    try:
        concurrency = int(os.environ.get("THREATLINT_TOOL_CONCURRENCY", "4"))
    except ValueError:
        raise RuntimeError("THREATLINT_TOOL_CONCURRENCY must be an integer from 1 to 16") from None
    if not 1 <= concurrency <= 16:
        raise RuntimeError("THREATLINT_TOOL_CONCURRENCY must be an integer from 1 to 16")
    if len(calls) > MAX_TOOL_CALLS:
        raise RuntimeError("Model requested too many inspection tools in one turn")
    ids = set()
    for call_id, name, arguments in calls:
        if (not isinstance(call_id, str) or not call_id or call_id in ids
                or name not in TOOL_NAMES or not isinstance(arguments, dict)):
            raise RuntimeError("Model returned an invalid inspection tool call")
        ids.add(call_id)
    if not calls:
        return []
    results = [""] * len(calls)
    cursor = 0
    with ThreadPoolExecutor(max_workers=min(concurrency, len(calls)), thread_name_prefix="threatlint-inspect") as pool:
        pending = {}
        try:
            while cursor < len(calls) or pending:
                while cursor < len(calls) and len(pending) < concurrency:
                    _, name, arguments = calls[cursor]
                    progress(f"\n  → {name}\n")
                    pending[pool.submit(execute, repo_root, name, arguments)] = cursor
                    cursor += 1
                completed, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in completed:
                    results[pending.pop(future)] = str(future.result())
        except BaseException:
            for future in pending:
                future.cancel()
            raise
    return results
