"""Ordered, bounded work admission shared by read-only tools and CLI reviews."""

from __future__ import annotations

import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def run_bounded(items: Iterable[T], execute: Callable[[T], R], workers: int,
                cancel: threading.Event | None = None) -> list[R]:
    """Stop admission on failure/cancellation; signal cooperative work and join all peers."""
    if isinstance(workers, bool) or not isinstance(workers, int) or not 1 <= workers <= 16:
        raise ValueError("workers must be an integer from 1 to 16")
    items = list(items)
    stop = cancel if cancel is not None else threading.Event()
    results = [None] * len(items)
    cursor = 0
    if stop.is_set():
        raise RuntimeError("Cancelled before starting")
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(items)), thread_name_prefix="threatlint-work") as pool:
        pending = {}
        try:
            while cursor < len(items) or pending:
                if stop.is_set():
                    raise RuntimeError("Cancelled")
                while cursor < len(items) and len(pending) < workers:
                    if stop.is_set():
                        raise RuntimeError("Cancelled")
                    pending[pool.submit(execute, items[cursor])] = cursor
                    cursor += 1
                completed, _ = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
                for future in completed:
                    results[pending.pop(future)] = future.result()
        except BaseException:
            stop.set()
            for future in pending:
                future.cancel()
            raise
    return results
