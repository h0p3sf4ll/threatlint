"""Canary and async batch execution policies."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from .models import AVITQueueItem, AVITStatus

if TYPE_CHECKING:
    from .orchestrator import AVITOrchestrator


async def process_batch(
    orchestrator: AVITOrchestrator,
    handler: Callable[[AVITQueueItem], Awaitable[bool]],
    max_concurrent: int,
    on_progress: Callable[[int, int], None] | None,
) -> dict[str, int]:
    if max_concurrent <= 0:
        raise ValueError("max_concurrent must be positive")
    pending = orchestrator.list_queue(AVITStatus.PENDING)
    total = len(pending)
    results = {"success": 0, "failed": 0, "skipped": 0}
    semaphore = asyncio.Semaphore(max_concurrent)

    async def process_one(item: AVITQueueItem) -> None:
        async with semaphore:
            if not orchestrator.claim_pending(item):
                results["skipped"] += 1
            else:
                error_message = None
                try:
                    succeeded = bool(await handler(item))
                except asyncio.CancelledError:
                    orchestrator.update_item(item, status=AVITStatus.PENDING)
                    raise
                except Exception as error:
                    orchestrator.log.exception("Handler failed for %s", item.number)
                    succeeded = False
                    error_message = str(error)
                _record_outcome(orchestrator, item, succeeded, error_message)
                results["success" if succeeded else "failed"] += 1
            if on_progress:
                on_progress(sum(results.values()), total)

    tasks = [asyncio.create_task(process_one(item)) for item in pending]
    try:
        await asyncio.gather(*tasks)
    except BaseException:
        # Do not let sibling handlers outlive a failed or cancelled batch.
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    return results


def run_canary(
    orchestrator: AVITOrchestrator,
    handler: Callable[[AVITQueueItem], bool],
    canary_size: int,
) -> dict[str, Any]:
    if canary_size <= 0:
        raise ValueError("canary_size must be positive")
    pending = orchestrator.list_queue(AVITStatus.PENDING)
    canary_items = pending[:canary_size]
    if not canary_items:
        return {
            "status": "no_items", "message": "No pending AVITs to canary",
            "total": 0, "processed": 0, "success": 0, "failed": 0,
            "success_rate": 0.0, "ready_for_full_run": False,
        }

    orchestrator.log.info("Starting canary with %s items", len(canary_items))
    success = failed = 0
    for item in canary_items:
        if not orchestrator.claim_pending(item):
            continue
        error_message = None
        try:
            succeeded = bool(handler(item))
        except Exception as error:
            orchestrator.log.exception("Handler failed for %s", item.number)
            succeeded = False
            error_message = str(error)
        _record_outcome(orchestrator, item, succeeded, error_message)
        if succeeded:
            success += 1
        else:
            failed += 1
    success_rate = success / len(canary_items) * 100
    ready = (
        success_rate >= 80
        and success + failed == len(canary_items)
        and not orchestrator.is_paused()
    )
    return {
        "status": "success" if ready else "degraded",
        "total": len(canary_items), "success": success, "failed": failed,
        "success_rate": success_rate, "ready_for_full_run": ready,
    }


def _record_outcome(
    orchestrator: AVITOrchestrator,
    item: AVITQueueItem,
    succeeded: bool,
    error_message: str | None,
) -> None:
    # Keep persistence failures outside the handler exception boundary.
    orchestrator.update_item(
        item,
        status=AVITStatus.COMPLETED if succeeded else AVITStatus.FAILED,
        error=None if succeeded else (
            error_message if error_message is not None else "Handler returned False"
        ),
    )
