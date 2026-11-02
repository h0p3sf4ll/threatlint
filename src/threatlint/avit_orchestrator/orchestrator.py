"""Queue lifecycle and synchronization, independent of presentation."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Awaitable, Callable

from . import execution
from .models import AVITQueueItem, AVITStatus, OrchestratorState, utc_now
from .storage import JsonStateStore, StateStore


class AVITOrchestrator:
    """Manage AVIT queue state and delegate persistence and execution."""

    def __init__(
        self,
        state_dir: Path | str | None = None,
        logger: logging.Logger | None = None,
        *,
        store: StateStore | None = None,
    ):
        self.state_dir = Path(state_dir) if state_dir is not None else (
            Path.home() / ".threatlint" / "avit_orchestrator"
        )
        self.queue_file = self.state_dir / "queue.json"
        self.state_file = self.state_dir / "state.json"
        self.log = logger or logging.getLogger("threatlint.avit_orchestrator")
        if store is None:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            store = JsonStateStore(self.state_file, self.log)
        self._store = store
        self._lock = threading.RLock()
        self._state = self._load_state()

    def _load_state(self) -> OrchestratorState:
        return self._store.load()

    def _save_state(self) -> None:
        self._state.updated_at = utc_now()
        self._store.save(self._state)

    def add_avit(self, number: str) -> AVITQueueItem:
        """Add an item unless that number already has an unfinished entry."""
        with self._lock:
            for item in self._state.queue:
                if item.number == number and item.status != AVITStatus.COMPLETED:
                    self.log.info("AVIT %s already in queue with status %s", number, item.status.value)
                    return item
            item = AVITQueueItem(number=number)
            self._state.queue.append(item)
            self._save_state()
            self.log.info("Added %s to queue", number)
            return item

    def add_avits(self, numbers: list[str]) -> list[AVITQueueItem]:
        """Add multiple AVITs to the queue."""
        return [self.add_avit(number) for number in numbers]

    def get_next_pending(self) -> AVITQueueItem | None:
        """Peek at the next eligible item without claiming it."""
        with self._lock:
            if self._state.paused:
                return None
            return next((
                item for item in self._state.queue
                if item.status == AVITStatus.PENDING and item.attempts < item.max_attempts
            ), None)

    def update_avit(
        self,
        number: str,
        status: AVITStatus | None = None,
        error: str | None = None,
        result: dict[str, Any] | None = None,
    ) -> AVITQueueItem | None:
        """Update an item's status, metadata and aggregate counters."""
        with self._lock:
            for item in self._state.queue:
                if item.number == number:
                    return self.update_item(item, status, error, result)
            return None

    def update_item(
        self,
        item: AVITQueueItem,
        status: AVITStatus | None = None,
        error: str | None = None,
        result: dict[str, Any] | None = None,
    ) -> AVITQueueItem:
        """Update an exact entry, leaving requeued-number history untouched."""
        with self._lock:
            if not any(queued is item for queued in self._state.queue):
                raise ValueError("Item does not belong to this orchestrator queue")
            if status:
                item.status = status
                if status == AVITStatus.IN_PROGRESS:
                    if not item.started_at:
                        item.started_at = utc_now()
                elif status == AVITStatus.COMPLETED:
                    item.completed_at = utc_now()
                    self._state.total_processed += 1
                elif status == AVITStatus.FAILED:
                    self._state.total_failed += 1
                    item.attempts += 1
                self._state.active_avit = next((
                    queued.number for queued in self._state.queue
                    if queued.status == AVITStatus.IN_PROGRESS
                ), None)
            if error:
                item.error = error
            if result:
                item.result = result
            self._save_state()
            return item

    def claim_pending(self, item: AVITQueueItem) -> bool:
        """Atomically check eligibility and persist the claim before execution."""
        with self._lock:
            if (
                self._state.paused
                or item.status != AVITStatus.PENDING
                or item.attempts >= item.max_attempts
                or not any(queued is item for queued in self._state.queue)
            ):
                return False
            self.update_item(item, status=AVITStatus.IN_PROGRESS)
            return True

    def get_avit(self, number: str) -> AVITQueueItem | None:
        """Get the first queue entry matching a number."""
        with self._lock:
            return next((item for item in self._state.queue if item.number == number), None)

    def list_queue(self, status: AVITStatus | None = None) -> list[AVITQueueItem]:
        """Return a queue snapshot, optionally filtered by status."""
        with self._lock:
            return [
                item for item in self._state.queue
                if status is None or item.status == status
            ]

    def remove_avit(self, number: str) -> bool:
        """Remove all entries for a number, returning whether any were removed."""
        with self._lock:
            original_len = len(self._state.queue)
            self._state.queue = [item for item in self._state.queue if item.number != number]
            if len(self._state.queue) < original_len:
                self._save_state()
                return True
            return False

    def clear_queue(self) -> int:
        """Remove entries other than completed/failed, preserving legacy behavior."""
        with self._lock:
            original_len = len(self._state.queue)
            self._state.queue = [
                item for item in self._state.queue
                if item.status in (AVITStatus.COMPLETED, AVITStatus.FAILED)
            ]
            count = original_len - len(self._state.queue)
            if count:
                self._save_state()
            return count

    def get_stats(self) -> dict[str, Any]:
        """Return queue status counts and lifetime processing counters."""
        with self._lock:
            return {
                "total_items": len(self._state.queue),
                "by_status": {status.value: len(self.list_queue(status)) for status in AVITStatus},
                "active_avit": self._state.active_avit,
                "paused": self._state.paused,
                "total_processed": self._state.total_processed,
                "total_failed": self._state.total_failed,
            }

    def pause(self) -> None:
        """Persistently pause processing."""
        with self._lock:
            self._state.paused = True
            self._save_state()
            self.log.info("Orchestrator paused")

    def resume(self) -> None:
        """Persistently resume processing."""
        with self._lock:
            self._state.paused = False
            self._save_state()
            self.log.info("Orchestrator resumed")

    def is_paused(self) -> bool:
        with self._lock:
            return self._state.paused

    async def process_batch(
        self,
        handler: Callable[[AVITQueueItem], Awaitable[bool]],
        max_concurrent: int = 1,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> dict[str, int]:
        """Process a pending snapshot with bounded concurrent async handlers."""
        return await execution.process_batch(self, handler, max_concurrent, on_progress)

    def run_canary(
        self,
        handler: Callable[[AVITQueueItem], bool],
        canary_size: int = 10,
    ) -> dict[str, Any]:
        """Process a small synchronous batch before a full run."""
        return execution.run_canary(self, handler, canary_size)
