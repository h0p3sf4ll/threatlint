"""Queue models and the persisted JSON schema."""

from __future__ import annotations

import datetime
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class AVITStatus(str, Enum):
    """AVIT processing status in the orchestrator queue."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class AVITQueueItem:
    """An AVIT in the orchestrator queue."""

    number: str
    status: AVITStatus = AVITStatus.PENDING
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    completed_at: str | None = None
    error: str | None = None
    result: dict[str, Any] = field(default_factory=dict)
    attempts: int = 0
    max_attempts: int = 3

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dict."""
        return {**asdict(self), "status": self.status.value}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AVITQueueItem:
        """Reconstruct from JSON, ignoring unknown item fields."""
        data = dict(data)
        if isinstance(data.get("status"), str):
            data["status"] = AVITStatus(data["status"])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class OrchestratorState:
    """Persistent orchestrator state."""

    queue: list[AVITQueueItem] = field(default_factory=list)
    active_avit: str | None = None
    paused: bool = False
    total_processed: int = 0
    total_failed: int = 0
    updated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dict."""
        return {
            "queue": [item.to_dict() for item in self.queue],
            "active_avit": self.active_avit,
            "paused": self.paused,
            "total_processed": self.total_processed,
            "total_failed": self.total_failed,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OrchestratorState:
        """Reconstruct from the existing JSON schema."""
        return cls(
            queue=[AVITQueueItem.from_dict(item) for item in data.get("queue", [])],
            active_avit=data.get("active_avit"),
            paused=data.get("paused", False),
            total_processed=data.get("total_processed", 0),
            total_failed=data.get("total_failed", 0),
            updated_at=data.get("updated_at", utc_now()),
        )
