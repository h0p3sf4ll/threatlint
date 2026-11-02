"""Persistence boundary for orchestrator state."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Protocol

from .models import OrchestratorState


class StateStore(Protocol):
    """Storage contract; tests can provide an in-memory implementation."""

    def load(self) -> OrchestratorState: ...

    def save(self, state: OrchestratorState) -> None: ...


class JsonStateStore:
    """Read and write the existing state.json format."""

    def __init__(self, path: Path, logger: logging.Logger):
        self.path = path
        self.log = logger

    def load(self) -> OrchestratorState:
        try:
            with self.path.open(encoding="utf-8") as stream:
                data = json.load(stream)
            if not isinstance(data, dict):
                raise ValueError("Orchestrator state must be a JSON object")
            return OrchestratorState.from_dict(data)
        except FileNotFoundError:
            return OrchestratorState()
        except (OSError, ValueError, TypeError) as error:
            self.log.error("Failed to load state from %s: %s", self.path, error)
            raise

    def save(self, state: OrchestratorState) -> None:
        """Replace state atomically; never truncate the last valid snapshot."""
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.path.parent,
                prefix=f".{self.path.name}.", suffix=".tmp", delete=False,
            ) as stream:
                stream.flush()
                temporary = Path(stream.name)
                json.dump(state.to_dict(), stream, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except (OSError, ValueError, TypeError) as error:
            self.log.error("Failed to save state to %s: %s", self.path, error)
            raise
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
