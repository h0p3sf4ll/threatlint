"""Persistence failures must not erase the last saved queue."""

import json
import logging

import pytest

from threatlint.avit_orchestrator import AVITOrchestrator, AVITQueueItem, OrchestratorState
from threatlint.avit_orchestrator import storage
from threatlint.avit_orchestrator.storage import JsonStateStore


def test_missing_state_is_empty(tmp_path):
    store = JsonStateStore(tmp_path / "state.json", logging.getLogger(__name__))
    assert store.load().queue == []


def test_atomic_replace_keeps_old_json_until_commit(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    store = JsonStateStore(path, logging.getLogger(__name__))
    old = OrchestratorState(queue=[AVITQueueItem("AVIT0000001")])
    new = OrchestratorState(queue=[AVITQueueItem("AVIT0000002")])
    store.save(old)
    replace = storage.os.replace
    seen = []

    def observe(source, target):
        assert path.read_text() == json.dumps(old.to_dict(), indent=2)
        assert json.loads(source.read_text()) == new.to_dict()
        assert source.parent == path.parent
        seen.append(target)
        replace(source, target)

    monkeypatch.setattr(storage.os, "replace", observe)
    store.save(new)
    assert seen == [path]
    assert store.load() == new
    assert list(tmp_path.iterdir()) == [path]


def test_replace_failure_is_logged_propagated_and_leaves_old_state(tmp_path, monkeypatch, caplog):
    path = tmp_path / "state.json"
    store = JsonStateStore(path, logging.getLogger(__name__))
    original = OrchestratorState(queue=[AVITQueueItem("AVIT0000001")])
    store.save(original)

    def fail(source, target):
        raise OSError("synthetic disk failure")

    monkeypatch.setattr(storage.os, "replace", fail)
    with pytest.raises(OSError, match="synthetic disk failure"):
        store.save(OrchestratorState())
    assert store.load() == original
    assert list(tmp_path.iterdir()) == [path]
    assert "Failed to save state" in caplog.text


def test_serialization_failure_preserves_old_state(tmp_path):
    path = tmp_path / "state.json"
    store = JsonStateStore(path, logging.getLogger(__name__))
    original = OrchestratorState(queue=[AVITQueueItem("AVIT0000001")])
    store.save(original)
    invalid = OrchestratorState(queue=[AVITQueueItem("AVIT0000002", result={"bad": object()})])
    with pytest.raises(TypeError):
        store.save(invalid)
    assert store.load() == original
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("contents", [
    "{broken", "[]", '{"queue": null}', '{"queue": [{"status": "invalid"}]}',
])
def test_bad_existing_state_is_not_silently_discarded(tmp_path, caplog, contents):
    path = tmp_path / "state.json"
    path.write_text(contents)
    with pytest.raises((ValueError, TypeError)):
        AVITOrchestrator(tmp_path)
    assert path.read_text() == contents
    assert "Failed to load state" in caplog.text


def test_injected_store_does_not_create_directories(tmp_path):
    class MemoryStore:
        def __init__(self):
            self.payload = OrchestratorState().to_dict()
            self.saves = 0

        def load(self):
            return OrchestratorState.from_dict(self.payload)

        def save(self, state):
            self.payload = state.to_dict()
            self.saves += 1

    store = MemoryStore()
    unused = tmp_path / "not-created"
    orch = AVITOrchestrator(unused, store=store)
    orch.add_avit("AVIT0000001")
    orch.pause()
    assert store.saves == 2
    assert AVITOrchestrator(unused, store=store).is_paused()
    assert not unused.exists()
