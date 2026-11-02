"""Compatibility tests for the public orchestrator API and persisted schema."""

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from threatlint.avit_orchestrator import (
    AVITOrchestrator,
    AVITQueueItem,
    AVITStatus,
    OrchestratorState,
)


def test_models_round_trip_with_legacy_fields():
    item = AVITQueueItem("AVIT0000001", status=AVITStatus.FAILED, attempts=2)
    state = OrchestratorState(queue=[item], paused=True, total_failed=2)
    payload = json.loads(json.dumps(state.to_dict()))
    payload["queue"][0]["future_field"] = "ignored"
    assert OrchestratorState.from_dict(payload) == state
    assert payload["queue"][0]["status"] == "failed"


def test_queue_deduplication_lookup_and_filtering(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    first, second = orch.add_avits(["AVIT0000001", "AVIT0000002"])
    assert orch.add_avit(first.number) is first
    assert orch.get_avit(first.number) is first
    assert orch.get_avit("missing") is None
    assert orch.update_avit("missing", status=AVITStatus.COMPLETED) is None
    assert orch.get_next_pending() is first
    orch.update_avit(first.number, status=AVITStatus.IN_PROGRESS)
    assert orch.list_queue(AVITStatus.PENDING) == [second]
    assert orch.get_next_pending() is second
    snapshot = orch.list_queue()
    snapshot.clear()
    assert len(orch.list_queue()) == 2


def test_completed_number_can_be_added_again(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    first = orch.add_avit("AVIT0000001")
    orch.update_avit(first.number, status=AVITStatus.COMPLETED)
    assert orch.add_avit(first.number) is not first
    assert len(orch.list_queue()) == 2


def test_status_metadata_counters_and_recovery(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    first, second = orch.add_avits(["AVIT0000001", "AVIT0000002"])
    orch.update_avit(first.number, status=AVITStatus.IN_PROGRESS)
    assert first.started_at and orch.get_stats()["active_avit"] == first.number
    orch.update_avit(first.number, status=AVITStatus.COMPLETED, result={"ok": True})
    orch.update_avit(second.number, status=AVITStatus.FAILED, error="handler failed")
    assert first.completed_at and first.result == {"ok": True}
    assert second.attempts == 1 and second.error == "handler failed"
    recovered = AVITOrchestrator(tmp_path)
    assert recovered.list_queue() == orch.list_queue()
    assert recovered.get_stats() == {
        "total_items": 2,
        "by_status": dict(pending=0, in_progress=0, completed=1, failed=1, skipped=0),
        "active_avit": None,
        "paused": False,
        "total_processed": 1,
        "total_failed": 1,
    }


def test_pause_and_resume_are_persistent(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    item = orch.add_avit("AVIT0000001")
    orch.pause()
    recovered = AVITOrchestrator(tmp_path)
    assert recovered.is_paused() and recovered.get_next_pending() is None
    recovered.resume()
    assert recovered.get_next_pending() == item
    assert not AVITOrchestrator(tmp_path).is_paused()


def test_clear_preserves_completed_and_failed_items(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    items = orch.add_avits([f"AVIT{i:07d}" for i in range(5)])
    for item, status in zip(items, AVITStatus):
        orch.update_avit(item.number, status=status)
    assert orch.clear_queue() == 3
    assert [item.status for item in orch.list_queue()] == [
        AVITStatus.COMPLETED, AVITStatus.FAILED,
    ]
    assert orch.clear_queue() == 0
    assert orch.remove_avit(items[2].number)
    assert not orch.remove_avit("missing")


def test_pending_at_retry_limit_is_not_eligible(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    item = orch.add_avit("AVIT0000001")
    for _ in range(item.max_attempts):
        orch.update_avit(item.number, status=AVITStatus.FAILED)
        orch.update_avit(item.number, status=AVITStatus.PENDING)
    assert orch.get_next_pending() is None


def test_claim_is_atomic_across_threads(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    item = orch.add_avit("AVIT0000001")
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: orch.claim_pending(item), range(16)))
    assert results.count(True) == 1
    assert item.status == AVITStatus.IN_PROGRESS
    assert AVITOrchestrator(tmp_path).get_avit(item.number).status == AVITStatus.IN_PROGRESS


def test_removed_entry_cannot_be_claimed_or_updated(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    item = orch.add_avit("AVIT0000001")
    orch.remove_avit(item.number)
    assert not orch.claim_pending(item)
    with pytest.raises(ValueError, match="does not belong"):
        orch.update_item(item, status=AVITStatus.COMPLETED)


def test_active_item_tracks_remaining_concurrent_work(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    first, second = orch.add_avits(["AVIT0000001", "AVIT0000002"])
    assert orch.claim_pending(first) and orch.claim_pending(second)
    orch.update_item(first, status=AVITStatus.COMPLETED)
    assert orch.get_stats()["active_avit"] == second.number
    orch.update_item(second, status=AVITStatus.COMPLETED)
    assert orch.get_stats()["active_avit"] is None
