"""Execution tests use synthetic items and never run an AVIT integration."""

import asyncio

import pytest

from threatlint.avit_orchestrator import AVITOrchestrator, AVITStatus


def test_ten_item_canary_preserves_remaining_queue(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    orch.add_avits([f"AVIT{i:07d}" for i in range(12)])
    seen = []
    result = orch.run_canary(lambda item: seen.append(item.number) or True)
    assert result == {
        "status": "success", "total": 10, "success": 10, "failed": 0,
        "success_rate": 100.0, "ready_for_full_run": True,
    }
    assert len(seen) == len(set(seen)) == 10
    recovered = AVITOrchestrator(tmp_path)
    assert len(recovered.list_queue(AVITStatus.COMPLETED)) == 10
    assert len(recovered.list_queue(AVITStatus.PENDING)) == 2


@pytest.mark.parametrize("successes, ready", [(8, True), (7, False)])
def test_canary_threshold(tmp_path, successes, ready):
    orch = AVITOrchestrator(tmp_path)
    orch.add_avits([f"AVIT{i:07d}" for i in range(10)])
    result = orch.run_canary(lambda item: int(item.number[4:]) < successes)
    assert result["ready_for_full_run"] is ready
    assert result["success_rate"] == successes * 10


def test_canary_records_handler_exception(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    item = orch.add_avit("AVIT0000001")

    def handler(item):
        raise RuntimeError("synthetic failure")

    assert orch.run_canary(handler)["failed"] == 1
    assert item.error == "synthetic failure" and item.attempts == 1


def test_empty_execution(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    assert orch.run_canary(lambda item: True)["status"] == "no_items"
    async def handler(item):
        return True

    assert asyncio.run(orch.process_batch(handler)) == {
        "success": 0, "failed": 0, "skipped": 0,
    }


def test_async_batch_concurrency_results_and_progress(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    orch.add_avits([f"AVIT{i:07d}" for i in range(6)])
    active = peak = 0
    progress = []

    async def handler(item):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0)
            if item.number.endswith("0"):
                raise RuntimeError("synthetic failure")
            return not item.number.endswith("1")
        finally:
            active -= 1

    result = asyncio.run(orch.process_batch(
        handler, max_concurrent=2,
        on_progress=lambda current, total: progress.append((current, total)),
    ))
    assert result == {"success": 4, "failed": 2, "skipped": 0}
    assert peak == 2
    assert progress == [(i, 6) for i in range(1, 7)]
    assert len(AVITOrchestrator(tmp_path).list_queue(AVITStatus.COMPLETED)) == 4


@pytest.mark.parametrize("mode", ["canary", "batch"])
def test_paused_queue_never_calls_handler(tmp_path, mode):
    orch = AVITOrchestrator(tmp_path)
    orch.add_avit("AVIT0000001")
    orch.pause()
    seen = []

    async def handler(item):
        seen.append(item.number)
        return True

    if mode == "batch":
        assert asyncio.run(orch.process_batch(handler))["skipped"] == 1
    else:
        assert not orch.run_canary(lambda item: seen.append(item.number) or True)["ready_for_full_run"]
    assert not seen
    assert len(orch.list_queue(AVITStatus.PENDING)) == 1


@pytest.mark.parametrize("mode", ["canary", "batch"])
def test_exhausted_pending_item_never_calls_handler(tmp_path, mode):
    orch = AVITOrchestrator(tmp_path)
    item = orch.add_avit("AVIT0000001")
    item.attempts = item.max_attempts
    seen = []

    async def handler(item):
        seen.append(item.number)
        return True

    if mode == "batch":
        assert asyncio.run(orch.process_batch(handler))["skipped"] == 1
    else:
        assert not orch.run_canary(lambda item: seen.append(item.number) or True)["ready_for_full_run"]
    assert not seen and item.status == AVITStatus.PENDING


def test_pause_during_canary_blocks_full_run_even_above_threshold(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    orch.add_avits([f"AVIT{i:07d}" for i in range(10)])
    seen = []

    def handler(item):
        seen.append(item.number)
        if len(seen) == 9:
            orch.pause()
        return True

    result = orch.run_canary(handler)
    assert len(seen) == 9 and result["success_rate"] == 90
    assert not result["ready_for_full_run"]
    assert len(orch.list_queue(AVITStatus.PENDING)) == 1


def test_pause_while_waiting_for_semaphore_skips_unstarted_items(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    orch.add_avits([f"AVIT{i:07d}" for i in range(3)])
    progress = []

    async def handler(item):
        orch.pause()
        await asyncio.sleep(0)
        return True

    result = asyncio.run(orch.process_batch(
        handler, on_progress=lambda current, total: progress.append((current, total)),
    ))
    assert result == {"success": 1, "failed": 0, "skipped": 2}
    assert progress == [(1, 3), (2, 3), (3, 3)]


@pytest.mark.parametrize("mode", ["canary", "batch"])
def test_invalid_execution_limit_is_rejected(tmp_path, mode):
    orch = AVITOrchestrator(tmp_path)

    async def handler(item):
        return True

    for limit in (0, -1):
        with pytest.raises(ValueError, match="positive"):
            if mode == "batch":
                asyncio.run(orch.process_batch(handler, max_concurrent=limit))
            else:
                orch.run_canary(lambda item: True, canary_size=limit)


def test_overlapping_batches_only_claim_each_item_once(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    orch.add_avits([f"AVIT{i:07d}" for i in range(4)])
    seen = []

    async def handler(item):
        seen.append(item.number)
        await asyncio.sleep(0)
        return True

    async def run():
        return await asyncio.gather(orch.process_batch(handler), orch.process_batch(handler))

    results = asyncio.run(run())
    assert len(seen) == len(set(seen)) == 4
    assert sum(result["success"] for result in results) == 4


@pytest.mark.parametrize("mode", ["canary", "batch"])
def test_requeued_number_does_not_update_completed_history(tmp_path, mode):
    orch = AVITOrchestrator(tmp_path)
    original = orch.add_avit("AVIT0000001")
    orch.update_avit(original.number, status=AVITStatus.COMPLETED, result={"old": True})
    old_payload = original.to_dict()
    current = orch.add_avit(original.number)

    async def handler(item):
        return True

    if mode == "batch":
        asyncio.run(orch.process_batch(handler))
    else:
        orch.run_canary(lambda item: True)
    assert current.status == AVITStatus.COMPLETED
    assert original.to_dict() == old_payload


@pytest.mark.parametrize("mode", ["canary", "batch"])
def test_storage_failure_is_not_mislabeled_as_handler_failure(tmp_path, monkeypatch, mode):
    orch = AVITOrchestrator(tmp_path)
    orch.add_avit("AVIT0000001")

    def fail():
        raise OSError("synthetic save failure")

    def handler(item):
        monkeypatch.setattr(orch, "_save_state", fail)
        return True

    async def async_handler(item):
        return handler(item)

    with pytest.raises(OSError, match="synthetic save failure"):
        if mode == "batch":
            asyncio.run(orch.process_batch(async_handler))
        else:
            orch.run_canary(handler)
    assert orch.get_stats()["total_failed"] == 0


def test_cancellation_releases_claim_without_recording_handler_failure(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    item = orch.add_avit("AVIT0000001")

    async def run():
        started = asyncio.Event()

        async def handler(item):
            started.set()
            await asyncio.Event().wait()
            return True

        task = asyncio.create_task(orch.process_batch(handler))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    recovered = AVITOrchestrator(tmp_path)
    assert recovered.get_avit(item.number).status == AVITStatus.PENDING
    assert recovered.get_stats()["total_failed"] == 0
    assert recovered.get_stats()["active_avit"] is None


def test_progress_failure_cancels_and_joins_sibling_handlers(tmp_path):
    orch = AVITOrchestrator(tmp_path)
    orch.add_avits(["AVIT0000001", "AVIT0000002"])
    stopped = []

    async def run():
        second_started = asyncio.Event()

        async def handler(item):
            if item.number.endswith("1"):
                await second_started.wait()
                return True
            second_started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.append(item.number)
            return True

        def progress(current, total):
            raise RuntimeError("synthetic progress failure")

        with pytest.raises(RuntimeError, match="synthetic progress failure"):
            await orch.process_batch(handler, max_concurrent=2, on_progress=progress)
        assert stopped == ["AVIT0000002"]

    asyncio.run(run())
    assert len(orch.list_queue(AVITStatus.COMPLETED)) == 1
    assert len(orch.list_queue(AVITStatus.PENDING)) == 1
