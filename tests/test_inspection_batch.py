"""Read-only tool fan-out uses synthetic work and no provider/network credentials."""
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from threatlint.inspection_batch import run_inspections
from threatlint.skills import agent_contracts, agent_prompt, skill_map


def calls(count):
    return [(f"call-{index}", "Read", {"index": index}) for index in range(count)]


def test_parallel_tools_overlap_and_keep_request_order(monkeypatch):
    monkeypatch.setenv("THREATLINT_TOOL_CONCURRENCY", "2")
    both_started = threading.Barrier(2)
    lock = threading.Lock()
    active = 0
    maximum = 0

    def execute(_root, _name, arguments):
        nonlocal active, maximum
        with lock:
            active += 1
            maximum = max(maximum, active)
        both_started.wait(timeout=5)
        with lock:
            active -= 1
        return arguments["index"]

    assert run_inspections(calls(4), ".", execute, lambda _: None) == ["0", "1", "2", "3"]
    assert maximum == 2


@pytest.mark.parametrize("invalid", ["zero", "0", "17"])
def test_concurrency_configuration_is_bounded(monkeypatch, invalid):
    monkeypatch.setenv("THREATLINT_TOOL_CONCURRENCY", invalid)
    with pytest.raises(RuntimeError, match="integer from 1 to 16"):
        run_inspections([], ".", lambda *args: None, lambda _: None)


@pytest.mark.parametrize("bad", [
    [("same", "Read", {}), ("same", "Read", {})],
    [("one", "Write", {})], [("one", "Read", [])], calls(65),
])
def test_entire_batch_validated_before_dispatch(bad):
    with pytest.raises(RuntimeError):
        run_inspections(bad, ".", lambda *args: pytest.fail("must not execute"), lambda _: None)


def test_failure_drains_inflight_work_before_returning(monkeypatch):
    monkeypatch.setenv("THREATLINT_TOOL_CONCURRENCY", "2")
    release = threading.Event()
    started = threading.Event()
    finished = threading.Event()
    observed = []

    def execute(_root, _name, args):
        observed.append(args["index"])
        if not args["index"]:
            assert started.wait(5)
            raise RuntimeError("fixture failure")
        started.set()
        assert release.wait(5)
        finished.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(run_inspections, calls(3), ".", execute, lambda _: None)
        assert started.wait(5)
        assert not pending.done()
        release.set()
        with pytest.raises(RuntimeError, match="fixture failure"):
            pending.result(timeout=5)
    assert finished.is_set()
    assert observed == [0, 1]


def test_canonical_contracts_cover_every_agent_and_reach_prompts():
    contracts = agent_contracts()
    assert set(contracts) == set(skill_map())
    assert len({contract["inputs"] for contract in contracts.values()}) == 22
    for agent, contract in contracts.items():
        prompt = agent_prompt(agent)
        assert contract["inputs"] in prompt
        assert contract["outputs"] in prompt
        assert contract["boundaries"] in prompt
