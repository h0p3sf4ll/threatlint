"""Independent scope execution, cancellation and budgets without model/network calls."""

import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from threatlint import agent_batch
from threatlint.bounded_work import run_bounded
from threatlint.cli import build_parser, cmd_run


def arguments(tmp_path, targets=None, *extra):
    source = tmp_path / "targets.json"
    source.write_text(json.dumps(targets if targets is not None else ["src/auth", "src/api"]), encoding="utf-8")
    return build_parser().parse_args(["run", "auth-review", "--targets-file", str(source),
                                     "--output-dir", str(tmp_path / "reports"), *extra])


@pytest.mark.parametrize("extra", [["--workers", "0"], ["--workers", "9"], ["--workers", "-1"],
                                   ["--max-model-runs", "1"], ["--max-model-runs", "65"],
                                   ["--target", "duplicate"], ["--resolve-avits", "--yes"]])
def test_invalid_plans_fail_before_dispatch_or_output(tmp_path, extra):
    args = arguments(tmp_path, None, *extra)
    with pytest.raises(ValueError):
        agent_batch.run_batch(args, invoke=lambda *_: pytest.fail("must not dispatch"))
    assert not (tmp_path / "reports").exists()


@pytest.mark.parametrize("targets", [[], [""], ["a", "a"], ["a", 2], ["a\0b"], ["x" * 12001], "src"])
def test_scope_manifest_is_bounded_and_unambiguous(tmp_path, targets):
    with pytest.raises(ValueError):
        agent_batch.load_targets(arguments(tmp_path, targets))


def test_upstream_and_runtime_scopes_cannot_be_partitioned(tmp_path):
    args = arguments(tmp_path)
    for mode in ["fp-review", "compliance-check", "runtime-review", "attack-tree"]:
        args.mode = mode
        with pytest.raises(ValueError, match="stay together"):
            agent_batch.load_targets(args)


def test_parallel_scope_reports_have_distinct_destinations_and_stable_manifest(tmp_path):
    args = arguments(tmp_path, ["src/a", "src/b", "src/c", "src/d"], "--workers", "2", "--api-key", "fixture-private")
    barrier = threading.Barrier(2)
    seen = []

    def invoke(command, environment, output, _cancel):
        seen.append(command)
        assert environment["_THREATLINT_BATCH_API_KEY"] == "fixture-private"
        assert "fixture-private" not in " ".join(command)
        assert "--targets-file" not in command
        barrier.wait(timeout=5)
        (output / "report.md").write_text("# Fixture report", encoding="utf-8")

    assert agent_batch.run_batch(args, invoke=invoke) == 0
    manifest = next((tmp_path / "reports").glob("*/batch.json"))
    data = json.loads(manifest.read_text())
    assert data["status"] == "complete"
    assert data["plannedModelRuns"] == 4
    assert [item["target"] for item in data["scopes"]] == ["src/a", "src/b", "src/c", "src/d"]
    assert {item["status"] for item in data["scopes"]} == {"complete"}
    assert len({command[command.index("--output-dir") + 1] for command in seen}) == 4
    assert "fixture-private" not in manifest.read_text()
    if os.name == "posix":
        assert manifest.stat().st_mode & 0o777 == 0o600


def test_failed_scope_cancels_and_drains_peers_without_dispatching_queued_scopes(tmp_path):
    args = arguments(tmp_path, ["a", "b", "c"], "--workers", "2")
    both_started = threading.Barrier(2)
    observed = []
    drained = threading.Event()

    def invoke(command, _environment, _output, cancel):
        target = command[command.index("--target") + 1]
        observed.append(target)
        both_started.wait(timeout=5)
        if target == "a":
            raise RuntimeError("synthetic failure")
        assert cancel.wait(5)
        drained.set()
        raise RuntimeError("Cancelled")

    assert agent_batch.run_batch(args, invoke=invoke) == 1
    assert drained.is_set()
    assert sorted(observed) == ["a", "b"]
    data = json.loads(next((tmp_path / "reports").glob("*/batch.json")).read_text())
    assert [item["status"] for item in data["scopes"]] == ["error", "cancelled", "cancelled"]


def test_local_child_is_reaped_on_cancellation(tmp_path):
    marker = tmp_path / "started"
    command = [sys.executable, "-c", "import pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text('started'); time.sleep(60)", str(marker)]
    stop = threading.Event()
    with ThreadPoolExecutor(max_workers=1) as pool:
        running = pool.submit(agent_batch.run_child, command, dict(os.environ), tmp_path, stop)
        for _ in range(100):
            if marker.exists():
                break
            threading.Event().wait(0.02)
        assert marker.exists()
        stop.set()
        with pytest.raises(RuntimeError, match="Cancelled"):
            running.result(timeout=5)


def test_packaged_cli_children_use_scoped_targets_and_produce_reports(tmp_path, monkeypatch):
    """Exercise the actual child CLI and streaming transport against a loopback fake server."""
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"data":[{"id":"fixture"}]}')

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((body, self.headers.get("Authorization")))
            payload = json.dumps({"choices": [{"delta": {"content": "# Security Review\n\nNo candidate findings in the synthetic scope."}, "finish_reason": "stop"}]})
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(f"data: {payload}\n\ndata: [DONE]\n\n".encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("PYTHONPATH", str(Path(__file__).resolve().parents[1] / "src"))
    monkeypatch.chdir(tmp_path)
    args = arguments(tmp_path, ["src/auth", "src/api"], "--workers", "2", "--model", "fixture",
                     "--base-url", f"http://127.0.0.1:{server.server_port}/v1", "--api-key", "fixture-private")
    try:
        assert agent_batch.run_batch(args) == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert len(requests) == 2
    assert {authorization for _, authorization in requests} == {"Bearer fixture-private"}
    prompts = [body["messages"][-1]["content"] for body, _ in requests]
    assert sum("Focus area / target: src/auth" in prompt for prompt in prompts) == 1
    assert sum("Focus area / target: src/api" in prompt for prompt in prompts) == 1
    reports = [item for item in (tmp_path / "reports").glob("*/scope-*/*") if item.suffix in (".md", ".docx")]
    assert len(reports) == 2


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group ownership")
@pytest.mark.parametrize("exit_code", [0, 1])
def test_exited_leader_cannot_leave_a_running_descendant(tmp_path, exit_code):
    child_pid = tmp_path / "descendant.pid"
    leader = ("import pathlib,subprocess,sys; "
              "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
              "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); sys.exit(int(sys.argv[2]))")
    command = [sys.executable, "-c", leader, str(child_pid), str(exit_code)]
    if exit_code:
        with pytest.raises(RuntimeError, match="Scope review failed"):
            agent_batch.run_child(command, dict(os.environ), tmp_path, threading.Event())
    else:
        agent_batch.run_child(command, dict(os.environ), tmp_path, threading.Event())
    pid = int(child_pid.read_text())
    try:
        for _ in range(100):
            state = subprocess.run(["ps", "-p", str(pid), "-o", "stat="], capture_output=True, text=True, check=False).stdout.strip()
            if not state or state.startswith("Z"):
                break  # A terminated orphan may await its platform's reaper.
            threading.Event().wait(0.02)
        assert not state or state.startswith("Z"), "owned descendant is still running"
    finally:
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass


def test_shared_scheduler_rejects_precancelled_work():
    stop = threading.Event()
    stop.set()
    with pytest.raises(RuntimeError, match="Cancelled"):
        run_bounded([1], lambda _: pytest.fail("must not dispatch"), 1, stop)


def test_single_run_does_not_silently_ignore_parallel_controls(capsys):
    args = build_parser().parse_args(["run", "auth-review", "--workers", "2"])
    assert cmd_run(args) == 1
    assert "require --targets-file" in capsys.readouterr().out
