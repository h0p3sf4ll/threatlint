"""Run one specialist over explicitly independent source scopes with bounded workers.

Children use the normal packaged CLI/provider path. Complete reports remain attributed
to their scopes; this runner neither invents consensus nor applies source changes.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from .bounded_work import run_bounded
from .run_context import _MODE_TO_AGENT
from .skills import agent_contracts

MAX_TARGET_BYTES = 256_000
CHILD_TIMEOUT_SECONDS = 7200


def load_targets(args) -> list[str]:
    workers = getattr(args, "workers", 1)
    budget = getattr(args, "max_model_runs", 24)
    if isinstance(workers, bool) or not isinstance(workers, int) or not 1 <= workers <= 8:
        raise ValueError("--workers must be an integer from 1 to 8")
    if isinstance(budget, bool) or not isinstance(budget, int) or not 1 <= budget <= 64:
        raise ValueError("--max-model-runs must be an integer from 1 to 64")
    agent = _MODE_TO_AGENT[args.mode]
    if agent_contracts()[agent]["evidenceMode"] != "source" or args.mode == "runtime-review":
        raise ValueError("Parallel target lists require a source-review role; shared findings and runtime evidence stay together")
    incompatible = ["target", "findings", "avit", "avit_file", "isst", "resolve_avits", "yes",
                    "semgrep_deployment", "semgrep_rule_hash_id"]
    if any(getattr(args, key, None) for key in incompatible):
        raise ValueError("--targets-file cannot be combined with --target, supplied findings, AVITs, or write-back options")
    source = Path(args.targets_file).expanduser()
    with source.open("rb") as handle:
        raw = handle.read(MAX_TARGET_BYTES + 1)
    if len(raw) > MAX_TARGET_BYTES:
        raise ValueError("Target list exceeds 256,000 bytes")
    try:
        targets = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ValueError("--targets-file must contain a JSON array of source scope strings") from None
    if (not isinstance(targets, list) or not targets or len(targets) > 64
            or any(not isinstance(item, str) or not item.strip() or len(item) > 12_000 or "\0" in item for item in targets)):
        raise ValueError("Choose 1 to 64 nonempty source scopes, each at most 12,000 characters")
    targets = [item.strip() for item in targets]
    if len(set(targets)) != len(targets):
        raise ValueError("Target scopes must be distinct; avoid overlapping primary source ownership")
    if len(targets) > budget:
        raise ValueError(f"This batch needs {len(targets)} model runs; --max-model-runs is {budget}")
    return targets


def child_command(args, target: str, output: Path) -> tuple[list[str], dict[str, str]]:
    command = [sys.executable, "-m", "threatlint", "run", args.mode,
               "--target", target, "--output-dir", str(output)]
    for name in ("provider", "model", "base_url", "bedrock_region", "base", "head"):
        value = getattr(args, name, None)
        if value:
            command.extend(["--" + name.replace("_", "-"), str(value)])
    for name in ("deep", "daybreak_blue"):
        if getattr(args, name, False):
            command.append("--" + name.replace("_", "-"))
    if getattr(args, "design", None):
        command.extend(["--design", *(str(Path(item).expanduser().resolve()) for item in args.design)])
    environment = dict(os.environ)
    key = getattr(args, "api_key", None)
    if key:
        # Preserve normal provider validation, including native clients rejecting API keys.
        environment["_THREATLINT_BATCH_API_KEY"] = key
    return command, environment


def _signal_child(child, *, force=False):
    for attempt in range(5):
        try:
            if os.name == "posix":
                os.killpg(child.pid, signal.SIGKILL if force else signal.SIGTERM)
            elif not force:
                child.terminate()
            else:
                child.kill()
            return
        except ProcessLookupError:
            return
        except PermissionError:
            # macOS may briefly report EPERM for an exited group's orphan being reaped.
            # Retry only after the leader exited; persistent permission failures remain errors.
            if os.name != "posix" or child.poll() is None or attempt == 4:
                raise
            time.sleep(0.01)


def run_child(command, environment, output, cancel, *, popen=subprocess.Popen) -> None:
    """Logs stay local; cancellation signals the process group and waits for process exit."""
    if cancel.is_set():
        raise RuntimeError("Cancelled before starting")
    log_path = output / "execution.log"
    with log_path.open("x", encoding="utf-8") as log:
        os.chmod(log_path, 0o600)
        child = popen(command, env=environment, stdout=log, stderr=subprocess.STDOUT,
                      stdin=subprocess.DEVNULL, start_new_session=os.name == "posix")
        started = time.monotonic()
        try:
            while child.poll() is None:
                if cancel.wait(0.1):
                    raise RuntimeError("Cancelled")
                if time.monotonic() - started > CHILD_TIMEOUT_SECONDS:
                    raise RuntimeError("Review exceeded the two-hour process budget")
            if child.returncode:
                raise RuntimeError(f"Scope review failed (exit {child.returncode}); inspect its local execution.log")
        finally:
            # Terminate the process group even if its leader exited but left descendants.
            if os.name == "posix" or cancel.is_set() or child.poll() is None:
                _signal_child(child)
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    _signal_child(child, force=True)
                    child.wait()
                if os.name == "posix":
                    _signal_child(child, force=True)


def run_batch(args, *, invoke=run_child) -> int:
    targets = load_targets(args)  # Complete admission validation precedes writes or providers.
    destination = Path(getattr(args, "output_dir", None) or Path.cwd()).expanduser().resolve()
    root = destination / f"threatlint-{args.mode}-batch-{uuid.uuid4().hex[:12]}"
    root.mkdir(parents=True, mode=0o700)
    cancel = threading.Event()
    outcomes = [{"scope": index + 1, "target": target, "status": "queued", "directory": f"scope-{index + 1:03d}"}
                for index, target in enumerate(targets)]
    previous_term = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: cancel.set())
    failed = False

    def review(item):
        directory = root / item["directory"]
        directory.mkdir(mode=0o700)
        item["status"] = "running"
        command, environment = child_command(args, item["target"], directory)
        try:
            invoke(command, environment, directory, cancel)
            if cancel.is_set():
                raise RuntimeError("Cancelled")
            item["status"] = "complete"
        except BaseException:
            item["status"] = "cancelled" if cancel.is_set() else "error"
            raise

    print(f"Reviewing {len(targets)} explicit scopes with up to {args.workers} workers; model-run budget {args.max_model_runs}.")
    try:
        run_bounded(outcomes, review, args.workers, cancel)
    except (RuntimeError, OSError, KeyboardInterrupt) as error:
        failed = True
        print(f"Review batch stopped: {error or 'Interrupted'}")
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        for item in outcomes:
            if item["status"] in ("queued", "running"):
                item["status"] = "cancelled"
        manifest = root / "batch.json"
        with manifest.open("x", encoding="utf-8") as handle:
            os.chmod(manifest, 0o600)
            json.dump({"schemaVersion": 1, "mode": args.mode, "workers": args.workers,
                       "plannedModelRuns": len(targets), "maxModelRuns": args.max_model_runs,
                       "status": "error" if failed else "complete", "scopes": outcomes,
                       "limitations": "User-defined scopes may overlap. Reports are independent; no deduplication or consensus is asserted. Supporting reads may cross scopes."}, handle, indent=2)
    print(f"Scope reports and execution status: {manifest}")
    return 1 if failed else 0
