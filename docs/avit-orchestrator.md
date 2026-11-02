# AVIT orchestrator

Batch reviews need a reliable answer to “what ran, what failed, and what is safe to
retry?” The orchestrator records that local queue state and limits concurrent work.
**It does not fetch, review, or close ServiceNow AVITs.** Your Python handlers perform
those operations; see [AVIT triage integration](avit-integration.md).

## Quick Start

Use an isolated directory to check queue execution without credentials, models, or
ServiceNow writes. Run this from an installed Threatlint environment:

```python
from pathlib import Path
from threatlint.avit_orchestrator import AVITOrchestrator

orch = AVITOrchestrator(state_dir=Path("avit-canary-state"))
orch.add_avits([f"AVIT{number:015d}" for number in range(1, 11)])

def synthetic_handler(item):
    print(f"Synthetic check: {item.number}")
    return True  # No external operations.

result = orch.run_canary(synthetic_handler, canary_size=10)
print(result)
```

This marks up to ten entries `completed` **in the local queue only**. A passing
synthetic canary proves queue execution, not real review quality or ServiceNow
resolution. Re-running the example requeues completed numbers; use a fresh directory
for an independent check.

For real work, replace the handler with an adapter that reviews the AVIT, performs
authorized writes, and verifies the external outcome before returning success.
Neither loading a queue nor running `resume` starts a worker.

## CLI Commands

These commands use `~/.threatlint/avit_orchestrator/state.json`:

```bash
threatlint orchestrator queue add AVIT000000095938462 AVIT000000095938463
threatlint orchestrator queue list --status pending
threatlint orchestrator stats
threatlint orchestrator pause
threatlint orchestrator resume
```

| Command | Behavior |
| --- | --- |
| `queue add AVIT…` | Add numbers; an existing non-completed entry is reused. The printed count is the number supplied, not necessarily newly added. |
| `queue list [--status STATUS]` | Print JSON; statuses are `pending`, `in_progress`, `completed`, `failed`, `skipped`. |
| `stats` | Print status counts, `active_avit`, pause state, and cumulative processed/failure counters. |
| `clear` | Remove pending, in-progress, and skipped entries; **keep completed and failed**. Do not use during execution. |
| `pause` / `resume` | Persist the pause flag. They do not signal another already-loaded process. |
| `canary [--size N]` | Currently prints “not implemented without handler” and exits **1**. Use Python below. |

Use **one orchestrator instance per state directory**. In particular, do not run
these CLI commands against a directory owned by an active Python worker: separate
processes neither share a lock nor reload each other's changes.

## Python API

### Canary Testing

`run_canary(handler, canary_size=10)` calls a **synchronous** handler for at most the
first `canary_size` pending entries. A truthy return records completion; a falsey
return or ordinary exception records failure.

`ready_for_full_run` requires all selected entries to have run, at least **80%**
success, and an unpaused queue. Ten is a maximum, not a minimum: a one-item queue
can pass. An empty queue returns `status="no_items"`, `success_rate=0.0`, and
`ready_for_full_run=False`. The nonempty result includes `total`, `success`,
`failed`, `success_rate`, and `status` (`success` or `degraded`).

A canary consumes real queue entries. With a real handler, it also performs that
handler's real external operations. Review failures before treating the readiness
flag as permission to proceed.

### Integration with AVIT Review Workflow

Supply your own synchronous and asynchronous adapters; they are not built-ins:

```python
import asyncio

def review_handler(item):
    return review_and_verify(item.number)  # Your synchronous adapter.

async def batch_handler(item):
    return await review_and_verify_async(item.number)  # Your async adapter.

canary = orch.run_canary(review_handler, canary_size=10)
if canary["ready_for_full_run"]:
    result = asyncio.run(orch.process_batch(
        batch_handler,
        max_concurrent=3,
        on_progress=lambda current, total: print(f"{current}/{total}"),
    ))
    print(result)
```

`process_batch` takes a snapshot of pending entries and bounds concurrent handlers
with a semaphore. Items added later need another call. It returns counts:
`{"success": …, "failed": …, "skipped": …}`. Progress counts all three outcomes.
Here, `skipped` means an entry could not be claimed; it does **not** change that
entry's status to `skipped`. Both execution limits must be positive.

### Basic Usage

| Method | Use |
| --- | --- |
| `add_avit(number)` / `add_avits(numbers)` | Queue work; completed numbers may be added again as new entries. |
| `list_queue(status=None)` | Inspect entries, optionally filtering by `AVITStatus`. |
| `get_next_pending()` | Peek at the next eligible entry; it does not reserve it. |
| `claim_pending(item)` | Atomically claim and save an eligible entry before invoking a handler. |
| `update_item(item, status=…, error=…, result=…)` | Update the exact entry and persist it. |
| `get_avit(number)` / `update_avit(number, …)` | Legacy lookup/update of the **first** matching number, including completed history. Prefer exact entries when requeuing. |
| `remove_avit(number)` | Remove all entries with that number. Do not remove active work. |
| `get_stats()` | Inspect status counts and lifetime counters. |
| `pause()` / `resume()` / `is_paused()` | Control new claims in the same instance. |

## Error Handling and Retry

Normal execution moves `pending → in_progress → completed` or `failed`.
`attempts` counts **recorded failures**, not starts; `max_attempts` defaults to 3.
Failed entries are not retried automatically:

```python
from threatlint.avit_orchestrator import AVITStatus

for item in orch.list_queue(AVITStatus.FAILED):
    # First reconcile external effects and fix the cause of failure.
    if item.attempts < item.max_attempts:
        orch.update_item(item, status=AVITStatus.PENDING)
```

Resetting to pending does not erase the attempt count or previous error metadata.
At the failure limit, execution will not claim the entry even if it is pending.
Counters are cumulative transitions, not unique AVIT totals; `active_avit` names
one in-progress entry, not every concurrent handler.

- **Handler exceptions:** logged, recorded as failures, and processing continues.
- **Pause:** blocks new claims, including entries waiting for the batch semaphore.
  Running handlers finish. Resume allows future claims; skipped batch entries need
  another batch call.
- **Async cancellation:** returns the claimed entry to pending and propagates
  cancellation. External effects are not undone.
- **Batch-level errors:** cancel and join sibling tasks before control returns.
- **Storage failures:** propagate rather than being counted as handler failures.
  Stop, repair storage, and reload; the current instance may contain unsaved changes.

Make handlers idempotent and cancellation-safe. A ServiceNow write can succeed even
if recording local completion fails.

## Architecture

### State Storage

The default path is `~/.threatlint/avit_orchestrator/state.json`, independent of
`THREATLINT_HOME`. Override it with `AVITOrchestrator(state_dir=Path("…"))`.
The historical `queue_file` attribute remains, but `queue.json` is not used for
persistence.

Each save serializes the whole queue, flushes and syncs a sibling temporary file,
then atomically replaces `state.json`. Serialization or replacement failure leaves
the previous snapshot intact. Missing state starts empty; corrupt or unreadable
existing state is logged and raises instead of silently discarding the queue.

Loading preserves recorded statuses. After a crash, inspect external effects
before resetting stranded `in_progress` entries with `update_item`.
Atomic replacement prevents partial JSON, **not** lost updates between writers.

### Thread Safety

An in-process `RLock` protects queue operations and claims. Returned items remain
live objects; update through methods, not direct field mutation. Use
`claim_pending(item)`, not a peek followed by an unconditional status change, when
writing your own worker.

### Package Responsibilities

Public imports remain under `threatlint.avit_orchestrator`:

| Module | Responsibility |
| --- | --- |
| `models.py` | Status enum, queue/state dataclasses, JSON schema |
| `storage.py` | `StateStore` protocol and atomic `JsonStateStore` |
| `orchestrator.py` | Queue operations, locking, transitions, pause/resume |
| `execution.py` | Synchronous canary and bounded async batch |
| `cli.py` | Arguments and command output |
| `__init__.py` | Public exports |

`AVITOrchestrator(store=your_store)` accepts `load() -> OrchestratorState` and
`save(state) -> None` without creating the default directory. Queue scans are
linear; every save rewrites the full state. No throughput or queue-size benchmark
is claimed.

## Troubleshooting

| Symptom | Next action |
| --- | --- |
| Queue will not load | Check permissions and validate JSON with `python3 -m json.tool ~/.threatlint/avit_orchestrator/state.json`. Preserve the file before recovery; do not delete the only record of side effects. |
| Nothing runs | Check `paused`, pending status, and `attempts < max_attempts`. A failed entry needs an explicit reset. |
| Canary is degraded | Inspect failed entries and unclaimed selections. Fix the handler or dependency, reconcile external effects, then retry eligible entries. |
| CLI pause does not stop a worker | Call `pause()` on the worker's existing instance; CLI state is not cross-process control. |
| Crash left work in progress | Verify ServiceNow/Semgrep effects first, then reset only entries safe to retry. |

## Testing

The package requires Python 3.9+. The focused tests cover queue compatibility,
atomic persistence, explicit retries, pause, thresholds, concurrency, cancellation,
and CLI registration using isolated state stores:

```bash
python3 -m pytest -q tests/test_avit_orchestrator.py \
  tests/test_avit_orchestrator_storage.py \
  tests/test_avit_orchestrator_execution.py \
  tests/test_avit_orchestrator_cli.py
```

These are synthetic checks, not live ServiceNow acceptance tests.

## See Also

- [AVIT integration](avit-integration.md) — credentials, review, and external writes
- [Threatlint overview](../README.md) — installation and other workflows
