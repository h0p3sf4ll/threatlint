"""Orchestrate the gated assurance run: pull → SAST (gate) → classify → dynamic (gate) → verdict.

The pipeline mirrors the runtime red team's shape: staged functions, JSON-serialisable state, an injectable
environment provider, and teardown that always runs. Its defining rule is the "DNF": a CRITICAL or HIGH finding
in any stage loses the run on disqualification, but **no stage is skipped because of it** — every scan still runs so
the platforms get their updates. The verdict is computed once, at the end, from the gate each stage reported.
"""

from __future__ import annotations

import datetime
import json
import os

from threatlint import avit_resolve as ar
from threatlint import dast
from threatlint.assurance import appclass, gate, report, sast
from threatlint.assurance import dast as dynamic

REPORT_FILE = "assurance-report.md"
STATE_FILE = "assurance-state.json"


def _save(state: dict) -> None:
    with open(os.path.join(state["work"], STATE_FILE), "w", encoding="utf-8") as handle:
        json.dump({key: value for key, value in state.items() if not key.startswith("_")}, handle, indent=1, default=str)


def _stage(name: str, kind: str) -> dict:
    return {"name": name, "kind": kind, "status": "ran", "findings": [], "gate": {}}


def _record(stage: dict, findings: list[dict], **extra) -> dict:
    stage["findings"] = findings
    stage["gate"] = gate.evaluate(findings)
    stage.update(extra)
    return stage


def sast_stage(args, state: dict) -> dict:
    stage = _stage("static analysis (SAST)", "sast")
    stage["provider"] = "semgrep"
    try:
        findings = sast.scan(state["checkout"], config=getattr(args, "semgrep_config", None) or "auto",
                             runner=state.get("_sast_runner") or sast._semgrep_runner)
        _record(stage, findings)
        print(f"  {'!' if stage['gate']['tripped'] else '✓'} Semgrep: {stage['gate']['blocking']} CRITICAL/HIGH of {len(findings)} finding(s)")
    except Exception as exc:  # noqa: BLE001 - a scan that cannot run is an ERROR stage, not a crash of the pipeline
        stage.update(status="error", note=str(exc))
        print(f"  ! Semgrep could not run: {exc}")
    return stage


def dynamic_stage(args, state: dict, env) -> dict:
    app_class = state["app_class"]
    if app_class["type"] == "mobile":
        stage = _stage("mobile analysis (NowSecure)", "mast")
        stage["provider"] = "nowsecure"
        try:
            result = dynamic.mobile_dynamic(state["target"], app_class)
            _record(stage, result["findings"], note=result["nowsecure"]["note"])
        except Exception as exc:  # noqa: BLE001
            stage.update(status="error", note=str(exc))
        return stage
    stage = _stage("dynamic analysis (Invicti)", "dast")
    try:
        result = dynamic.web_dynamic(state["checkout"], state["work"], state["target"], state["run_id"], env=env)
        _record(stage, result["findings"], provider=result["provider"], note=result["invicti"]["note"],
                endpoints=result["endpoints"], probe_count=result["probe_count"])
        print(f"  {'!' if stage['gate']['tripped'] else '✓'} Dynamic: {len(result['findings'])} finding(s) over {result['endpoints']} endpoint(s); teardown complete")
    except Exception as exc:  # noqa: BLE001
        stage.update(status="error", note=str(exc))
        print(f"  ! Dynamic stage could not run: {exc}")
    return stage


def run(args, *, env=None) -> int:
    work = os.path.realpath(args.work) if getattr(args, "work", None) else _scratch()
    os.makedirs(work, exist_ok=True)
    from threatlint import runtime_env as rt  # noqa: PLC0415
    run_id = rt.DockerProvider.new_run_id()
    state = {"work": work, "run_id": run_id, "stages": [],
             "started": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}
    if getattr(args, "_sast_runner", None):
        state["_sast_runner"] = args._sast_runner
    print(f"threatlint assure · run {run_id} · {work}")

    target = dast.repository_target(args.repo, args.branch)
    state["target"] = target
    state["checkout"] = os.path.join(work, "repo")
    dast.clone(target, state["checkout"])
    print(f"  ✓ Checked out {target['web_url']} · branch {target['branch']}")

    state["app_class"] = appclass.classify(state["checkout"])
    print(f"  · Application type: {state['app_class']['type']} ({state['app_class']['platform']})")

    # Every stage runs to completion regardless of the gate; the verdict is computed once, at the end.
    print("[static analysis]")
    state["stages"].append(sast_stage(args, state))
    _save(state)

    print("[dynamic analysis]")
    provider = env or rt.provider(getattr(args, "env_provider", "docker")) if state["app_class"]["type"] == "web" else None
    state["stages"].append(dynamic_stage(args, state, provider))

    state["verdict"], state["disqualified_at"] = gate.verdict(state["stages"])
    _finalize(args, state)
    print(f"[verdict] {state['verdict']}" + (f" · disqualified at {state['disqualified_at']}" if state["disqualified_at"] else ""))
    return 0 if state["verdict"] == "QUALIFIED" else 1


def _finalize(args, state: dict) -> None:
    document = report.render(state)
    with open(os.path.join(state["work"], REPORT_FILE), "w", encoding="utf-8") as handle:
        handle.write(document)
    state["report"] = os.path.join(state["work"], REPORT_FILE)
    _save(state)
    print(f"  ✓ Report: {state['report']}")
    if not getattr(args, "keep_checkout", False) and ar.remove_checkout(state.get("checkout")):
        print(f"  ✓ Deleted the checkout {state['checkout']}")


def _scratch() -> str:
    from threatlint import runtime_env as rt  # noqa: PLC0415
    return rt.scratch_dir(prefix="threatlint-assure-")
