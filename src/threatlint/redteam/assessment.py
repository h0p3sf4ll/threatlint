"""Orchestrate a runtime red-team assessment: clone, build in an isolated ephemeral environment, run the repository's
own tests, probe the deployed endpoints with Threatlint's ruleset, learn from the results, draft AVITs, and tear down.

Reuses the DAST subsystem's vetted building blocks (`dast.clone`, `runtime_discovery.detect`, `runtime_env` provider,
`dast_*` probing) so every isolation guarantee holds. The provider is injectable, so the flow is testable without
Docker. Steps mirror `dast.py`: each writes JSON-serialisable state and teardown always runs.
"""

from __future__ import annotations

import datetime
import json
import os

from threatlint import avit_resolve as ar
from threatlint import dast
from threatlint import runtime_env as rt
from threatlint.avit_resolve import ResolveError
from threatlint.redteam import credentials as creds
from threatlint.redteam import discovery, engine, report, servicenow_stub
from threatlint.redteam.engine import Budget
from threatlint.redteam.rules import load_ruleset, save_ruleset

REPORT_FILE = "redteam-report.md"
AVITS_FILE = "avits.json"


def _save_state(state: dict) -> None:
    with open(os.path.join(state["work"], "redteam-state.json"), "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=1, default=str)


def provision(args, state: dict, env) -> dict:
    target = dast.repository_target(args.repo, args.branch)
    state.update(target=target, checkout=os.path.join(state["work"], "repo"), provider=env.name,
                 started=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), credential_mode="synthetic")
    dast.clone(target, state["checkout"])
    print(f"  ✓ Checked out {target['web_url']} · branch {target['branch']}")
    plan = rt.detect(state["checkout"], state["work"], service=args.service or "", port=args.port or 0,
                     health_path=args.health_path or "", test_command=getattr(args, "test_command", None), start_command=args.start_command or "")
    state["stack"] = plan.stack
    for note in plan.notes:
        print(f"    {note}")
    if getattr(args, "credentials", None):
        config = creds.load_config(args.credentials)
        resolved = creds.resolve(config, getattr(args, "aws_profile", None))
        for service in plan.services:
            if service.name == plan.app:
                service.env.update(resolved)
        state.update(credential_mode=f"resolved from {config['store']} ({len(resolved)} secret(s))", _resolved=resolved)
        print(f"  ✓ Resolved {len(resolved)} credential(s) from {config['store']} into the app environment")
    state["plan"] = rt.plan_dict(plan)
    _save_state(state)
    print(f"  Building {plan.stack}: {', '.join(item.name for item in plan.services)} (egress allowed only while building)")
    try:
        env.provision(state, plan)
    finally:
        _save_state(state)
    print(f"  ✓ Built {len(state.get('built', []))} image(s); internal network {state.get('network', '?')} (no egress)")
    return state


def deploy(args, state: dict, env) -> dict:
    env.deploy(state)
    _save_state(state)
    health = state.get("health", {})
    if health.get("default_route"):
        raise ResolveError("The sandbox network has a default route; refusing to continue")
    if not health.get("healthy"):
        raise ResolveError(f"The application did not become healthy within the start timeout ({health.get('responses')})")
    print(f"  ✓ Deployed; healthy on {health['path']} · no default route (egress blocked)")
    return state


def test(args, state: dict, env) -> dict:
    env.run_tests(state)
    _save_state(state)
    tests = state.get("tests", {})
    print(f"  {'✓' if tests.get('status') == 'PASSED' else '!'} Repository tests {tests.get('status', 'not run')}")
    return state


def assess(args, state: dict, env) -> dict:
    ruleset = load_ruleset(getattr(args, "rules", None))
    endpoints = discovery.discover(state["checkout"], rt.plan_from(state["plan"]), routes_file=getattr(args, "routes", "") or "")
    state["endpoints"] = endpoints
    print(f"  Assessing {len(endpoints)} endpoint(s) with {len(ruleset.rules)} rule(s)")
    budget, findings, confirmed_before = Budget(), [], {rule_id: rule.hits for rule_id, rule in ruleset.rules.items()}
    for endpoint in endpoints:
        findings += engine.assess_endpoint(state, env, ruleset, endpoint, state["run_id"], budget)
    state["probe_count"] = engine.MAX_PROBES - budget.remaining
    # Dedupe: one finding per (rule, endpoint, parameter).
    unique = {(item["rule_id"], item["path"], item.get("parameter", "")): item for item in findings}
    state["findings"] = list(unique.values())
    learned = {"rules_run": sum(1 for rule in ruleset.rules.values() if rule.runs),
               "confirmed": sum(max(0, rule.hits - confirmed_before.get(rule_id, 0)) for rule_id, rule in ruleset.rules.items()),
               "affinities": sorted({token for rule in ruleset.rules.values() for token in rule.affinity})[:12]}
    path = save_ruleset(ruleset, getattr(args, "rules", None))
    state["ruleset_summary"], state["learned"] = ruleset.summary(), learned
    print(f"  ✓ {len(state['findings'])} candidate finding(s); ruleset updated ({learned['confirmed']} newly confirmed) → {path}")
    state["_ruleset"] = ruleset
    _save_state_without_private(state)
    return state


def _save_state_without_private(state: dict) -> None:
    _save_state({key: value for key, value in state.items() if not key.startswith("_")})


def finalize(args, state: dict, env) -> dict:
    """Write the report and AVIT drafts (posting stubbed), applying credential redaction when real secrets were used."""
    findings = state.get("findings", [])
    drafts = servicenow_stub.publish_drafts([servicenow_stub.avit_draft(item, state["target"], state["run_id"])
                                             for item in findings if item["severity"] in ("CRITICAL", "HIGH", "MEDIUM")])
    state["avit_drafts"] = drafts
    ruleset = state.get("_ruleset") or load_ruleset(getattr(args, "rules", None))
    document = report.render(state, findings, ruleset, drafts, state.get("learned", {}))
    avits_json = json.dumps(drafts, indent=1)
    if state.get("_resolved"):
        document = creds.redact_resolved(document, state["_resolved"])
        avits_json = creds.redact_resolved(avits_json, state["_resolved"])
    report_path = os.path.join(state["work"], REPORT_FILE)
    with open(report_path, "w", encoding="utf-8") as handle:
        handle.write(document)
    with open(os.path.join(state["work"], AVITS_FILE), "w", encoding="utf-8") as handle:
        handle.write(avits_json)
    state["report"] = report_path
    _save_state_without_private(state)
    print(f"  ✓ Report: {report_path}")
    print(f"  ✓ AVIT drafts: {os.path.join(state['work'], AVITS_FILE)}"
          + (" (ServiceNow posting is stubbed)" if servicenow_stub.stubbed() else ""))
    return state


def teardown(args, state: dict, env, *, checkout: bool = True) -> dict:
    env.teardown(state)
    done = state.get("teardown", {})
    print(f"  ✓ Removed {done.get('containers', 0)} container(s), {done.get('networks', 0)} network(s), "
          f"{done.get('volumes', 0)} volume(s), {done.get('images', 0)} image(s)")
    if checkout and ar.remove_checkout(state.get("checkout")):
        print(f"  ✓ Deleted the checkout {state['checkout']}")
    _save_state_without_private(state)
    return state


def run(args, env=None) -> int:
    """Full assessment: provision → deploy → test → assess → report → teardown. Teardown always runs."""
    env = env or rt.provider(getattr(args, "env_provider", "docker"))
    work = os.path.realpath(args.work) if getattr(args, "work", None) else rt.scratch_dir()
    os.makedirs(work, exist_ok=True)
    state = {"work": work, "run_id": rt.DockerProvider.new_run_id()}
    print(f"threatlint redteam · run {state['run_id']} · {work}")
    ok = False
    try:
        for step in (provision, deploy, test, assess):
            print(f"[{step.__name__}]")
            step(args, state, env)
        ok = True
    finally:
        print("[finalize]")
        try:
            finalize(args, state, env)
        except Exception as exc:  # noqa: BLE001 - never lose teardown over a reporting error
            print(f"  ! Report not written: {exc}")
        print("[teardown]")
        teardown(args, state, env, checkout=not ok or not getattr(args, "keep_checkout", False))
    return 0 if ok else 1
