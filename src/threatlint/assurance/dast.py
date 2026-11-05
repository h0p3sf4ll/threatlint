"""Dynamic stage: build + probe a web/API app in an ephemeral environment, or hand a mobile app to NowSecure.

Web/API: the checkout is built in the same bounded, no-egress ephemeral environment the runtime red team uses, and
probed with the shared runtime engine (the real dynamic scan); the target is also submitted to Invicti (stubbed).
Mobile: there is no ephemeral web build, so the checkout is submitted to NowSecure (stubbed). Both vendor
submissions are injectable — see ``vendors`` — and any findings they return feed the gate.

The environment provider is injectable so the web path is testable without Docker; teardown always runs.
"""

from __future__ import annotations

from threatlint.assurance import vendors


def _dedupe(findings: list[dict]) -> list[dict]:
    unique = {}
    for finding in findings:
        key = (finding.get("rule_id"), finding.get("path") or finding.get("location"), finding.get("parameter", ""))
        unique.setdefault(key, finding)
    return list(unique.values())


def web_dynamic(checkout: str, work: str, target: dict, run_id: str, *, env) -> dict:
    """Build the app, probe it with the runtime engine, submit to Invicti, and tear down (always)."""
    from threatlint import runtime_env as rt  # noqa: PLC0415
    from threatlint.redteam import discovery, engine  # noqa: PLC0415
    from threatlint.redteam.rules import Ruleset  # noqa: PLC0415

    plan = rt.detect(checkout, work)
    state = {"work": work, "stack": plan.stack, "run_id": run_id}
    findings: list[dict] = []
    endpoints: list[dict] = []
    budget = engine.Budget()
    try:
        env.provision(state, plan)
        env.deploy(state)
        endpoints = discovery.discover(checkout, plan)
        ruleset = Ruleset.seed()
        for endpoint in endpoints:
            findings += engine.assess_endpoint(state, env, ruleset, endpoint, run_id, budget)
    finally:
        try:
            env.teardown(state)
        except Exception:  # noqa: BLE001 - teardown failure must not mask the stage result
            state.setdefault("teardown", {"error": "teardown failed"})
    invicti = vendors.submit_invicti({"target": target, "stack": plan.stack, "endpoints": len(endpoints)})
    findings += invicti.get("findings", [])
    return {"provider": env.name, "stack": plan.stack, "endpoints": len(endpoints),
            "probe_count": engine.MAX_PROBES - budget.remaining, "health": state.get("health", {}),
            "teardown": state.get("teardown", {}), "invicti": invicti, "findings": _dedupe(findings)}


def mobile_dynamic(target: dict, app_class: dict) -> dict:
    """Submit the mobile build to NowSecure (stubbed unless a provider is registered)."""
    nowsecure = vendors.submit_nowsecure({"target": target, "platform": app_class.get("platform")})
    return {"provider": "nowsecure", "platform": app_class.get("platform"),
            "nowsecure": nowsecure, "findings": _dedupe(nowsecure.get("findings", []))}
