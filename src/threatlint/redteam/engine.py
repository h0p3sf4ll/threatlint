"""Probe one deployed endpoint with the applicable ruleset, bounded and sandbox-only.

Every request is built by the vetted `dast_requests.plan_requests` / `_request` and assessed by `dast_probe.assess`
and `dast_passive.passive_checks`; this module only chooses which rules to run per endpoint and caps the totals. One
baseline round per endpoint feeds every passive rule; active rules run per targeted parameter. Observations are never
verdicts — they become candidate findings the report hands to the reviewer. Raw responses stay local; only redacted
evidence leaves this module.
"""

from __future__ import annotations

from threatlint.dast_evidence import redact_response, redact_text
from threatlint.dast_passive import passive_checks
from threatlint.dast_probe import assess
from threatlint.dast_requests import PROBE_ORIGIN, _request, plan_requests

MAX_PROBES = 400          # hard ceiling on probe requests per assessment
MAX_PARAMS_PER_RULE = 4   # targeted parameters per active rule per endpoint

# Passive ruleset kinds share one baseline round; map the passive_checks rule ids onto our ruleset rule ids.
_PASSIVE_RULE = {"RT-CORS-REFLECT": "RT-RT-CORS", "RT-COOKIE-FLAGS": "RT-RT-COOKIE", "RT-HDR-HSTS": "RT-RT-HEADERS",
                 "RT-HDR-CSP": "RT-RT-HEADERS", "RT-HDR-XCTO": "RT-RT-HEADERS", "RT-HDR-FRAME": "RT-RT-HEADERS",
                 "RT-DISCLOSE-VERSION": "RT-RT-DISCLOSE", "RT-DEBUG-LEAK": "RT-RT-DEBUG"}


def _finding(endpoint: dict, kind: str, parameter: str = "") -> dict:
    """A synthetic finding dict in the shape plan_requests/assess expect, scoped to the sandbox path."""
    params = endpoint.get("params") or []
    return {"kind": kind, "method": endpoint["method"], "path": endpoint["path"], "parameter": parameter,
            "query": "&".join(f"{name}=1" for name in params), "vulnerability": "", "scanned_origin": "(none; discovered from source)"}


class Budget:
    """Shared probe-request ceiling across all endpoints in one assessment."""

    def __init__(self, limit: int = MAX_PROBES):
        self.remaining = limit

    def take(self, count: int) -> bool:
        if self.remaining < count:
            return False
        self.remaining -= count
        return True


def _baseline_round(state: dict, env, endpoint: dict, marker: str, budget: Budget) -> list[dict]:
    """One baseline request (plus a CORS Origin request) for the endpoint; returns raw responses."""
    base = _finding(endpoint, "generic")
    requests = [_request("baseline", base)]
    requests.append(_request("origin", {**base, "parameter": ""}, None, {"Origin": PROBE_ORIGIN}))
    if not budget.take(len(requests)):
        return []
    return env.probe(state, requests), requests


def assess_endpoint(state: dict, env, ruleset, endpoint: dict, run_id: str, budget: Budget) -> list[dict]:
    """Run the applicable rules against one endpoint; update the ruleset's learned stats; return candidate findings."""
    applicable = ruleset.applicable(state.get("stack", ""), endpoint)
    passive_rules = {rule.id: rule for rule in applicable if not rule.applies.get("needs_param")}
    active_rules = [rule for rule in applicable if rule.applies.get("needs_param")]
    findings: list[dict] = []

    # One baseline round serves every passive rule for this endpoint.
    if passive_rules:
        outcome = _baseline_round(state, env, endpoint, run_id, budget)
        responses, requests = outcome if outcome else ([], [])
        observed = [item for response in responses for item in passive_checks(response, endpoint["path"])]
        hit_rules = {}
        for item in observed:
            rule_id = _PASSIVE_RULE.get(item["rule"])
            if rule_id in passive_rules:
                hit_rules.setdefault(rule_id, []).append(item)
        # Directory listing has no passive_checks entry; read it from the baseline body.
        if "RT-RT-DIRLIST" in passive_rules and any("index of" in (redact_text(r.get("body", "")) or "").lower()
                                                     or "directory listing for" in (r.get("body", "")).lower() for r in responses):
            hit_rules.setdefault("RT-RT-DIRLIST", []).append({"observation": f"{endpoint['path']} returned a directory index"})
        for rule_id, rule in passive_rules.items():
            hits = hit_rules.get(rule_id, [])
            signal = "; ".join(item["observation"] for item in hits) if hits else "not observed"
            ruleset.record(rule_id, endpoint, bool(hits), signal, run_id)
            if hits:
                findings.append(_candidate(rule, endpoint, "", [item["observation"] for item in hits], responses, run_id))

    # Active rules target each parameter of the endpoint, bounded.
    for rule in active_rules:
        for parameter in (endpoint.get("params") or [])[:MAX_PARAMS_PER_RULE]:
            finding = _finding(endpoint, rule.kind, parameter)
            try:
                requests = plan_requests(finding, run_id)
            except Exception:  # noqa: BLE001 - an unplannable parameter is skipped, not fatal
                continue
            if not budget.take(len(requests)):
                return findings
            responses = env.probe(state, requests)
            result = assess(finding, requests, responses, run_id)
            confirmed = result["observed"] is True
            ruleset.record(rule.id, endpoint, confirmed, "; ".join(result["signals"][:3]), run_id)
            if confirmed:
                findings.append(_candidate(rule, endpoint, parameter, result["signals"], responses, run_id))
    return findings


def _candidate(rule, endpoint: dict, parameter: str, signals: list[str], responses: list[dict], run_id: str) -> dict:
    """A confirmed observation as a candidate finding, with redacted evidence."""
    return {"rule_id": rule.id, "title": rule.title, "category": rule.category, "cwe": rule.cwe, "severity": rule.severity,
            "kind": rule.kind, "method": endpoint["method"], "path": endpoint["path"], "parameter": parameter,
            "signals": signals, "evidence": [redact_response(response, run_id) for response in responses]}
