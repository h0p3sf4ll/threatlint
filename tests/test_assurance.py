"""Gated assurance pipeline: gate/DNF semantics, SAST normalization, app classification, vendor stubs, and the
full orchestrated run (SAST → dynamic) with a fake environment and injected SAST runner — no Docker, no Semgrep."""

import json
import types
import urllib.parse

import pytest

from threatlint import dast
from threatlint import runtime_env as rt
from threatlint.runtime_models import Plan, Service
from threatlint.assurance import appclass, gate, sast, vendors, pipeline


# ── A reflecting fake web app (mirrors the runtime red team's fake provider) ─────

class ReflectingEnv:
    name = "fake"

    def provision(self, state, plan): state.update(built=["app:fake"], network="tl-net"); return state
    def deploy(self, state): state["health"] = {"healthy": True, "default_route": False, "path": "/health"}; return state
    def run_tests(self, state): return state
    def teardown(self, state): state["teardown"] = {"containers": 1}; return state

    def probe(self, state, requests):
        responses = []
        for request in requests:
            reflected = urllib.parse.unquote(request["path"] + (request.get("body") or ""))
            responses.append({"id": request["id"], "status": 200, "headers": [["content-type", "text/html"]],
                              "body": f"<html>echo {reflected}</html>"})
        return responses


class QuietEnv(ReflectingEnv):
    """Returns security headers and never reflects input, so no CRITICAL/HIGH is observed."""
    def probe(self, state, requests):
        headers = [["content-type", "text/html"], ["x-content-type-options", "nosniff"],
                   ["content-security-policy", "default-src 'self'"], ["x-frame-options", "DENY"]]
        return [{"id": r["id"], "status": 200, "headers": headers, "body": "<html>ok</html>"} for r in requests]


def _args(tmp_path, **overrides):
    base = dict(repo=str(tmp_path / "src"), branch="main", work=str(tmp_path / "run"),
                semgrep_config="auto", env_provider="fake", keep_checkout=True, _sast_runner=None)
    base.update(overrides)
    return types.SimpleNamespace(**base)


def _sast_returning(*severities):
    """A fake Semgrep runner emitting one result per metadata severity."""
    results = [{"check_id": f"rule.{i}", "path": "app.py", "start": {"line": i + 1},
                "extra": {"message": f"finding {sev}", "severity": "ERROR", "metadata": {"severity": sev}}}
               for i, sev in enumerate(severities)]
    return lambda checkout, config: types.SimpleNamespace(stdout=json.dumps({"results": results}), stderr="", returncode=0)


@pytest.fixture
def fake_repo(monkeypatch, tmp_path):
    (tmp_path / "src").mkdir(exist_ok=True)  # repository_target requires --repo to be an existing local path
    def clone(target, directory):
        import os
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "server.js"), "w") as handle:
            handle.write("app.get('/search',(req,res)=>res.send(req.query['q']));\n")
    monkeypatch.setattr(dast, "clone", clone)
    plan = Plan(stack="node", services=[Service("app", "node:20-slim", role="app", port=3000)], app="app", port=3000,
                health_paths=["/health"], test_command="npm test", notes=["node"])
    monkeypatch.setattr(rt, "detect", lambda *a, **k: plan)


# ── Gate / DNF semantics ─────────────────────────────────────────────────────────

def test_gate_trips_only_on_critical_or_high():
    assert gate.evaluate([{"severity": "HIGH"}])["tripped"] is True
    assert gate.evaluate([{"severity": "CRITICAL"}])["tripped"] is True
    assert gate.evaluate([{"severity": "MEDIUM"}, {"severity": "LOW"}])["tripped"] is False
    assert gate.evaluate([])["tripped"] is False


def test_verdict_disqualifies_at_the_first_tripping_stage():
    stages = [{"name": "static analysis (SAST)", "status": "ran", "gate": {"tripped": True}},
              {"name": "dynamic analysis (Invicti)", "status": "ran", "gate": {"tripped": True}}]
    assert gate.verdict(stages) == ("DISQUALIFIED", "static analysis (SAST)")
    clean = [{"name": "a", "status": "ran", "gate": {"tripped": False}}]
    assert gate.verdict(clean) == ("QUALIFIED", None)
    errored = [{"name": "a", "status": "error", "gate": {}}]
    assert gate.verdict(errored) == ("ERROR", None)


# ── SAST normalization ───────────────────────────────────────────────────────────

def test_sast_maps_severity_and_normalizes():
    payload = {"results": [
        {"check_id": "py.sqli", "path": "a.py", "start": {"line": 3}, "extra": {"message": "SQLi", "severity": "ERROR", "metadata": {"severity": "CRITICAL"}}},
        {"check_id": "py.style", "path": "b.py", "start": {"line": 9}, "extra": {"message": "style", "severity": "INFO", "metadata": {}}},
    ]}
    findings = sast.normalize(payload)
    assert findings[0]["severity"] == "CRITICAL" and findings[0]["location"] == "a.py:3" and findings[0]["source"] == "semgrep"
    assert findings[1]["severity"] == "LOW"  # INFO level, no metadata severity


# ── App classification ───────────────────────────────────────────────────────────

def test_classify_detects_mobile_and_defaults_to_web(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text("<manifest/>")
    mobile = appclass.classify(str(tmp_path))
    assert mobile["type"] == "mobile" and mobile["platform"] == "android"
    web = tmp_path / "web"; web.mkdir(); (web / "package.json").write_text('{"dependencies":{"express":"4"}}')
    assert appclass.classify(str(web))["type"] == "web"


# ── Vendor stubs ─────────────────────────────────────────────────────────────────

def test_vendor_submissions_are_stubbed_then_use_a_provider():
    assert vendors.invicti_stubbed() and vendors.nowsecure_stubbed()
    assert vendors.submit_invicti({})["submitted"] is False
    try:
        vendors.set_nowsecure_provider(lambda ctx: {"reference": "NS-1", "findings": [{"severity": "HIGH", "title": "x"}]})
        result = vendors.submit_nowsecure({})
        assert result["submitted"] and result["reference"] == "NS-1" and result["findings"][0]["severity"] == "HIGH"
    finally:
        vendors.set_nowsecure_provider(None)


# ── Full pipeline: the DNF rule ──────────────────────────────────────────────────

def test_critical_sast_disqualifies_but_dynamic_still_runs(tmp_path, fake_repo):
    args = _args(tmp_path, _sast_runner=_sast_returning("CRITICAL"))
    rc = pipeline.run(args, env=ReflectingEnv())
    assert rc == 1
    state = json.loads((tmp_path / "run" / pipeline.STATE_FILE).read_text())
    assert state["verdict"] == "DISQUALIFIED" and state["disqualified_at"] == "static analysis (SAST)"
    # The finish line was still crossed: the dynamic stage ran to completion despite the SAST disqualification.
    dynamic = next(stage for stage in state["stages"] if stage["kind"] == "dast")
    assert dynamic["status"] == "ran" and dynamic.get("endpoints", 0) >= 1 and "teardown" not in dynamic.get("note", "")
    report_text = (tmp_path / "run" / pipeline.REPORT_FILE).read_text()
    assert "DISQUALIFIED" in report_text and "Invicti submission is stubbed" in report_text


def test_clean_repo_qualifies(tmp_path, fake_repo):
    args = _args(tmp_path, _sast_runner=_sast_returning("LOW", "INFO"))
    rc = pipeline.run(args, env=QuietEnv())
    assert rc == 0
    state = json.loads((tmp_path / "run" / pipeline.STATE_FILE).read_text())
    assert state["verdict"] == "QUALIFIED" and state["disqualified_at"] is None
    assert all(stage["status"] == "ran" for stage in state["stages"])


def test_mobile_repo_routes_to_nowsecure(tmp_path, fake_repo, monkeypatch):
    monkeypatch.setattr(appclass, "classify", lambda checkout: {"type": "mobile", "platform": "android", "signals": ["AndroidManifest.xml"]})
    args = _args(tmp_path, _sast_runner=_sast_returning("LOW"))
    rc = pipeline.run(args, env=None)  # no ephemeral build for mobile
    assert rc == 0
    state = json.loads((tmp_path / "run" / pipeline.STATE_FILE).read_text())
    mobile = next(stage for stage in state["stages"] if stage["kind"] == "mast")
    assert mobile["provider"] == "nowsecure" and mobile["status"] == "ran"
