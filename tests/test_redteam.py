"""Runtime red-team assessment: ruleset + learning store, bounded sandbox-only probing via a fake provider,
endpoint discovery, credential resolution/redaction, AVIT stub, and the full orchestrated flow."""

import json
import types
import urllib.parse

import pytest

from threatlint import runtime_env as rt
from threatlint import dast
from threatlint.runtime_models import Plan, Service
from threatlint.redteam import credentials, discovery, servicenow_stub
from threatlint.redteam import rules as rules_mod
from threatlint.redteam.rules import Ruleset, load_ruleset, save_ruleset
from threatlint.redteam import assessment


# ── A reflecting fake application provider (no Docker, no network) ──────────────

class FakeEnv:
    """Implements the provider lifecycle. probe() reflects each request into an HTML response with no security
    headers, so XSS, missing-headers and CORS-reflection rules observe behaviour but SQLi/traversal do not."""

    name = "fake"

    def __init__(self):
        self.probe_calls = 0

    def provision(self, state, plan):
        state.update(built=["app:fake"], network="tl-net-fake")
        return state

    def deploy(self, state):
        state["health"] = {"healthy": True, "default_route": False, "path": "/health", "responses": []}
        return state

    def run_tests(self, state):
        state["tests"] = {"status": "PASSED", "command": "npm test", "exit": 0, "tail": ""}
        return state

    def probe(self, state, requests):
        self.probe_calls += len(requests)
        responses = []
        for request in requests:
            reflected = urllib.parse.unquote(request["path"] + (request.get("body") or ""))
            headers = [["content-type", "text/html"]]
            origin = (request.get("headers") or {}).get("Origin")
            if origin:
                headers.append(["access-control-allow-origin", origin])
            responses.append({"id": request["id"], "status": 200, "headers": headers, "body": f"<html>echo {reflected}</html>"})
        return responses

    def teardown(self, state):
        state["teardown"] = {"containers": 1, "networks": 1, "volumes": 0, "images": 1, "remaining": []}
        return state


def _args(tmp_path, **overrides):
    base = dict(repo="/repo", branch="main", routes=None, credentials=None, rules=str(tmp_path / "ruleset.json"),
                work=str(tmp_path / "run"), env_provider="fake", service=None, port=None, health_path=None,
                start_command=None, keep_checkout=False, aws_profile=None, test_command=None)
    base.update(overrides)
    return types.SimpleNamespace(**base)


@pytest.fixture
def fake_repo(monkeypatch):
    """Clone writes a tiny app with one parameterised route; detect returns a fixed plan."""
    def clone(target, directory):
        import os
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "server.js"), "w") as handle:
            handle.write("app.get('/search', (req,res)=>{ const q = req.query['q']; res.send(q); });\n")
    monkeypatch.setattr(dast, "clone", clone)
    plan = Plan(stack="node", services=[Service("app", "node:20-slim", role="app", port=3000)], app="app", port=3000,
                health_paths=["/health"], test_command="npm test", notes=["detected node"])
    monkeypatch.setattr(rt, "detect", lambda *a, **k: plan)


# ── Ruleset and learning store ─────────────────────────────────────────────────

def test_builtin_ruleset_covers_the_probe_kinds_and_orders_by_priority():
    ruleset = Ruleset.seed()
    assert {rule.kind for rule in ruleset.rules.values()} >= set(rules_mod.ACTIVE_KINDS)
    endpoint = {"method": "GET", "path": "/search", "params": ["q"]}
    applicable = ruleset.applicable("node", endpoint)
    assert any(rule.kind == "sqli" for rule in applicable) and any(rule.kind == "headers" for rule in applicable)
    # Without a parameter, active rules drop out; passive rules remain.
    passive_only = ruleset.applicable("node", {"method": "GET", "path": "/", "params": []})
    assert all(not rule.applies.get("needs_param") for rule in passive_only)


def test_learning_persists_and_reorders(tmp_path):
    path = str(tmp_path / "rs.json")
    ruleset = load_ruleset(path)
    endpoint = {"method": "GET", "path": "/api/pay/charge", "params": ["id"]}
    ruleset.record("RT-RT-SQLI", endpoint, confirmed=True, signal="db error", run_id="r1")
    ruleset.record("RT-RT-XSS", endpoint, confirmed=False, signal="not reflected", run_id="r1")
    save_ruleset(ruleset, path)
    import os
    # Windows stat mode bits do not represent its ACLs; keep persistence checks on every OS.
    if os.name != "nt":
        assert os.stat(path).st_mode & 0o777 == 0o600
    assert sorted(item.name for item in tmp_path.iterdir()) == ["rs.json"]
    reloaded = load_ruleset(path)
    assert reloaded.rules["RT-RT-SQLI"].hits == 1 and reloaded.rules["RT-RT-SQLI"].runs == 1
    assert reloaded.rules["RT-RT-SQLI"].affinity.get("pay") == 1
    # On a similar endpoint, the confirmed rule now outranks an unproven same-tier rule.
    order = [rule.id for rule in reloaded.applicable("node", {"method": "GET", "path": "/api/pay/refund", "params": ["id"]})]
    assert order.index("RT-RT-SQLI") < order.index("RT-RT-REDIRECT")


def test_load_keeps_learned_only_rule_and_ignores_unknown_kind(tmp_path):
    path = tmp_path / "rs.json"
    path.write_text(json.dumps({"version": 1, "rules": [
        {"id": "RT-RT-LEARNED", "title": "x", "category": "c", "cwe": "CWE-1", "severity": "LOW", "kind": "cors", "runs": 3, "hits": 1},
        {"id": "RT-RT-BOGUS", "title": "x", "category": "c", "cwe": "CWE-1", "severity": "LOW", "kind": "not-a-kind"}]}))
    ruleset = load_ruleset(str(path))
    assert ruleset.rules["RT-RT-LEARNED"].source == "learned" and "RT-RT-BOGUS" not in ruleset.rules


# ── Discovery ──────────────────────────────────────────────────────────────────

def test_discovery_reads_routes_source_health_and_is_bounded(tmp_path, fake_repo):
    checkout = tmp_path / "repo"
    checkout.mkdir()
    (checkout / "server.js").write_text("app.post('/login', h); router.get('/users/:id', h); const q=req.query['next'];")
    plan = Plan("node", [], "app", 3000, ["/health"], "npm test")
    found = {(e["method"], e["path"]) for e in discovery.discover(str(checkout), plan)}
    assert ("POST", "/login") in found and ("GET", "/users/1") in found and ("GET", "/health") in found
    routes = tmp_path / "routes.txt"
    routes.write_text("GET /admin\nPUT /api/config\n")
    with_routes = {(e["method"], e["path"]) for e in discovery.discover(str(checkout), plan, routes_file=str(routes))}
    assert ("GET", "/admin") in with_routes and ("PUT", "/api/config") in with_routes


# ── AVIT stub ──────────────────────────────────────────────────────────────────

def test_avit_drafts_are_stubbed_then_use_a_registered_publisher():
    finding = {"title": "Reflected XSS", "category": "A03", "cwe": "CWE-79", "severity": "HIGH", "rule_id": "RT-RT-XSS",
               "method": "GET", "path": "/search", "parameter": "q", "signals": ["reflected"]}
    draft = servicenow_stub.avit_draft(finding, {"web_url": "https://git/x", "branch": "main"}, "run1")
    assert servicenow_stub.stubbed()
    stubbed = servicenow_stub.publish_drafts([draft])
    assert stubbed[0]["posted"] is False and "stubbed" in stubbed[0]["note"]
    try:
        servicenow_stub.set_avit_publisher(lambda d: "AVIT00012345")
        posted = servicenow_stub.publish_drafts([draft])
        assert posted[0]["posted"] and posted[0]["reference"] == "AVIT00012345"
    finally:
        servicenow_stub.set_avit_publisher(None)


# ── Credentials (opt-in, reference-only, redacted) ─────────────────────────────

def test_credentials_resolve_from_store_and_reject_literals(tmp_path):
    good = tmp_path / "creds.json"
    good.write_text(json.dumps({"store": "aws-parameter-store", "secrets": {"DB_PASSWORD": "/app/db", "API_KEY": "/app/api"}}))
    config = credentials.load_config(str(good))
    resolved = credentials.resolve(config, reader=lambda ref: {"/app/db": "s3cr3t-db", "/app/api": "k-9"}[ref])
    assert resolved == {"DB_PASSWORD": "s3cr3t-db", "API_KEY": "k-9"}
    assert credentials.redact_resolved("log: s3cr3t-db and k-9", resolved) == "log: <resolved-credential> and <resolved-credential>"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"store": "aws-parameter-store", "secrets": {"X": "literal-not-a-ref"}}))
    with pytest.raises(Exception, match="store reference"):
        credentials.load_config(str(bad))


# ── Full orchestrated assessment ───────────────────────────────────────────────

def test_assessment_finds_issues_learns_drafts_avits_and_tears_down(tmp_path, fake_repo, monkeypatch):
    monkeypatch.setattr(assessment.ar, "remove_checkout", lambda path: False)
    env = FakeEnv()
    rc = assessment.run(_args(tmp_path, repo=str(tmp_path)), env=env)
    assert rc == 0
    report_text = (tmp_path / "run" / assessment.REPORT_FILE).read_text(encoding="utf-8")
    assert "Runtime Red Team Assessment" in report_text and "Ruleset coverage and learning" in report_text
    # Reflecting app with no headers → XSS, missing-headers, and CORS reflection observed.
    assert "Reflected cross-site scripting" in report_text
    drafts = json.loads((tmp_path / "run" / assessment.AVITS_FILE).read_text(encoding="utf-8"))
    assert drafts and all(item["posted"] is False for item in drafts)
    assert any(item["rule_id"] == "RT-RT-XSS" for item in drafts)
    # Isolation and probe bound held.
    assert env.probe_calls <= assessment.engine.MAX_PROBES
    # Learning persisted: XSS confirmed at least once, with affinity for the /search endpoint shape.
    learned = load_ruleset(str(tmp_path / "ruleset.json"))
    assert learned.rules["RT-RT-XSS"].hits >= 1 and "search" in learned.rules["RT-RT-XSS"].affinity
    assert learned.rules["RT-RT-SQLI"].runs >= 1 and learned.rules["RT-RT-SQLI"].hits == 0


def test_assessment_redacts_resolved_credentials_from_outputs(tmp_path, fake_repo, monkeypatch):
    monkeypatch.setattr(assessment.ar, "remove_checkout", lambda path: False)
    config = tmp_path / "creds.json"
    config.write_text(json.dumps({"store": "aws-parameter-store", "secrets": {"TOKEN": "/app/token"}}))
    monkeypatch.setattr(credentials, "resolve", lambda cfg, profile=None, **k: {"TOKEN": "supersecretvalue"})
    assessment.run(_args(tmp_path, repo=str(tmp_path), credentials=str(config)), env=FakeEnv())
    report_text = (tmp_path / "run" / assessment.REPORT_FILE).read_text(encoding="utf-8")
    assert "supersecretvalue" not in report_text and "resolved from aws-parameter-store" in report_text
