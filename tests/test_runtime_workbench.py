"""Exercise lifecycle and credential handling without building or scanning real apps."""
from pathlib import Path

import pytest

from threatlint import runtime_workbench as bridge


class Environment:
    def __init__(self, fail=""):
        self.fail = fail
        self.cleaned = False
        self.work = None

    def provision(self, state, plan):
        self.work = state["work"]
        assert not (Path(self.work) / "repo" / ".env").exists()
        if self.fail == "build":
            raise RuntimeError("synthetic build failure")

    def deploy(self, state):
        if self.fail == "start":
            raise RuntimeError("synthetic startup failure")

    def run_tests(self, state):
        state["tests"] = {"status": "PASSED"}
        return state

    def probe(self, state, requests):
        return [{"id": request["id"], "status": 200, "headers": [], "body": "synthetic-secret"} for request in requests]

    def teardown(self, state):
        self.cleaned = True
        state["teardown"] = {"remaining": ["containers"] if self.fail == "cleanup" else []}


def config(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    (repo / "package.json").write_text('{"scripts":{"start":"node app.js"}}')
    (repo / ".env").write_text("PASSWORD=must-not-build")
    return {"repoPath": str(repo), "paths": ["/"], "auth": {"type": "bearer", "token": "synthetic-secret"},
            "limits": {"maxRequests": 20, "timeoutMs": 1000}}


def test_ephemeral_scan_cleans_up_and_redacts_echoed_credentials(tmp_path):
    env = Environment()
    result = bridge.run(config(tmp_path), provider=env)
    assert env.cleaned
    assert not Path(env.work).exists()
    assert result["responses"][0]["body"] == "<redacted credential>"
    assert result["cleanup"] == "complete"
    assert result["tests"]["status"] == "PASSED"


@pytest.mark.parametrize("failure", ["build", "start", "cleanup"])
def test_failure_still_attempts_exact_teardown_and_removes_work(tmp_path, failure):
    env = Environment(failure)
    with pytest.raises(RuntimeError):
        bridge.run(config(tmp_path), provider=env)
    assert env.cleaned
    assert not Path(env.work).exists()


def test_unsupported_external_auth_is_not_silently_anonymous():
    with pytest.raises(ValueError, match="isolated runtime"):
        bridge.auth_headers({"type": "oauth-client-credentials"})
