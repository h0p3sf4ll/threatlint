"""Checkout fallback boundaries use synthetic subprocess results only."""

import subprocess
from types import SimpleNamespace

import pytest

from threatlint import servicenow as sn

TARGET = {
    "scm": "github", "clone_url": "https://github.com/synthetic/repo.git",
    "web_url": "https://github.com/synthetic/repo", "branch": "main", "organization": "synthetic",
}


@pytest.mark.parametrize("scm", ["github", "azure-devops"])
def test_timeout_uses_the_current_original_fallback(monkeypatch, tmp_path, scm):
    monkeypatch.setattr(sn.shutil, "which", lambda name: "/synthetic/git")
    monkeypatch.setattr(sn, "_git_auth_env", lambda *args: {})

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("synthetic git", 1)

    monkeypatch.setattr(sn.subprocess, "run", timeout)
    seen = []
    monkeypatch.setattr(sn, "_ado_folder_download", lambda *args: seen.append("ado"))
    monkeypatch.setattr(sn, "_sparse_clone", lambda *args: seen.append("sparse") or SimpleNamespace(returncode=0))
    checkout = str(tmp_path / "checkout")
    assert sn.checkout_repository({**TARGET, "scm": scm}, checkout, "src/a.py") == checkout
    assert seen == (["sparse"] if scm == "github" else ["ado"])


def test_nonempty_checkout_is_rejected_before_starting_a_tool(monkeypatch, tmp_path):
    (tmp_path / "existing").write_text("synthetic")
    monkeypatch.setattr(sn.subprocess, "run", lambda *a, **k: pytest.fail("must not start git"))
    with pytest.raises(sn.ServiceNowError, match="not empty"):
        sn.checkout_repository(TARGET, str(tmp_path))


def test_sparse_checkout_stops_after_the_first_failed_command(monkeypatch, tmp_path):
    calls = []
    failure = SimpleNamespace(returncode=1, stderr="synthetic failure")
    monkeypatch.setattr(sn.subprocess, "run", lambda command, **kwargs: calls.append(command) or failure)
    assert sn._sparse_clone("/synthetic/git", TARGET, str(tmp_path), "src/a.py", {}) is failure
    assert len(calls) == 1
    assert calls[0][-2:] == [TARGET["clone_url"], str(tmp_path)]
