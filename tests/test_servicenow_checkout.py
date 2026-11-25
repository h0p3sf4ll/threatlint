"""Checkout fallback boundaries use synthetic subprocess results only."""

import subprocess
from types import SimpleNamespace

import pytest

from threatlint import servicenow as sn
from threatlint import servicenow_checkout as checkout

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


def test_successful_host_checkout_is_marked_for_owned_cleanup(monkeypatch, tmp_path):
    destination = tmp_path / "new-checkout"
    monkeypatch.setattr(sn.shutil, "which", lambda name: "/synthetic/git")
    monkeypatch.setattr(sn, "_git_auth_env", lambda *args: {})
    def clone(*_args, **_kwargs):
        (destination / ".git").mkdir(parents=True)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(sn.subprocess, "run", clone)
    assert sn.checkout_repository(TARGET, str(destination)) == str(destination)
    assert checkout.remove_owned_checkout(str(destination)) is True
    assert not destination.exists()


def test_sparse_checkout_stops_after_the_first_failed_command(monkeypatch, tmp_path):
    calls = []
    failure = SimpleNamespace(returncode=1, stderr="synthetic failure")
    monkeypatch.setattr(sn.subprocess, "run", lambda command, **kwargs: calls.append(command) or failure)
    assert sn._sparse_clone("/synthetic/git", TARGET, str(tmp_path), "src/a.py", {}) is failure
    assert len(calls) == 1
    assert calls[0][-2:] == [TARGET["clone_url"], str(tmp_path)]


@pytest.mark.parametrize("scm", ["github", "azure-devops"])
def test_windows_worktree_failure_retries_the_selected_source_without_reauth(monkeypatch, tmp_path, scm):
    monkeypatch.setattr(checkout.sys, "platform", "win32")
    monkeypatch.setattr(sn.shutil, "which", lambda name: "/synthetic/git")
    monkeypatch.setattr(sn, "_git_auth_env", lambda *args: {})
    commands, fallbacks = [], []
    def fail_clone(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=128, stderr="error: invalid path 'unrelated:windows-file'\nwarning: Clone succeeded, but checkout failed.\nand retry with 'git restore --source=HEAD :/'")
    monkeypatch.setattr(sn.subprocess, "run", fail_clone)
    monkeypatch.setattr(sn, "_ado_folder_download", lambda target, directory, file_path: fallbacks.append((target["branch"], file_path, "ado")))
    monkeypatch.setattr(sn, "_sparse_clone", lambda git, target, directory, file_path, env: fallbacks.append((target["branch"], file_path, "sparse")) or SimpleNamespace(returncode=0))
    directory = str(tmp_path / "copy")
    target = {**TARGET, "scm": scm, "branch": "tasks/27838532-example"}
    assert sn.checkout_repository(target, directory, "src/app.py") == directory
    assert commands[0][1:4] == ["-c", "core.longpaths=true", "clone"]
    assert fallbacks == [(target["branch"], "src/app.py", "ado" if scm == "azure-devops" else "sparse")]


def test_worktree_diagnostic_never_recommends_replacing_a_pat_or_echoes_stderr():
    reason = checkout.checkout_failure("error: filename too long synthetic-secret\nwarning: Clone succeeded, but checkout failed.\nand retry with 'git restore --source=HEAD :/'", {**TARGET, "scm": "azure-devops"})
    assert "working tree" in reason and "Linux/WSL" in reason
    assert "synthetic-secret" not in reason and "PAT" not in reason and "ado login" not in reason
    assert "Code: Read" in checkout.checkout_failure("fatal: Authentication failed", {**TARGET, "scm": "azure-devops"})


def test_readonly_partial_checkout_is_made_writable_for_cleanup(monkeypatch, tmp_path):
    locked = tmp_path / "readonly-object"
    locked.write_text("synthetic object")
    locked.chmod(0o400)
    def failing_remove(directory, onerror):
        onerror(lambda value: __import__('os').unlink(value), str(locked), (PermissionError, PermissionError("locked"), None))
    monkeypatch.setattr(checkout.shutil, "rmtree", failing_remove)
    checkout.remove_checkout(str(tmp_path))
    assert not locked.exists()


def test_authentication_failure_is_not_treated_as_a_windows_filename_problem(monkeypatch, tmp_path):
    monkeypatch.setattr(checkout.sys, "platform", "win32")
    monkeypatch.setattr(sn.shutil, "which", lambda name: "/synthetic/git")
    monkeypatch.setattr(sn, "_git_auth_env", lambda *args: {})
    monkeypatch.setattr(sn.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=128, stderr="fatal: Authentication failed"))
    monkeypatch.setattr(sn, "_ado_folder_download", lambda *args: pytest.fail("must not retry authentication errors as checkout errors"))
    with pytest.raises(sn.ServiceNowError, match="authentication or read access"):
        sn.checkout_repository({**TARGET, "scm": "azure-devops"}, str(tmp_path / "copy"), "src/app.py")


@pytest.mark.parametrize('source_path', ['/../outside', '/src/../../outside', '/src/NUL', '/src/CON.txt', '/src/a:b.py', '/src/trailing.'])
def test_folder_fallback_rejects_windows_devices_and_escaping_paths(monkeypatch, tmp_path, source_path):
    monkeypatch.setattr(checkout.sys, 'platform', 'win32')
    with pytest.raises(ValueError):
        checkout.source_destination(str(tmp_path), source_path)
