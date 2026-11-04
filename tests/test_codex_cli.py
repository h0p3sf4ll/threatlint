"""Signed-in Codex provider uses the CLI without extracting its credentials."""

from __future__ import annotations

import argparse
import io
import json
import subprocess
import types

import pytest

from threatlint import cli, codex_cli, run_context


class FakeProcess:
    def __init__(self, events, *, exit_code=0):
        self.events = events
        self.returncode = exit_code
        self.killed = False

    def __call__(self, argv, **options):
        self.argv = argv
        self.options = options
        self.stdin = io.StringIO()
        self.stdin.close = lambda: setattr(self, "prompt", self.stdin.getvalue())
        self.stdout = io.StringIO("".join(json.dumps(event) + "\n" for event in self.events))
        return self

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True


@pytest.mark.parametrize("stdout, stderr", [
    ("Logged in using ChatGPT\n", ""),
    ("", "Logged in using ChatGPT\n"),
])
def test_codex_login_status_uses_cli_not_auth_file(monkeypatch, stdout, stderr):
    def run(argv, **options):
        assert argv == ["/bin/codex", "login", "status"]
        assert options["env"]["CODEX_HOME"] == "/synthetic/codex"
        assert "OPENAI_API_KEY" not in options["env"]
        return types.SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr)

    monkeypatch.setenv("CODEX_HOME", "/synthetic/codex")
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-pass")
    monkeypatch.setattr(subprocess, "run", run)
    assert codex_cli.login_status("/bin/codex") == codex_cli.LoginStatus(True, True)


@pytest.mark.parametrize("status, expected", [
    (codex_cli.LoginStatus(False), None),
    (codex_cli.LoginStatus(True, False), None),
    (codex_cli.LoginStatus(True, True), ("codex", "", "")),
])
def test_provider_uses_signed_in_codex_without_key(monkeypatch, status, expected):
    monkeypatch.setattr(codex_cli, "login_status", lambda: status)
    args = argparse.Namespace(provider="codex", api_key="", daybreak_blue=False)
    assert run_context._resolve_provider(args) == expected
    assert run_context._default_run_model("codex") == ""


def test_codex_provider_rejects_explicit_api_key(monkeypatch, capsys):
    monkeypatch.setattr(codex_cli, "login_status", lambda: pytest.fail("Login check must not run"))
    args = argparse.Namespace(provider="codex", api_key="synthetic", daybreak_blue=False)
    assert run_context._resolve_provider(args) is None
    assert "does not accept --api-key" in capsys.readouterr().out


def test_daybreak_blue_flag_does_not_silently_apply_to_other_providers(capsys):
    args = argparse.Namespace(provider="openai", api_key="", daybreak_blue=True)
    assert run_context._resolve_provider(args) is None
    assert "only supported with --provider codex" in capsys.readouterr().out


def test_codex_run_is_ephemeral_read_only_and_keyless(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "do-not-pass")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "do-not-pass")
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "do-not-pass")
    monkeypatch.setenv("CODEX_HOME", "/synthetic/codex")
    events = [
        {"type": "item.completed", "item": {"type": "command_execution", "command": "rg pattern"}},
        {"type": "item.completed", "item": {"type": "agent_message", "text": "# Report\nTM-001"}},
        {"type": "turn.completed", "usage": {}},
    ]
    fake = FakeProcess(events)
    progress = []
    result = codex_cli.run_agent("You are the threat modeler.", "Analyze this repo",
                                 str(tmp_path), codex="/bin/codex",
                                 popen=fake, progress=progress.append)
    assert result == "# Report\nTM-001"
    argv = fake.argv
    assert argv[:3] == ["/bin/codex", "exec", "--json"]
    for value in ("read-only", "--ephemeral", "--ignore-user-config", "--skip-git-repo-check", str(tmp_path)):
        assert value in argv
    assert argv[-1] == "-"
    assert not any("threat modeler" in part or "Analyze this repo" in part for part in argv)
    assert "You are the threat modeler." in fake.prompt and "Analyze this repo" in fake.prompt
    assert fake.options["env"]["CODEX_HOME"] == "/synthetic/codex"
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_BEARER_TOKEN_BEDROCK"):
        assert name not in fake.options["env"]
    assert progress == ["  → Codex inspected evidence"]


def test_codex_daybreak_blue_uses_documented_headless_setting(tmp_path):
    fake = FakeProcess([
        {"type": "item.completed", "item": {"type": "agent_message", "text": "report"}},
        {"type": "turn.completed"},
    ])
    codex_cli.run_agent("role", "request", str(tmp_path), "gpt-6-sol",
                        daybreak_blue=True, codex="/bin/codex", popen=fake)
    assert fake.argv[fake.argv.index("-m") + 1] == "gpt-6-sol"
    assert "--strict-config" in fake.argv
    assert fake.argv[fake.argv.index("-c") + 1] == "daybreak=true"


def test_completed_turn_is_returned_even_if_codex_cleanup_stalls(tmp_path):
    class SlowExit(FakeProcess):
        def wait(self, timeout=None):
            if not self.killed:
                raise subprocess.TimeoutExpired("codex", timeout)
            return -9

        def poll(self):
            return None if not self.killed else -9

    fake = SlowExit([
        {"type": "item.completed", "item": {"type": "agent_message", "text": "report"}},
        {"type": "turn.completed"},
    ])
    assert codex_cli.run_agent("role", "request", str(tmp_path),
                               codex="/bin/codex", popen=fake) == "report"
    assert fake.killed


@pytest.mark.parametrize("events, exit_code", [
    ([{"type": "item.completed", "item": {"type": "agent_message", "text": "partial"}}], 0),
    ([{"type": "turn.failed", "error": {"message": "secret-should-not-echo"}}], 1),
    ([{"type": "turn.completed"}], 0),
])
def test_codex_does_not_save_incomplete_or_failed_report(tmp_path, events, exit_code):
    with pytest.raises(codex_cli.CodexError) as exc:
        codex_cli.run_agent("role", "request", str(tmp_path), codex="/bin/codex",
                            popen=FakeProcess(events, exit_code=exit_code))
    assert "secret-should-not-echo" not in str(exc.value)


def test_codex_rejects_corrupt_jsonl_and_noncompleted_status(tmp_path):
    with pytest.raises(codex_cli.CodexError, match="invalid event stream"):
        codex_cli.run_agent("role", "request", str(tmp_path), codex="/bin/codex",
                            popen=FakeProcess(["not-json"]))
    events = [
        {"type": "item.completed", "item": {"type": "agent_message", "text": "report"}},
        {"type": "turn.completed", "turn": {"status": "interrupted"}},
    ]
    with pytest.raises(codex_cli.CodexError, match="failed"):
        codex_cli.run_agent("role", "request", str(tmp_path), codex="/bin/codex",
                            popen=FakeProcess(events))


def test_codex_cli_parser_and_daybreak_flag():
    args = cli.build_parser().parse_args(["run", "threat-model", "--provider", "codex", "--daybreak-blue"])
    assert args.provider == "codex" and args.daybreak_blue
    assert run_context._default_run_model("codex", args.model) == ""
    assert "daybreak=true" in codex_cli.command("/bin/codex", "/repo", daybreak_blue=True)


@pytest.mark.parametrize("extra, expected_model, expected_blue", [
    ([], "", False),
    (["--daybreak-blue"], "gpt-6-sol", True),
    (["--daybreak-blue", "--model", "gpt-6-luna"], "gpt-6-luna", True),
])
def test_cli_routes_agent_to_signed_in_codex(monkeypatch, tmp_path, extra, expected_model, expected_blue):
    monkeypatch.setattr(codex_cli, "login_status", lambda: codex_cli.LoginStatus(True, True))
    monkeypatch.setattr(cli, "_git_output", lambda *args: str(tmp_path))
    seen = []
    monkeypatch.setattr(codex_cli, "run_agent",
                        lambda *args, **kwargs: seen.append((args, kwargs)) or "# Report\n")
    monkeypatch.setattr(cli, "_save_report", lambda *args: tmp_path / "report.md")
    args = cli.build_parser().parse_args(
        ["run", "secrets-scan", "--provider", "codex", "--output-dir", str(tmp_path), *extra]
    )
    assert cli.cmd_run(args) == 0
    positional, kwargs = seen[0]
    assert positional[2] == str(tmp_path)
    assert positional[3] == expected_model
    assert kwargs["daybreak_blue"] is expected_blue


def test_daybreak_direct_uses_openai_base_url(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic")
    args = argparse.Namespace(provider="daybreak", api_key="", model="", daybreak_blue=False)
    assert run_context._resolve_provider(args) == ("daybreak", "https://api.openai.com/v1", "synthetic")
