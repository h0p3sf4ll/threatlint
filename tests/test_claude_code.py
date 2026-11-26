"""Claude Code provider: locked-down argv, no API keys in the child, stream-json parsing, and errors. No real CLI."""

import io
import json
import subprocess
import types
from pathlib import Path

import pytest

from threatlint import claude_code, run_context


class FakeProcess:
    """Popen stand-in that records its call and replays stream-json lines."""

    def __init__(self, events, *, returncode=0, stderr=""):
        self.events, self.returncode, self._stderr = events, returncode, stderr
        self.calls = []

    def __call__(self, argv, **options):
        prompt_file = argv[argv.index("--system-prompt-file") + 1]
        self.call = {"argv": argv, "options": options, "system_prompt": open(prompt_file, encoding="utf-8").read(), "prompt_file": prompt_file}
        self.stdin = io.StringIO()
        self.stdin.close = lambda: self.call.setdefault("input", self.stdin.getvalue())
        self.stdout = io.StringIO("".join(json.dumps(event) + "\n" for event in self.events))
        options["stderr"].write(self._stderr)
        return self

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass


RESULT = {"type": "result", "subtype": "success", "is_error": False, "result": "# Threat model\n\nTM-001"}


def test_run_is_read_only_keyless_and_returns_the_report(monkeypatch, tmp_path):
    for name in claude_code.STRIPPED_ENV:
        monkeypatch.setenv(name, "provider-setting-should-not-pass")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "subscription-token")
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.invalid")
    fake = FakeProcess([{"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Grep", "input": {"pattern": "app.get"}}]}}, RESULT])
    progress = []
    report = claude_code.run_agent("You are the threat modeler.", "Analyze the repo", str(tmp_path), "claude-opus-5-5",
                                   claude="/bin/claude", progress=progress.append, popen=fake)
    assert report == RESULT["result"]
    argv = fake.call["argv"]
    for flag in ("-p", "--restricted", "--strict-mcp-config", "--no-session-persistence"):
        assert flag in argv
    assert argv[argv.index("--tools") + 1] == "Read,Grep,Glob"
    assert argv[argv.index("--permission-mode") + 1] == "dontAsk"
    assert argv[argv.index("--model") + 1] == "claude-opus-5-5"
    assert not any("threat modeler" in arg or "Analyze" in arg for arg in argv), "prompts never appear in argv"
    assert fake.call["system_prompt"] == "You are the threat modeler." and fake.call["input"] == "Analyze the repo"
    env = fake.call["options"]["env"]
    assert not set(claude_code.STRIPPED_ENV).intersection(env)
    assert "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST" not in env, "with it the CLI ignores the claude.ai login"
    assert env["CLAUDE_CODE_OAUTH_TOKEN"] == "subscription-token" and env["HTTPS_PROXY"] == "https://proxy.invalid"
    assert fake.call["options"]["cwd"] == str(tmp_path)
    assert progress == ["  → Grep(pattern='app.get')"]


@pytest.mark.parametrize("events, stderr, message", [
    ([{"type": "result", "subtype": "error_max_turns", "is_error": True, "result": "Reached max turns"}], "", "Reached max turns"),
    ([], "Not logged in · Please run /login", "sign in"),
    ([{"type": "result", "subtype": "success", "is_error": True, "result": "Credit balance is too low"}], "", "API-billed Anthropic Console account"),
])
def test_failures_are_explained(events, stderr, message, tmp_path):
    with pytest.raises(claude_code.ClaudeCodeError, match=message):
        claude_code.run_agent("s", "u", str(tmp_path), claude="/bin/claude", progress=lambda _line: None, popen=FakeProcess(events, returncode=1, stderr=stderr))


def test_missing_install_is_explained(monkeypatch, tmp_path):
    monkeypatch.setattr(claude_code, "executable", lambda: None)
    with pytest.raises(claude_code.ClaudeCodeError, match="not installed"):
        claude_code.run_agent("s", "u", str(tmp_path))


def test_login_status_reads_claude_auth_status(monkeypatch):
    for name in claude_code.STRIPPED_ENV:
        monkeypatch.setenv(name, "provider-setting-should-not-pass")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "subscription-token")
    monkeypatch.setenv("SSL_CERT_FILE", "/synthetic/cert.pem")
    monkeypatch.setenv("CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST", "1")  # inherited from a host process, it would hide the login
    def run(argv, **options):
        assert argv == ["/bin/claude", "auth", "status"]
        assert not set(claude_code.STRIPPED_ENV).intersection(options["env"])
        assert "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST" not in options["env"]
        assert options["env"]["CLAUDE_CODE_OAUTH_TOKEN"] == "subscription-token"
        assert options["env"]["SSL_CERT_FILE"] == "/synthetic/cert.pem"
        return types.SimpleNamespace(stdout='{"loggedIn": true, "authMethod": "claude.ai"}')
    monkeypatch.setattr(subprocess, "run", run)
    status = claude_code.login_status("/bin/claude")
    assert status.logged_in and status.label == "Claude Code login (claude.ai)"


@pytest.mark.parametrize("status, ok", [(claude_code.LoginStatus(True, True, "claude.ai"), True),
                                        (claude_code.LoginStatus(True, False), False), (claude_code.LoginStatus(False), False)])
def test_provider_needs_a_signed_in_claude_code_and_no_key(monkeypatch, capsys, status, ok):
    monkeypatch.setattr(claude_code, "login_status", lambda: status)
    resolved = run_context._resolve_provider(types.SimpleNamespace(provider="claude-code", api_key=""))
    assert (resolved == ("claude-code", "", "")) is ok
    assert run_context._default_run_model("claude-code") == "claude-opus-5-5"


def test_images_are_written_to_an_added_directory_and_listed(tmp_path):
    from threatlint.design_inputs import Image
    fake = FakeProcess([RESULT])
    claude_code.run_agent("s", "Model this", str(tmp_path), claude="/bin/claude", progress=lambda _line: None, popen=fake,
                          images=[Image("white board.png", "image/png", "cG5n")])
    argv = fake.call["argv"]
    directory = argv[argv.index("--add-dir") + 1]
    assert "Image files (open each with the Read tool):\n1. " in fake.call["input"]
    assert str(Path(directory) / "1-white_board.png") in fake.call["input"]


def _hanging_popen(script: str):
    import subprocess
    import sys
    return lambda _args, **kwargs: subprocess.Popen([sys.executable, "-c", script], **kwargs)


def test_a_stalled_run_is_stopped_with_the_last_error_line(monkeypatch, tmp_path):
    import time
    from threatlint import claude_code as cc

    monkeypatch.setattr(cc, "IDLE_TIMEOUT_S", 1)
    monkeypatch.setattr(cc, "_WATCHDOG_POLL_S", 0.05)
    script = ("import json, sys, time\n"
              "sys.stdin.read()\n"
              "print(json.dumps({'type': 'assistant', 'message': {'content': []}}), flush=True)\n"
              "print('API Error: 529 Overloaded. Retrying in 64 seconds', file=sys.stderr, flush=True)\n"
              "time.sleep(60)\n")
    started = time.monotonic()
    try:
        cc.run_agent("system", "user", str(tmp_path), claude="claude", progress=lambda _line: None, popen=_hanging_popen(script))
    except cc.ClaudeCodeError as exc:
        message = str(exc)
    else:
        raise AssertionError("a stalled run must raise")
    assert message.startswith("Claude Code stalled: no output for 0 minutes")
    assert "Last message from Claude Code: API Error: 529 Overloaded" in message
    assert time.monotonic() - started < 20, "stopped by the stall watchdog, not by the child finishing"


def test_the_overall_limit_also_applies_while_output_continues(monkeypatch, tmp_path):
    from threatlint import claude_code as cc

    monkeypatch.setattr(cc, "RUN_TIMEOUT_S", 1)
    monkeypatch.setattr(cc, "IDLE_TIMEOUT_S", 600)
    monkeypatch.setattr(cc, "_WATCHDOG_POLL_S", 0.05)
    script = ("import json, sys, time\nsys.stdin.read()\n"
              "while True:\n    print(json.dumps({'type': 'assistant', 'message': {'content': []}}), flush=True)\n    time.sleep(0.1)\n")
    try:
        cc.run_agent("system", "user", str(tmp_path), claude="claude", progress=lambda _line: None, popen=_hanging_popen(script))
    except cc.ClaudeCodeError as exc:
        assert str(exc).startswith("Claude Code did not finish within 0 minutes")
    else:
        raise AssertionError("an overlong run must raise")


def test_headless_review_retries_a_stalled_claude_code_run_once(monkeypatch, tmp_path):
    from threatlint import avit_headless, claude_code as cc

    calls = []

    def run_agent(*_args, **_kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise cc.ClaudeCodeError("Claude Code stalled: no output for 15 minutes, so the run was stopped.")
        return "# report"

    monkeypatch.setattr(cc, "run_agent", run_agent)
    assert avit_headless._run_review_model("claude-code", "s", "p", tmp_path, "m", None, "", "") == "# report"
    assert len(calls) == 2
    calls.clear()

    def failing(*_args, **_kwargs):
        calls.append(1)
        raise cc.ClaudeCodeError("Claude Code run failed: Credit balance is too low.")

    monkeypatch.setattr(cc, "run_agent", failing)
    try:
        avit_headless._run_review_model("claude-code", "s", "p", tmp_path, "m", None, "", "")
    except cc.ClaudeCodeError:
        pass
    assert len(calls) == 1, "other failures are not retried"
