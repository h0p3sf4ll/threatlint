"""GitHub Copilot CLI provider uses a read-only, noninteractive review run."""

from __future__ import annotations

import argparse
import subprocess

import pytest

from threatlint import cli, copilot_cli, run_context


def test_copilot_provider_checks_installed_cli_without_api_key(monkeypatch, capsys):
    monkeypatch.setattr(copilot_cli, "executable", lambda: "/bin/copilot")
    assert run_context._resolve_provider(argparse.Namespace(provider="copilot", api_key="", daybreak_blue=False)) == ("copilot", "", "")
    assert run_context._default_run_model("copilot") == ""
    monkeypatch.setattr(copilot_cli, "executable", lambda: None)
    assert run_context._resolve_provider(argparse.Namespace(provider="copilot", api_key="", daybreak_blue=False)) is None
    assert "not installed" in capsys.readouterr().out
    assert run_context._resolve_provider(argparse.Namespace(provider="copilot", api_key="synthetic", daybreak_blue=False)) is None
    assert "does not accept --api-key" in capsys.readouterr().out


def test_copilot_command_allows_only_read_tools_and_no_ui(tmp_path):
    argv = copilot_cli.command("/bin/copilot", str(tmp_path), "selected-model")
    assert argv[:3] == ["/bin/copilot", "-C", str(tmp_path)]
    assert "--model" in argv and argv[argv.index("--model") + 1] == "selected-model"
    assert "--silent" in argv and "--no-ask-user" in argv
    assert "--available-tools=view,glob,grep" in argv
    assert "--deny-tool=shell,write,url,memory" in argv
    assert "--disable-builtin-mcps" in argv and "--no-custom-instructions" in argv
    assert "--sync-session=off" in argv and "--no-auto-update" in argv
    assert "-p" not in argv and "--allow-all-tools" not in argv


def test_copilot_report_prompt_uses_stdin_and_strips_other_provider_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-anthropic-secret")
    monkeypatch.setenv("COPILOT_ALLOW_ALL", "true")
    seen = {}

    class Process:
        returncode = 0

        def communicate(self, prompt, timeout):
            seen["prompt"] = prompt
            assert timeout == copilot_cli.RUN_TIMEOUT_S
            return "# FP Review\n", ""

    def popen(argv, **options):
        seen["argv"] = argv
        seen["options"] = options
        return Process()

    report = copilot_cli.run_agent("Reviewer role", "Inspect this repo", str(tmp_path), copilot="/bin/copilot", popen=popen)
    assert report == "# FP Review\n"
    assert "Reviewer role" in seen["prompt"] and "Inspect this repo" in seen["prompt"]
    assert "Reviewer role" not in " ".join(seen["argv"])
    assert seen["options"]["cwd"] == str(tmp_path)
    assert seen["options"]["env"]["COPILOT_ALLOW_ALL"] == "false"
    assert "ANTHROPIC_API_KEY" not in seen["options"]["env"]
    assert seen["options"]["stdin"] == subprocess.PIPE


@pytest.mark.parametrize("returncode,output", [(1, "report"), (0, "")])
def test_copilot_rejects_failed_or_empty_output(tmp_path, returncode, output):
    class Process:
        def __init__(self):
            self.returncode = returncode

        def communicate(self, _prompt, timeout):
            return output, "possible sensitive diagnostics"

    with pytest.raises(copilot_cli.CopilotError) as error:
        copilot_cli.run_agent("role", "request", str(tmp_path), copilot="/bin/copilot", popen=lambda *_a, **_kw: Process())
    assert "sensitive diagnostics" not in str(error.value)


@pytest.mark.parametrize("provider", ["claude", "claude-code", "codex", "copilot"])
def test_all_three_provider_families_route_to_the_same_headless_runner(monkeypatch, provider):
    from threatlint import avit_headless

    args = cli.build_parser().parse_args(["run", "fp-review", "--provider", provider,
                                          "--avit", "AVIT000000095938462", "--resolve-avits", "--yes"])
    monkeypatch.setattr(cli, "_resolve_provider", lambda _args: (provider, "https://api.example.test", "synthetic-key"))
    monkeypatch.setattr(cli, "_semgrep_version", lambda: "1.99")
    seen = {}
    monkeypatch.setattr(avit_headless, "run", lambda *values, **kwargs: seen.update(values=values, kwargs=kwargs) or 0)
    assert cli.cmd_run(args) == 0
    assert seen["values"][0] is args
    assert seen["kwargs"] == {"provider": provider, "base_url": "https://api.example.test", "api_key": "synthetic-key"}


def test_isst_requires_headless_mode_and_excludes_explicit_avit(monkeypatch, capsys):
    def parse(*options):
        return cli.build_parser().parse_args(["run", "fp-review", "--provider", "copilot", *options])

    assert cli.cmd_run(parse("--isst", "ISST0035374")) == 1
    assert "requires --resolve-avits --yes" in capsys.readouterr().out
    assert cli.cmd_run(parse("--isst", "ISST0035374", "--avit", "AVIT000000095938462", "--resolve-avits", "--yes")) == 1
    assert "discovers associated AVITs" in capsys.readouterr().out
