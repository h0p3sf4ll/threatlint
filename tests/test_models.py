"""Claude model policy: Sonnet for scanning, Opus for everything else; env/org.json overrides; explicit wins."""
import argparse
import importlib.util
import io
import json
import re
from pathlib import Path

import pytest

from threatlint import cli, models

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src" / "threatlint" / "data"


@pytest.fixture(autouse=True)
def _no_policy_env(monkeypatch):
    for name in ("THREATLINT_SCAN_MODEL", "THREATLINT_GENERAL_MODEL"):
        monkeypatch.delenv(name, raising=False)


def test_defaults_split_scanning_from_everything_else():
    assert models.SCAN_MODEL == "claude-opus-5-5"
    assert models.GENERAL_MODEL == "claude-opus-5-5"
    assert models.default_model("scan") == "claude-opus-5-5"
    assert models.default_model("general") == "claude-opus-5-5"
    with pytest.raises(ValueError):
        models.default_model("unknown")


def test_environment_overrides_each_default(monkeypatch):
    monkeypatch.setenv("THREATLINT_SCAN_MODEL", "scan-override")
    monkeypatch.setenv("THREATLINT_GENERAL_MODEL", "general-override")
    assert models.scan_model() == "scan-override"
    assert models.general_model() == "general-override"


def test_org_json_overrides_when_environment_is_unset(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    (tmp_path / "org.json").write_text(json.dumps({"scanModel": "org-scan", "generalModel": "org-general"}), encoding="utf-8")
    assert (models.scan_model(), models.general_model()) == ("org-scan", "org-general")
    monkeypatch.setenv("THREATLINT_SCAN_MODEL", "env-scan")
    assert models.scan_model() == "env-scan"


def test_explicit_model_wins():
    assert models.resolve("scan", "my-model") == "my-model"
    assert models.resolve("scan", "  ") == models.SCAN_MODEL
    assert models.resolve("general", None) == models.GENERAL_MODEL


def test_node_policy_mirrors_python_defaults():
    source = (ROOT / "web" / "lib" / "model-policy.cjs").read_text(encoding="utf-8")
    assert f"const SCAN_MODEL = '{models.SCAN_MODEL}';" in source
    assert f"const GENERAL_MODEL = '{models.GENERAL_MODEL}';" in source


# ── CLI ──────────────────────────────────────────────────────────────────────

def test_cli_run_defaults_claude_to_scan_model(monkeypatch):
    assert cli._default_run_model("claude") == models.SCAN_MODEL
    assert cli._default_run_model("claude", "claude-opus-5-5") == "claude-opus-5-5"
    assert cli._default_run_model("openai") == cli._OPENAI_DEFAULT_MODEL
    assert cli._default_run_model("lmstudio") == ""
    monkeypatch.setenv("THREATLINT_SCAN_MODEL", "env-scan")
    assert cli._default_run_model("claude") == "env-scan"


def test_cli_claude_provider_uses_anthropic_key(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    args = argparse.Namespace(provider="claude", api_key="", base_url="http://localhost:1234/v1")
    assert cli._resolve_provider(args) is None
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().out
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert cli._resolve_provider(args) == ("claude", "https://api.anthropic.com/v1", "sk-test")


def test_cli_run_with_claude_sends_scan_model_and_model_flag_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    seen = []
    monkeypatch.setattr(cli, "_run_agent", lambda base_url, model, *a, **k: seen.append((base_url, model)) or "# Report\n")
    monkeypatch.setattr(cli, "_save_report", lambda output, directory, base, mode: tmp_path / "report.md")
    parser = cli.build_parser()
    assert cli.cmd_run(parser.parse_args(["run", "secrets-scan", "--provider", "claude", "--output-dir", str(tmp_path)])) == 0
    assert cli.cmd_run(parser.parse_args(["run", "secrets-scan", "--provider", "claude", "--model", "claude-opus-5-5",
                                          "--output-dir", str(tmp_path)])) == 0
    assert seen == [("https://api.anthropic.com/v1", models.SCAN_MODEL), ("https://api.anthropic.com/v1", "claude-opus-5-5")]


# ── Bundled agents and slash commands ─────────────────────────────────────────

def _frontmatter_model(path):
    match = re.match(r"^---\n([\s\S]*?)\n---\n", path.read_text(encoding="utf-8"))
    found = re.search(r"^model:\s*(\S+)\s*$", match.group(1), re.MULTILINE)
    return found.group(1) if found else None


@pytest.mark.parametrize("folder", [DATA / "agents", ROOT / ".claude" / "agents"], ids=["bundled", "project"])
def test_analysis_agents_run_on_the_scan_model(folder):
    agents = sorted(folder.glob("appsec-*.md"))
    assert len(agents) == len(json.loads((DATA / "agent-skills.json").read_text(encoding="utf-8")))
    assert {path.name: _frontmatter_model(path) for path in agents} == {path.name: models.SCAN_MODEL for path in agents}


def test_cloud_slash_commands_run_on_the_scan_model_and_local_ones_do_not_pin_claude():
    for path in sorted((DATA / "commands").glob("*.md")):
        expected = None if path.stem.endswith("-local") else models.SCAN_MODEL
        assert _frontmatter_model(path) == expected, path.name


# ── CI scripts and workflows ──────────────────────────────────────────────────

def _load_chat():
    spec = importlib.util.spec_from_file_location("threatlint_chat_policy", ROOT / ".github/scripts/threatlint_chat.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_pr_chat_defaults_to_general_model_with_env_and_explicit_overrides():
    chat = _load_chat()
    assert chat.GENERAL_MODEL == models.GENERAL_MODEL
    sent = []

    def opener(request, timeout=None):
        sent.append(json.loads(request.data)["model"])
        return _Response(json.dumps({"content": [{"type": "text", "text": "ok"}]}).encode())

    env = {"ANTHROPIC_API_KEY": "ak-test"}
    assert chat.call_model("claude", "sys", "user", "", env, opener)[0] == models.GENERAL_MODEL
    assert chat.call_model("claude", "sys", "user", "", {**env, "THREATLINT_GENERAL_MODEL": "env-general"}, opener)[0] == "env-general"
    assert chat.call_model("claude", "sys", "user", "explicit", {**env, "THREATLINT_GENERAL_MODEL": "env-general"}, opener)[0] == "explicit"
    assert sent == [models.GENERAL_MODEL, "env-general", "explicit"]
    assert chat.PROVIDERS["openai"]["model"] == "gpt-4o"


def test_scan_workflows_default_to_scan_model_and_auto_fix_to_general_model():
    workflows = ROOT / ".github" / "workflows"
    for path in sorted(workflows.glob("appsec-*.yml")):
        text = path.read_text(encoding="utf-8")
        if "claude_args" not in text:
            continue
        expected = ("--model ${{ vars.THREATLINT_GENERAL_MODEL || 'claude-opus-5-5' }}" if path.stem == "appsec-auto-fix"
                    else "--model ${{ vars.THREATLINT_SCAN_MODEL || 'claude-opus-5-5' }}")
        assert text.count(expected) == text.count("claude_args:"), path.name
    action = (ROOT / ".github" / "actions" / "threatlint" / "action.yml").read_text(encoding="utf-8")
    assert "--model ${{ inputs.model || 'claude-opus-5-5' }}" in action
    steps = (ROOT / "azure-pipelines" / "templates" / "threatlint-steps.yml").read_text(encoding="utf-8")
    assert 'args+=(--model "${TL_MODEL:-claude-opus-5-5}")' in steps


def test_azure_prompt_pipelines_follow_the_policy():
    for path in sorted((ROOT / "azure-pipelines").glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        if "APPSEC_MODEL" not in text:
            continue
        expected = models.GENERAL_MODEL if path.stem == "auto-fix" else models.SCAN_MODEL
        assert f"os.environ.get('APPSEC_MODEL', '{expected}')" in text, path.name
