"""Bedrock configuration and CLI routing; synthetic keys, no AWS requests."""

import argparse
import json

import pytest

from threatlint import bedrock, cli, run_context


def settings(tmp_path, values):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"env": values}), encoding="utf-8")
    return path


def test_configuration_precedence_and_global_claude_settings(tmp_path):
    path = settings(tmp_path, {"AWS_BEARER_TOKEN_BEDROCK": "settings-aws", "BEDROCK_API_KEY": "settings-bedrock",
                               "AWS_REGION": "eu-west-1", "AWS_DEFAULT_REGION": "eu-west-2"})
    configured = bedrock.configuration(settings_path=path, env={})
    assert (configured.api_key, configured.region) == ("settings-aws", "eu-west-1")
    env = {"BEDROCK_API_KEY": "process-bedrock", "AWS_DEFAULT_REGION": "ap-south-1"}
    configured = bedrock.configuration(settings_path=path, env=env)
    assert (configured.api_key, configured.region) == ("process-bedrock", "ap-south-1")
    env.update(AWS_BEARER_TOKEN_BEDROCK="process-aws", AWS_REGION="us-west-2")
    configured = bedrock.configuration(settings_path=path, env=env)
    assert (configured.api_key, configured.region) == ("process-aws", "us-west-2")
    configured = bedrock.configuration("explicit", "cn-north-1", settings_path=path, env=env)
    assert (configured.api_key, configured.region) == ("explicit", "cn-north-1")
    assert configured.messages_url == "https://bedrock-runtime.cn-north-1.amazonaws.com.cn/anthropic/v1/messages"
    assert "explicit" not in repr(configured)


@pytest.mark.parametrize("payload", ["not json", "[]", '{"env": []}', '{"env": {"BEDROCK_API_KEY": 3}}'])
def test_malformed_optional_settings_are_ignored(tmp_path, payload):
    path = tmp_path / "settings.json"
    path.write_text(payload, encoding="utf-8")
    assert bedrock.configuration("explicit", env={}, settings_path=path).region == "us-east-1"


def test_bedrock_never_uses_other_provider_credentials_or_endpoint_overrides(tmp_path):
    path = settings(tmp_path, {"ANTHROPIC_API_KEY": "claude-key", "ANTHROPIC_AUTH_TOKEN": "login-token",
                               "ANTHROPIC_BASE_URL": "https://attacker.invalid", "AWS_ACCESS_KEY_ID": "access-key"})
    with pytest.raises(ValueError, match="Bedrock API key required"):
        bedrock.configuration(env={"ANTHROPIC_API_KEY": "key", "AWS_SECRET_ACCESS_KEY": "secret"}, settings_path=path)
    configured = bedrock.configuration("bedrock-key", env={"ANTHROPIC_BASE_URL": "https://attacker.invalid"}, settings_path=path)
    assert configured.messages_url == "https://bedrock-runtime.us-east-1.amazonaws.com/anthropic/v1/messages"


@pytest.mark.parametrize("region", ["us-east-1/evil", "https://evil", "us-east-1.attacker.invalid", "us-east-1@evil",
                                    "us-east-1?target=x", "US-EAST-1", "us-east-1\nX-Test: bad"])
def test_region_cannot_override_host_or_path(region):
    with pytest.raises(ValueError, match="Invalid Bedrock region"):
        bedrock.endpoint(region)


def test_only_user_global_settings_are_read(monkeypatch, tmp_path):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text(json.dumps({"env": {"BEDROCK_API_KEY": "global-key"}}))
    repo = tmp_path / "repo"
    (repo / ".claude").mkdir(parents=True)
    (repo / ".claude" / "settings.json").write_text(json.dumps({"env": {"BEDROCK_API_KEY": "project-key"}}))
    monkeypatch.chdir(repo)
    monkeypatch.setattr(bedrock.Path, "home", lambda: home)
    assert bedrock.configuration(env={}).api_key == "global-key"


def test_cli_requires_exact_bedrock_model_and_does_not_fall_back_to_claude_policy(monkeypatch, capsys):
    monkeypatch.setenv("THREATLINT_SCAN_MODEL", "claude-default")
    assert run_context._default_run_model("bedrock") == ""
    args = argparse.Namespace(provider="bedrock", model="", api_key="key", bedrock_region="us-east-1")
    assert run_context._resolve_provider(args) is None
    assert "requires --model" in capsys.readouterr().out


def test_cli_bedrock_routes_to_native_messages_and_keeps_inference_profile(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bedrock-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "unrelated-claude-key")
    seen = []
    monkeypatch.setattr(cli, "_run_claude_api", lambda *a, **k: seen.append((a, k)) or "# Report\n")
    monkeypatch.setattr(cli, "_run_agent", lambda *a, **k: pytest.fail("OpenAI transport must not be used"))
    monkeypatch.setattr(cli, "_save_report", lambda *a: tmp_path / "report.md")
    model = "global.anthropic.synthetic-model-v1:0"
    args = cli.build_parser().parse_args(["run", "secrets-scan", "--provider", "bedrock", "--model", model,
                                         "--bedrock-region", "eu-west-1", "--output-dir", str(tmp_path)])
    assert cli.cmd_run(args) == 0
    positional, kwargs = seen[0]
    assert positional[:2] == ("https://bedrock-runtime.eu-west-1.amazonaws.com/anthropic/v1/messages", model)
    assert kwargs["api_key"] == "bedrock-key"


def test_cli_reports_bad_region_without_echoing_key(monkeypatch, capsys):
    monkeypatch.setenv("BEDROCK_API_KEY", "synthetic-private-key")
    args = argparse.Namespace(provider="bedrock", model="exact-model", api_key="", bedrock_region="bad/region")
    assert run_context._resolve_provider(args) is None
    output = capsys.readouterr().out
    assert "Invalid Bedrock region" in output and "synthetic-private-key" not in output
