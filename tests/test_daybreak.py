"""Daybreak Blue provider routing and stateless Responses calls; all keys are synthetic."""

import argparse
import io
import json
import urllib.error

import pytest

from threatlint import bedrock, cli, responses_api, run_context


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def test_daybreak_provider_defaults_and_fixed_bedrock_endpoint(monkeypatch):
    assert run_context._default_run_model("daybreak") == "gpt-6-sol"
    assert run_context._default_run_model("daybreak-bedrock") == bedrock.DAYBREAK_BLUE_MODEL
    assert bedrock.daybreak_blue_endpoint("us-east-2") == "https://bedrock-mantle.us-east-2.api.aws/openai/v1"
    with pytest.raises(ValueError, match="us-east-2 only"):
        bedrock.daybreak_blue_endpoint("us-east-1")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-synthetic")
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bedrock-synthetic")
    direct = argparse.Namespace(provider="daybreak", api_key="", model="")
    assert run_context._resolve_provider(direct) == ("daybreak", "https://api.openai.com/v1", "openai-synthetic")
    cloud = argparse.Namespace(provider="daybreak-bedrock", api_key="", model="", bedrock_region="")
    assert run_context._resolve_provider(cloud) == (
        "daybreak-bedrock", "https://bedrock-mantle.us-east-2.api.aws/openai/v1", "bedrock-synthetic")


def test_daybreak_rejects_unsupported_model_or_region_before_request(monkeypatch, capsys):
    monkeypatch.setenv("OPENAI_API_KEY", "openai-synthetic")
    monkeypatch.setenv("BEDROCK_API_KEY", "bedrock-synthetic")
    direct = argparse.Namespace(provider="daybreak", api_key="", model="gpt-6-astra")
    assert run_context._resolve_provider(direct) is None
    cloud = argparse.Namespace(provider="daybreak-bedrock", api_key="", model="", bedrock_region="us-east-1")
    assert run_context._resolve_provider(cloud) is None
    cloud.bedrock_region = "us-east-2"
    cloud.model = "openai.unrelated-model"
    assert run_context._resolve_provider(cloud) is None
    output = capsys.readouterr().out
    assert "openai-synthetic" not in output and "bedrock-synthetic" not in output


def test_claude_bedrock_cannot_send_openai_model_to_messages(monkeypatch, capsys):
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bedrock-synthetic")
    args = argparse.Namespace(provider="bedrock", api_key="", model=bedrock.DAYBREAK_BLUE_MODEL, bedrock_region="us-east-2")
    assert run_context._resolve_provider(args) is None
    assert "--provider daybreak-bedrock" in capsys.readouterr().out


def test_responses_tool_loop_replays_output_and_access_program(monkeypatch, tmp_path):
    requests = []
    payloads = [
        {"status": "completed", "output": [
            {"type": "reasoning", "id": "rs_1", "encrypted_content": "opaque"},
            {"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "Read",
             "arguments": '{"file_path":"README.md"}'},
        ]},
        {"status": "completed", "output": [
            {"type": "message", "role": "assistant", "content": [
                {"type": "output_text", "text": "# Report\nEvidence found."}
            ]}
        ]},
    ]

    def opener(request, timeout):
        assert timeout == responses_api._MODEL_REQUEST_TIMEOUT_S
        requests.append((request, json.loads(request.data)))
        return Response(json.dumps(payloads.pop(0)).encode())

    seen = []
    monkeypatch.setattr(responses_api, "_execute_tool", lambda root, name, arguments:
                        seen.append((root, name, arguments)) or "1\t# Evidence")
    output = responses_api.run_agent("https://api.openai.com/v1/responses", "gpt-6-sol", "system", "user",
                                     str(tmp_path), api_key="synthetic", access_program="daybreak_blue",
                                     opener=opener, progress=lambda text: None)
    assert output == "# Report\nEvidence found."
    assert seen == [(str(tmp_path), "Read", {"file_path": "README.md"})]
    assert len(requests) == 2
    for request, body in requests:
        assert request.get_header("Authorization") == "Bearer synthetic"
        assert body["access_programs"] == {"cyber": "daybreak_blue"}
        assert body["store"] is False
        assert body["tools"][0]["type"] == "function"
        assert all(tool["strict"] is False for tool in body["tools"])
    continuation = requests[1][1]["input"]
    assert continuation[1]["type"] == "reasoning"
    assert continuation[1]["encrypted_content"] == "opaque"
    assert continuation[2]["call_id"] == "call_1"
    assert continuation[3] == {"type": "function_call_output", "call_id": "call_1", "output": "1\t# Evidence"}


def test_responses_fail_closed_without_echoing_upstream_body():
    def opener(_request, _timeout):
        raise urllib.error.HTTPError("https://api.openai.com/v1/responses", 403, "denied", {},
                                     io.BytesIO(b"synthetic-secret-in-upstream-body"))
    with pytest.raises(responses_api.ResponsesError, match="HTTP 403") as failure:
        responses_api.run_agent("https://api.openai.com/v1/responses", "gpt-6-sol", "s", "u", ".",
                                api_key="synthetic-secret", access_program="daybreak_blue", opener=opener)
    assert "synthetic-secret" not in str(failure.value)


@pytest.mark.parametrize("provider,model,runner", [
    ("daybreak", "gpt-6-sol", "_run_responses_agent"),
    ("daybreak-bedrock", bedrock.DAYBREAK_BLUE_MODEL, "_run_responses_agent"),
])
def test_cli_routes_daybreak_to_correct_tool_loop(monkeypatch, tmp_path, provider, model, runner):
    monkeypatch.setenv("OPENAI_API_KEY", "openai-synthetic")
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bedrock-synthetic")
    seen = []
    monkeypatch.setattr(cli, "_run_responses_agent", lambda *a, **k: seen.append(("responses", a, k)) or "# Report\n")
    monkeypatch.setattr(cli, "_run_agent", lambda *a, **k: seen.append(("chat", a, k)) or "# Report\n")
    monkeypatch.setattr(cli, "_run_claude_api", lambda *a, **k: pytest.fail("Claude transport must not run"))
    monkeypatch.setattr(cli, "_save_report", lambda *a: tmp_path / "report.md")
    args = cli.build_parser().parse_args(["run", "secrets-scan", "--provider", provider, "--output-dir", str(tmp_path)])
    assert cli.cmd_run(args) == 0
    kind, positional, kwargs = seen[0]
    assert positional[1] == model
    if provider == "daybreak":
        assert kind == "responses"
        assert positional[0] == "https://api.openai.com/v1/responses"
        assert kwargs["access_program"] == "daybreak_blue"
        assert kwargs["api_key"] == "openai-synthetic"
    else:
        assert kind == "responses"
        assert positional[0] == "https://bedrock-mantle.us-east-2.api.aws/openai/v1/responses"
        assert kwargs["api_key"] == "bedrock-synthetic"
        assert "access_program" not in kwargs
