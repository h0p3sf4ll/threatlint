"""Native Messages HTTP/SSE/tool behavior for Claude and Bedrock, entirely offline."""

import io
import json
import types
import urllib.error

import pytest

from threatlint import bedrock, claude_api


def sse(*events):
    return "".join("event: " + event["type"] + "\r\ndata: " + json.dumps(event, ensure_ascii=False) + "\r\n\r\n"
                   for event in events).encode()


def turn(text="Report.", reason="end_turn", call=None):
    events = [{"type": "message_start", "message": {"type": "message", "role": "assistant", "content": []}}]
    if text:
        events += [{"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
                   {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}},
                   {"type": "content_block_stop", "index": 0}]
    if call:
        index = 1 if text else 0
        arguments = json.dumps(call.get("input", {}))
        split = len(arguments) // 2
        events += [{"type": "content_block_start", "index": index,
                    "content_block": {"type": "tool_use", "id": "call_1", "name": call["name"], "input": {}}},
                   {"type": "content_block_delta", "index": index,
                    "delta": {"type": "input_json_delta", "partial_json": arguments[:split]}},
                   {"type": "content_block_delta", "index": index,
                    "delta": {"type": "input_json_delta", "partial_json": arguments[split:]}},
                   {"type": "content_block_stop", "index": index}]
    return events + [{"type": "message_delta", "delta": {"stop_reason": reason}}, {"type": "message_stop"}]


class Response:
    def __init__(self, data, fragment_size=7):
        self.data = data
        self.fragment_size = fragment_size

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def __iter__(self):
        return (self.data[n:n + self.fragment_size] for n in range(0, len(self.data), self.fragment_size))


@pytest.mark.parametrize("endpoint", [claude_api.ANTHROPIC_MESSAGES_URL, bedrock.endpoint("us-east-1")])
def test_native_http_contract_images_and_fragmented_utf8(endpoint):
    sent = []
    def opener(request, timeout):
        sent.append((request, timeout))
        return Response(sse(*turn("Réport ✅")), fragment_size=1)
    image = types.SimpleNamespace(media_type="image/png", data="c3ludGhldGlj")
    result = claude_api.run_agent(endpoint, "global.synthetic-profile", "system instructions", "user message", ".",
                                  "provider-key", images=(image,), opener=opener, progress=lambda text: None)
    assert result == "Réport ✅"
    request, timeout = sent[0]
    assert request.full_url == endpoint and request.method == "POST" and timeout == 600
    headers = {name.lower(): value for name, value in request.header_items()}
    assert headers["x-api-key"] == "provider-key" and headers["anthropic-version"] == "2023-06-01"
    assert "authorization" not in headers
    body = json.loads(request.data)
    assert body["model"] == "global.synthetic-profile" and body["system"] == "system instructions"
    assert body["stream"] is True and body["max_tokens"] == 16000
    assert all("input_schema" in tool and "function" not in tool for tool in body["tools"])
    assert body["messages"] == [{"role": "user", "content": [
        {"type": "text", "text": "user message"},
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "c3ludGhldGlj"}},
    ]}]
    assert b"provider-key" not in request.data


def test_tool_roundtrip_uses_native_blocks_and_actual_repository_confinement(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("source evidence\n", encoding="utf-8")
    (tmp_path / "private.txt").write_text("outside-private-data", encoding="utf-8")
    streams = iter([
        sse(*turn("Inspecting.", "tool_use", {"name": "Read", "input": {"file_path": "app.py"}})),
        sse(*turn("", "tool_use", {"name": "Read", "input": {"file_path": "../private.txt"}})),
        sse(*turn("Report.")),
    ])
    requests = []
    def opener(request, timeout):
        requests.append(json.loads(request.data))
        return Response(next(streams))
    assert claude_api.run_agent(bedrock.endpoint("us-east-1"), "us.exact-profile", "s", "u", str(repo), "key",
                                 opener=opener, progress=lambda text: None) == "Report."
    messages = requests[1]["messages"]
    assert messages[-2]["role"] == "assistant"
    assert messages[-2]["content"][-1] == {"type": "tool_use", "id": "call_1", "name": "Read", "input": {"file_path": "app.py"}}
    assert messages[-1] == {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "call_1", "content": "1\tsource evidence\n"},
    ]}
    assert "Access outside the selected repository is denied" in requests[2]["messages"][-1]["content"][0]["content"]
    assert "outside-private-data" not in json.dumps(requests)


@pytest.mark.parametrize("events", [turn()[:-1], turn(reason="max_tokens"), turn(reason="refusal"),
                                    turn(reason="tool_use"),
                                    [{"type": "error", "error": {"message": "private upstream content", "type": "overloaded_error"}}]])
def test_incomplete_truncated_and_error_responses_fail_without_report(events):
    with pytest.raises(claude_api.MessagesError) as error:
        claude_api.run_agent(claude_api.ANTHROPIC_MESSAGES_URL, "model", "s", "u", ".", "private-key",
                              opener=lambda *a, **k: Response(sse(*events)), progress=lambda text: None)
    assert "private upstream content" not in str(error.value) and "private-key" not in str(error.value)


def test_truncated_sse_event_and_invalid_utf8_are_rejected():
    for payload in (sse(*turn())[:-3], b"data: \xff\n\n", b"data: malformed\n\n"):
        with pytest.raises(claude_api.MessagesError):
            claude_api.run_agent(claude_api.ANTHROPIC_MESSAGES_URL, "model", "s", "u", ".", "key",
                                  opener=lambda *a, **k: Response(payload), progress=lambda text: None)


def test_named_sse_error_cannot_be_hidden_by_a_mismatched_data_type():
    payload = sse(*turn()) + b'event: error\ndata: {"type":"ping", "message":"private-body"}\n\n'
    with pytest.raises(claude_api.MessagesError, match="stream returned an error") as error:
        claude_api.run_agent(claude_api.ANTHROPIC_MESSAGES_URL, "model", "s", "u", ".", "key",
                              opener=lambda *a, **k: Response(payload), progress=lambda text: None)
    assert "private-body" not in str(error.value)


def test_failed_stream_never_runs_a_tool(monkeypatch):
    events = turn("", "tool_use", {"name": "Read", "input": {"file_path": "app.py"}})[:-1]
    monkeypatch.setattr(claude_api, "_execute_tool", lambda *args: pytest.fail("incomplete turn must not execute tools"))
    with pytest.raises(claude_api.MessagesError, match="complete"):
        claude_api.run_agent(claude_api.ANTHROPIC_MESSAGES_URL, "model", "s", "u", ".", "key",
                              opener=lambda *a, **k: Response(sse(*events)), progress=lambda text: None)


def test_malformed_tool_json_is_not_executed(monkeypatch):
    events = turn("", "tool_use", {"name": "Read", "input": {"file_path": "app.py"}})
    events[2]["delta"]["partial_json"] = "["
    monkeypatch.setattr(claude_api, "_execute_tool", lambda *args: pytest.fail("invalid arguments must not execute"))
    with pytest.raises(claude_api.MessagesError, match="invalid event"):
        claude_api.run_agent(claude_api.ANTHROPIC_MESSAGES_URL, "model", "s", "u", ".", "key",
                              opener=lambda *a, **k: Response(sse(*events)), progress=lambda text: None)


def test_iteration_limit_fails_instead_of_saving_partial_report(monkeypatch):
    monkeypatch.setattr(claude_api, "_MAX_AGENT_ITERATIONS", 2)
    sent = []
    def opener(request, timeout):
        sent.append(request)
        return Response(sse(*turn("Partial.", "tool_use", {"name": "Unknown", "input": {}})))
    with pytest.raises(claude_api.MessagesError, match="iteration limit"):
        claude_api.run_agent(claude_api.ANTHROPIC_MESSAGES_URL, "model", "s", "u", ".", "key",
                              opener=opener, progress=lambda text: None)
    assert len(sent) == 2


def test_http_errors_and_network_errors_redact_upstream_text():
    failures = [urllib.error.HTTPError("https://upstream.invalid/?key=private-key", 403, "private-key", {}, io.BytesIO(b"private-body")),
                OSError("private-key private-body")]
    for failure in failures:
        def opener(*args, **kwargs):
            raise failure
        with pytest.raises(claude_api.MessagesError) as error:
            claude_api.run_agent(claude_api.ANTHROPIC_MESSAGES_URL, "model", "s", "u", ".", "private-key",
                                  opener=opener, progress=lambda text: None)
        assert "private-key" not in str(error.value) and "private-body" not in str(error.value)


def test_default_opener_explicitly_disables_redirects(monkeypatch):
    captured = []
    class Opener:
        def open(self, request, timeout):
            captured.append((request, timeout))
            return "response"
    def build(*handlers):
        assert len(handlers) == 1 and isinstance(handlers[0], claude_api._NoRedirect)
        assert handlers[0].redirect_request(None, None, 307, "redirect", {}, "https://attacker.invalid") is None
        return Opener()
    monkeypatch.setattr(claude_api.urllib.request, "build_opener", build)
    assert claude_api._open("request", 3) == "response"
    assert captured == [("request", 3)]


@pytest.mark.parametrize("endpoint", ["https://attacker.invalid/messages", "https://api.anthropic.com/v1/messages?key=x",
                                       "https://bedrock-runtime.us-east-1.amazonaws.com.attacker.invalid/anthropic/v1/messages",
                                       "http://bedrock-runtime.us-east-1.amazonaws.com/anthropic/v1/messages",
                                       "https://[bad"])
def test_credentials_cannot_be_sent_to_a_custom_endpoint(endpoint):
    with pytest.raises(claude_api.MessagesError, match="Invalid Messages endpoint"):
        claude_api.run_agent(endpoint, "model", "s", "u", ".", "key", opener=lambda *a, **k: pytest.fail("must not request"))


def test_stream_byte_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(claude_api, "_MAX_STREAM_BYTES", 20)
    with pytest.raises(claude_api.MessagesError, match="response limit"):
        claude_api.run_agent(claude_api.ANTHROPIC_MESSAGES_URL, "model", "s", "u", ".", "key",
                              opener=lambda *a, **k: Response(sse(*turn())), progress=lambda text: None)


def test_dast_existing_claude_review_uses_native_transport(monkeypatch, tmp_path):
    from threatlint import cli, dast
    monkeypatch.setattr(dast, "review_request", lambda state: "Synthetic DAST evidence")
    monkeypatch.setattr(dast, "save_state", lambda state: None)
    monkeypatch.setattr(cli, "_resolve_provider", lambda args: ("claude", "https://api.anthropic.com/v1", "claude-key"))
    monkeypatch.setattr(cli, "_run_agent", lambda *a, **k: pytest.fail("Claude must not use chat completions"))
    seen = []
    monkeypatch.setattr(cli, "_run_claude_api", lambda *a, **k: seen.append((a, k)) or "# Final report\n")
    state = {"work": str(tmp_path), "checkout": str(tmp_path), "avit": "AVIT-SYNTHETIC"}
    args = types.SimpleNamespace(review_provider="claude", api_key="", base_url="", model="exact-model")
    assert dast.step_review(args, state)["report"] == str(tmp_path / dast.REPORT_FILE)
    assert (tmp_path / dast.REPORT_FILE).read_text() == "# Final report\n"
    assert seen[0][0][:2] == (claude_api.ANTHROPIC_MESSAGES_URL, "exact-model")
    assert seen[0][1]["api_key"] == "claude-key"
