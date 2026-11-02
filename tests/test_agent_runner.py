"""Streaming and tool-loop policies can be tested without an HTTP server."""

import json

from threatlint import agent_runner, agent_tools, cli


def event(delta=None, finish=None):
    return "data: " + json.dumps({"choices": [{
        "delta": delta or {}, "finish_reason": finish,
    }]})


def test_stream_turn_merges_fragmented_tool_calls_and_text(capsys):
    turn = agent_runner._StreamTurn()
    turn.feed_line(": keep-alive")
    turn.feed_line("data: malformed")
    turn.feed_line(event({"content": "Hello"}))
    turn.feed_line(event({"tool_calls": [{
        "index": 0, "id": "call_1", "function": {"name": "Read", "arguments": '{"file_'},
    }]}))
    turn.feed_line(event({"tool_calls": [{
        "index": 0, "function": {"arguments": 'path":"app.py"}'},
    }]}, finish="tool_calls"))
    turn.feed_line("data: [DONE]")
    turn.feed_line(event({"content": "ignored"}))
    assert turn.done and turn.finish_reason == "tool_calls"
    assert turn.assistant_message() == {
        "role": "assistant", "content": "Hello",
        "tool_calls": [{
            "id": "call_1", "type": "function",
            "function": {"name": "Read", "arguments": '{"file_path":"app.py"}'},
        }],
    }
    assert capsys.readouterr().out == "Hello"


def test_agent_loop_records_tool_response_then_finishes(monkeypatch, tmp_path):
    first = agent_runner._StreamTurn()
    first.text = "Inspecting."
    first.finish_reason = "tool_calls"
    first.calls[0] = {"id": "read_1", "name": "Read", "args": '{"file_path":"app.py"}'}
    last = agent_runner._StreamTurn()
    last.text = "Report."
    turns = iter([first, last])
    requests = []

    def stream(base_url, model, messages, api_key):
        requests.append([dict(message) for message in messages])
        return next(turns)

    monkeypatch.setattr(agent_runner, "_stream_turn", stream)
    monkeypatch.setattr(agent_runner, "_execute_tool", lambda root, name, args: "source text")
    result = agent_runner._run_agent("http://unused", "synthetic-model", "system", "user", str(tmp_path))
    assert result == "Inspecting.Report."
    assert requests[1][-1] == {
        "role": "tool", "tool_call_id": "read_1", "content": "source text",
    }


def test_agent_iteration_budget_is_preserved(monkeypatch, tmp_path):
    turn = agent_runner._StreamTurn()
    turn.text = "partial"
    turn.finish_reason = "tool_calls"
    turn.calls[0] = {"id": "unknown", "name": "Unknown", "args": "{}"}
    monkeypatch.setattr(agent_runner, "_MAX_AGENT_ITERATIONS", 2)
    monkeypatch.setattr(agent_runner, "_stream_turn", lambda *args: turn)
    assert agent_runner._run_agent("http://unused", "synthetic", "", "", str(tmp_path)) == "partialpartial"


def test_cli_preserves_existing_tool_imports():
    assert cli._tool_read is agent_tools._tool_read
    assert cli._tool_bash is agent_tools._tool_bash
    assert cli._validate_bash is agent_tools._validate_bash
    assert cli._run_agent is agent_runner._run_agent
