"""OpenAI-compatible streaming transport and bounded tool-use execution."""

from __future__ import annotations

import http.client
import json as _json

from .agent_tools import _TOOLS, _execute_tool


_MAX_AGENT_ITERATIONS = 80
_MAX_OUTPUT_TOKENS = 16000
_MODEL_REQUEST_TIMEOUT_S = 600


def _lmstudio_auto_model(base_url: str) -> str:
    models = _lmstudio_models(base_url)
    return models[0] if models else ""


def _lmstudio_models(base_url: str) -> list[str]:
    """Model IDs served by an OpenAI-compatible server; empty when unreachable or none loaded."""
    import urllib.request as _req
    try:
        with _req.urlopen(f"{base_url}/models", timeout=5) as resp:
            data = _json.loads(resp.read())
    except (OSError, ValueError):
        return []
    return [m["id"] for m in data.get("data", []) if isinstance(m, dict) and isinstance(m.get("id"), str)]


class _StreamTurn:
    """Accumulates one streamed chat-completions turn: text, tool calls, and finish reason."""

    def __init__(self) -> None:
        self.text = ""
        self.calls: dict[int, dict] = {}
        self.finish_reason = "stop"
        self.done = False

    def feed_line(self, line: str) -> None:
        if self.done or not line.startswith("data: "):
            return
        data = line[6:].strip()
        if data == "[DONE]":
            self.done = True
            return
        try:
            choice = _json.loads(data).get("choices", [{}])[0]
        except (_json.JSONDecodeError, IndexError, AttributeError):
            return  # Keep-alive or malformed chunk; the stream carries on.
        if choice.get("finish_reason"):
            self.finish_reason = choice["finish_reason"]
        delta = choice.get("delta") or {}
        if delta.get("content"):
            self.text += delta["content"]
            print(delta["content"], end="", flush=True)
        for call in delta.get("tool_calls") or []:
            self._merge_call(call)

    def _merge_call(self, call: dict) -> None:
        index = call.get("index", 0)
        current = self.calls.setdefault(index, {"id": call.get("id", f"call_{index}"), "name": "", "args": ""})
        if call.get("id"):
            current["id"] = call["id"]
        function = call.get("function") or {}
        current["name"] += function.get("name") or ""
        current["args"] += function.get("arguments") or ""

    def assistant_message(self) -> dict:
        message: dict = {"role": "assistant", "content": self.text or None}
        if self.calls:
            message["tool_calls"] = [{"id": call["id"], "type": "function",
                                      "function": {"name": call["name"], "arguments": call["args"]}}
                                     for call in self.calls.values()]
        return message


def _stream_turn(base_url: str, model: str, messages: list[dict], api_key: str) -> _StreamTurn:
    import urllib.request as _req

    body = _json.dumps({"model": model, "messages": messages, "tools": _TOOLS,
                        "stream": True, "max_tokens": _MAX_OUTPUT_TOKENS}).encode()
    headers = {"Content-Type": "application/json", **({"Authorization": f"Bearer {api_key}"} if api_key else {})}
    request = _req.Request(f"{base_url}/chat/completions", data=body, headers=headers)
    turn = _StreamTurn()
    try:
        with _req.urlopen(request, timeout=_MODEL_REQUEST_TIMEOUT_S) as resp:
            buffer = ""
            for raw in resp:
                buffer += raw.decode("utf-8", errors="replace")
                *lines, buffer = buffer.split("\n")
                for line in lines:
                    turn.feed_line(line)
    except (OSError, http.client.HTTPException) as exc:
        raise RuntimeError(f"Model request failed: {exc}") from exc
    return turn


def _run_tool_calls(turn: _StreamTurn, repo_root: str) -> list[dict]:
    results = []
    for call in turn.calls.values():
        try:
            args = _json.loads(call["args"] or "{}")
        except _json.JSONDecodeError:
            args = {}
        short = ", ".join(f"{k}={repr(v)[:40]}" for k, v in list(args.items())[:2])
        print(f"  → {call['name']}({short})", flush=True)
        results.append({"role": "tool", "tool_call_id": call["id"], "content": str(_execute_tool(repo_root, call["name"], args))})
    return results


def _user_content(text: str, images=()) -> str | list[dict]:
    """OpenAI-compatible user content: text, or text plus data-URL image parts (design inputs)."""
    if not images:
        return text
    return [{"type": "text", "text": text},
            *({"type": "image_url", "image_url": {"url": f"data:{image.media_type};base64,{image.data}"}} for image in images)]


def _run_agent(base_url: str, model: str, system_prompt: str,
               user_message: str, repo_root: str, api_key: str = "", images=()) -> str:
    """Stream a full tool-use agentic loop against an OpenAI-compatible server. Returns output text."""
    model = model or _lmstudio_auto_model(base_url)
    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": _user_content(user_message, images)},
    ]
    full_text = ""
    for _iteration in range(_MAX_AGENT_ITERATIONS):
        turn = _stream_turn(base_url, model, messages, api_key)
        full_text += turn.text
        messages.append(turn.assistant_message())
        if turn.finish_reason != "tool_calls" or not turn.calls:
            break
        if turn.text:
            print()
        messages.extend(_run_tool_calls(turn, repo_root))
    return full_text
