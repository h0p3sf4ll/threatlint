"""Native Anthropic Messages streaming for Claude and Bedrock API keys.

Only complete, successful turns enter the bounded, read-only tool loop. HTTP
errors never expose response bodies or credential-bearing exception messages.
"""

from __future__ import annotations

import codecs
import http.client
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable

from .agent_tools import _TOOLS, _execute_tool
from .inspection_batch import run_inspections

ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
_MAX_AGENT_ITERATIONS = 80
_MAX_OUTPUT_TOKENS = 16000
_MODEL_REQUEST_TIMEOUT_S = 600
_MAX_STREAM_BYTES = 32 * 1024 * 1024
_MAX_EVENT_CHARS = 2 * 1024 * 1024
_MAX_CONTENT_BLOCKS = 1000
_MAX_TOOL_CALLS = 64


class MessagesError(RuntimeError):
    """A failed request or incomplete report; safe to display to the user."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open(request, timeout):
    return urllib.request.build_opener(_NoRedirect()).open(request, timeout=timeout)


def _events(chunks: Iterable[bytes]):
    """Decode SSE across arbitrary UTF-8/chunk boundaries, with bounded buffering."""
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    buffer = ""
    data: list[str] = []
    event_kind = ""
    event_chars = 0
    total = 0
    started = time.monotonic()
    try:
        for raw in chunks:
            total += len(raw)
            if total > _MAX_STREAM_BYTES or time.monotonic() - started > _MODEL_REQUEST_TIMEOUT_S:
                raise MessagesError("Model stream exceeded the response limit.")
            buffer += decoder.decode(raw)
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.removesuffix("\r")
                if line == "":
                    if event_kind == "error":
                        raise MessagesError("Model stream returned an error. Retry the request or check provider access.")
                    if data:
                        yield "\n".join(data)
                    data = []
                    event_chars = 0
                    event_kind = ""
                elif line.startswith("event:"):
                    event_kind = line[6:].strip()
                elif line.startswith("data:"):
                    value = line[5:].removeprefix(" ")
                    event_chars += len(value)
                    if event_chars > _MAX_EVENT_CHARS:
                        raise MessagesError("Model stream exceeded the event limit.")
                    data.append(value)
            if len(buffer) > _MAX_EVENT_CHARS:
                raise MessagesError("Model stream exceeded the event limit.")
        buffer += decoder.decode(b"", final=True)
    except UnicodeError:
        raise MessagesError("Model returned an invalid event stream.") from None
    # SSE events require a terminating blank line. Never accept a truncated tail.
    if buffer.strip() or data:
        raise MessagesError("Model stream ended before the final event was complete.")


class _Turn:
    def __init__(self, progress: Callable[[str], None]):
        self.progress = progress
        self.blocks: dict[int, dict] = {}
        self.partial_inputs: dict[int, str] = {}
        self.closed: set[int] = set()
        self.started = False
        self.done = False
        self.stop_reason = ""

    @property
    def text(self) -> str:
        return "".join(block["text"] for _, block in sorted(self.blocks.items()) if block["type"] == "text")

    @property
    def content(self) -> list[dict]:
        return [block for _, block in sorted(self.blocks.items())]

    def feed(self, raw: str) -> None:
        try:
            event = json.loads(raw)
            if not isinstance(event, dict):
                raise ValueError
            kind = event.get("type")
            if kind == "error":
                raise MessagesError("Model stream returned an error. Retry the request or check provider access.")
            if self.done:
                raise ValueError
            if kind == "ping":
                return
            if kind == "message_start":
                if self.started:
                    raise ValueError
                self.started = True
                return
            if not self.started:
                raise ValueError
            if kind == "content_block_start":
                self._start_block(event)
            elif kind == "content_block_delta":
                self._delta(event)
            elif kind == "content_block_stop":
                self._stop_block(event)
            elif kind == "message_delta":
                reason = event.get("delta", {}).get("stop_reason")
                if reason:
                    self.stop_reason = reason
            elif kind == "message_stop":
                if self.closed != self.blocks.keys() or not self.stop_reason:
                    raise ValueError
                self.done = True
            # New non-content event types are allowed by the Anthropic protocol.
        except (ValueError, KeyError, TypeError, AttributeError):
            raise MessagesError("Model returned an invalid event stream.") from None

    def _index(self, event: dict) -> int:
        index = event["index"]
        if type(index) is not int or not 0 <= index < _MAX_CONTENT_BLOCKS:
            raise ValueError
        return index

    def _start_block(self, event: dict) -> None:
        index = self._index(event)
        block = event["content_block"]
        if index in self.blocks or not isinstance(block, dict):
            raise ValueError
        kind = block.get("type")
        if kind == "text":
            if not isinstance(block.get("text"), str):
                raise ValueError
            self.blocks[index] = {"type": kind, "text": block["text"]}
            if block["text"]:
                self.progress(block["text"])
        elif kind == "tool_use":
            if not isinstance(block.get("id"), str) or not block["id"] or not isinstance(block.get("name"), str):
                raise ValueError
            if sum(value["type"] == "tool_use" for value in self.blocks.values()) >= _MAX_TOOL_CALLS:
                raise MessagesError("Model requested too many inspection tools in one turn.")
            if not isinstance(block.get("input", {}), dict):
                raise ValueError
            self.blocks[index] = {"type": kind, "id": block["id"], "name": block["name"], "input": block.get("input", {})}
        elif kind in ("thinking", "redacted_thinking"):
            self.blocks[index] = dict(block)
        else:
            raise MessagesError("Model returned an unsupported content block.")

    def _delta(self, event: dict) -> None:
        index = self._index(event)
        block, delta = self.blocks[index], event["delta"]
        if index in self.closed:
            raise ValueError
        kind = delta.get("type")
        if kind == "text_delta" and block["type"] == "text" and isinstance(delta.get("text"), str):
            block["text"] += delta["text"]
            self.progress(delta["text"])
        elif kind == "input_json_delta" and block["type"] == "tool_use" and isinstance(delta.get("partial_json"), str):
            self.partial_inputs[index] = self.partial_inputs.get(index, "") + delta["partial_json"]
        elif kind in ("thinking_delta", "signature_delta") and block["type"] == "thinking":
            field = "thinking" if kind == "thinking_delta" else "signature"
            if not isinstance(delta.get(field), str):
                raise ValueError
            block[field] = block.get(field, "") + delta[field]
        else:
            raise ValueError

    def _stop_block(self, event: dict) -> None:
        index = self._index(event)
        if index not in self.blocks or index in self.closed:
            raise ValueError
        if index in self.partial_inputs:
            parsed = json.loads(self.partial_inputs[index])
            if not isinstance(parsed, dict):
                raise ValueError
            self.blocks[index]["input"] = parsed
        self.closed.add(index)

    def validate(self) -> None:
        if not self.done:
            raise MessagesError("Model stream ended before the response was complete. No report was saved.")
        if self.stop_reason not in ("end_turn", "stop_sequence", "tool_use"):
            raise MessagesError("Model response did not finish successfully (output limit, refusal, or interruption). No report was saved.")
        calls = [block for block in self.content if block["type"] == "tool_use"]
        if bool(calls) != (self.stop_reason == "tool_use") or len({call["id"] for call in calls}) != len(calls):
            raise MessagesError("Model returned an invalid tool-use response.")


def _stream_turn(endpoint: str, body: dict, api_key: str, progress: Callable[[str], None], opener=None) -> _Turn:
    request = urllib.request.Request(endpoint, data=json.dumps(body).encode("utf-8"), method="POST", headers={
        "Content-Type": "application/json", "Accept": "text/event-stream",
        "x-api-key": api_key, "anthropic-version": "2023-06-01",
    })
    turn = _Turn(progress)
    try:
        with (opener or _open)(request, timeout=_MODEL_REQUEST_TIMEOUT_S) as response:
            for event in _events(response):
                turn.feed(event)
    except urllib.error.HTTPError as exc:
        # Never read/print an upstream body: it may include request content or keys.
        raise MessagesError(f"Model request failed (HTTP {exc.code}). Check the API key, model access, and provider region.") from None
    except (OSError, http.client.HTTPException, ValueError):
        raise MessagesError("Model request failed. Check network connectivity and provider configuration.") from None
    turn.validate()
    return turn


def run_agent(endpoint: str, model: str, system_prompt: str, user_message: str, repo_root: str,
              api_key: str = "", *, images=(), opener=None,
              progress: Callable[[str], None] = lambda text: print(text, end="", flush=True)) -> str:
    """Run the existing read-only tools using native Messages request/response blocks."""
    from .bedrock import endpoint as bedrock_endpoint  # noqa: PLC0415
    from urllib.parse import urlsplit  # noqa: PLC0415

    # Defense in depth for callers: provider credentials only reach fixed AWS/Anthropic routes.
    if endpoint != ANTHROPIC_MESSAGES_URL:
        try:
            host = urlsplit(endpoint).hostname or ""
            region = host.split(".")[1] if host.startswith("bedrock-runtime.") and "." in host else ""
            valid = endpoint == bedrock_endpoint(region)
        except ValueError:
            valid = False
        if not valid:
            raise MessagesError("Invalid Messages endpoint.")
    if not model or not model.strip():
        raise MessagesError("An exact model ID is required for this provider.")
    if not api_key or any(character in api_key for character in "\r\n\0"):
        raise MessagesError("A valid API key is required for this provider.")
    content = [{"type": "text", "text": user_message}, *({"type": "image", "source": {
        "type": "base64", "media_type": image.media_type, "data": image.data,
    }} for image in images)]
    messages = [{"role": "user", "content": content}]
    tools = [{"name": tool["function"]["name"], "description": tool["function"]["description"],
              "input_schema": tool["function"]["parameters"]} for tool in _TOOLS]
    for _iteration in range(_MAX_AGENT_ITERATIONS):
        body = {"model": model, "system": system_prompt, "messages": messages, "tools": tools,
                "max_tokens": _MAX_OUTPUT_TOKENS, "stream": True}
        turn = _stream_turn(endpoint, body, api_key, progress, opener)
        if turn.stop_reason != "tool_use":
            return turn.text
        messages.append({"role": "assistant", "content": turn.content})
        calls = [(block["id"], block["name"], block["input"]) for block in turn.content if block["type"] == "tool_use"]
        contents = run_inspections(calls, repo_root, _execute_tool, progress)
        results = [{"type": "tool_result", "tool_use_id": call[0], "content": result} for call, result in zip(calls, contents)]
        messages.append({"role": "user", "content": results})
    raise MessagesError("Model exceeded the inspection iteration limit. No complete report was saved.")
