"""Stateless OpenAI Responses tool loop for approved Daybreak Blue API access.

The model can only call Threatlint's bounded, read-only repository tools. Every
continuation keeps the selected access program, and provider errors never echo
request bodies, credentials, or upstream response content.
"""

from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request
from collections.abc import Callable

from .agent_tools import _TOOLS, _execute_tool

_MAX_AGENT_ITERATIONS = 80
_MAX_OUTPUT_TOKENS = 16000
_MODEL_REQUEST_TIMEOUT_S = 600
_MAX_RESPONSE_BYTES = 32 * 1024 * 1024
_MAX_TOOL_CALLS = 64
_TOOL_NAMES = frozenset(tool["function"]["name"] for tool in _TOOLS)


class ResponsesError(RuntimeError):
    """A safe-to-display provider or response validation failure."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open(request, timeout):
    return urllib.request.build_opener(_NoRedirect()).open(request, timeout=timeout)


def _tools() -> list[dict]:
    # The shared schemas intentionally leave offset, limit, path, and flags
    # optional. Responses may otherwise normalize them into required fields.
    return [{"type": "function", **tool["function"], "strict": False} for tool in _TOOLS]


def _user_input(text: str, images=()) -> dict:
    if not images:
        return {"role": "user", "content": text}
    return {"role": "user", "content": [
        {"type": "input_text", "text": text},
        *({"type": "input_image", "image_url": f"data:{image.media_type};base64,{image.data}"}
          for image in images),
    ]}


def _request(endpoint: str, body: dict, api_key: str, opener=None) -> dict:
    encoded = json.dumps(body).encode("utf-8")
    if len(encoded) > _MAX_RESPONSE_BYTES:
        raise ResponsesError("Model request exceeded the context limit.")
    request = urllib.request.Request(endpoint, data=encoded, method="POST", headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    })
    try:
        with (opener or _open)(request, _MODEL_REQUEST_TIMEOUT_S) as response:
            payload = response.read(_MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise ResponsesError(f"Model request failed (HTTP {exc.code}). Check model access and provider configuration.") from None
    except (OSError, http.client.HTTPException, ValueError):
        raise ResponsesError("Model request failed. Check network connectivity and provider configuration.") from None
    if len(payload) > _MAX_RESPONSE_BYTES:
        raise ResponsesError("Model response exceeded the size limit.")
    try:
        result = json.loads(payload)
    except (ValueError, UnicodeError):
        raise ResponsesError("Model returned an invalid response.") from None
    if not isinstance(result, dict) or result.get("status") != "completed" or not isinstance(result.get("output"), list):
        raise ResponsesError("Model response did not complete successfully. No report was saved.")
    return result


def _inspect_output(output: list[dict]) -> tuple[str, list[tuple[str, str, dict]]]:
    text_parts: list[str] = []
    calls: list[tuple[str, str, dict]] = []
    call_ids: set[str] = set()
    for item in output:
        if not isinstance(item, dict):
            raise ResponsesError("Model returned an invalid output item.")
        if item.get("type") == "message":
            content = item.get("content")
            if not isinstance(content, list):
                raise ResponsesError("Model returned an invalid message.")
            for part in content:
                if not isinstance(part, dict):
                    raise ResponsesError("Model returned an invalid message.")
                if part.get("type") == "output_text":
                    value = part.get("text")
                    if not isinstance(value, str):
                        raise ResponsesError("Model returned an invalid message.")
                    text_parts.append(value)
        elif item.get("type") == "function_call":
            call_id, name, arguments = item.get("call_id"), item.get("name"), item.get("arguments")
            if (not isinstance(call_id, str) or not call_id or call_id in call_ids
                    or name not in _TOOL_NAMES or not isinstance(arguments, str)):
                raise ResponsesError("Model returned an invalid inspection tool call.")
            try:
                parsed = json.loads(arguments)
            except ValueError:
                raise ResponsesError("Model returned invalid inspection tool arguments.") from None
            if not isinstance(parsed, dict):
                raise ResponsesError("Model returned invalid inspection tool arguments.")
            call_ids.add(call_id)
            calls.append((call_id, name, parsed))
            if len(calls) > _MAX_TOOL_CALLS:
                raise ResponsesError("Model requested too many inspection tools in one turn.")
    return "".join(text_parts), calls


def run_agent(endpoint: str, model: str, system_prompt: str, user_message: str, repo_root: str,
              api_key: str = "", *, images=(), access_program: str = "", opener=None,
              progress: Callable[[str], None] = lambda text: print(text, end="", flush=True)) -> str:
    """Run a complete, read-only Responses analysis without provider-side response storage."""
    if not endpoint.startswith("https://") or not endpoint.endswith("/responses"):
        raise ResponsesError("A valid HTTPS Responses endpoint is required.")
    if not model or not model.strip():
        raise ResponsesError("A model ID is required for this provider.")
    if not api_key or any(character in api_key for character in "\r\n\0"):
        raise ResponsesError("A valid API key is required for this provider.")
    if access_program and access_program != "daybreak_blue":
        raise ResponsesError("Unsupported Daybreak access program.")

    input_items: list[dict] = [_user_input(user_message, images)]
    full_text = ""
    for _iteration in range(_MAX_AGENT_ITERATIONS):
        body = {"model": model, "instructions": system_prompt, "input": input_items,
                "tools": _tools(), "max_output_tokens": _MAX_OUTPUT_TOKENS, "store": False}
        if access_program:
            body["access_programs"] = {"cyber": access_program}
        response = _request(endpoint, body, api_key, opener)
        turn_text, calls = _inspect_output(response["output"])
        if turn_text:
            full_text += turn_text
            progress(turn_text)
        if not calls:
            return full_text
        # The complete output carries function calls and encrypted reasoning for
        # stateless continuation with store=false.
        input_items.extend(response["output"])
        for call_id, name, arguments in calls:
            progress(f"\n  → {name}\n")
            result = _execute_tool(repo_root, name, arguments)
            input_items.append({"type": "function_call_output", "call_id": call_id, "output": str(result)})
    raise ResponsesError("Model exceeded the inspection iteration limit. No complete report was saved.")
