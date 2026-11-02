"""Bounded HTTP transport and model-provider wire protocols.

Provider operations receive the script's transport, message builder, error type,
and timeout explicitly. No environment, client, or network state is captured here.
"""
import json
import urllib.error
import urllib.parse
import urllib.request

from _chat_policy import ChatError


def http(method, url, headers, payload, raw, timeout, opener, *, max_bytes, error):
    opener = opener or urllib.request.urlopen
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={
        'User-Agent': 'threatlint-pr-chat', **({'Content-Type': 'application/json'} if data else {}), **(headers or {})})
    try:
        with opener(request, timeout=timeout) as response:
            content = response.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        raise error(f'{method} {urllib.parse.urlsplit(url).path} returned HTTP {exc.code}') from None
    except OSError as exc:  # urllib.error.URLError is an OSError
        raise error(f'{method} {urllib.parse.urlsplit(url).netloc} failed: {getattr(exc, "reason", exc)}') from None
    if len(content) > max_bytes:
        content = content[:max_bytes]
    text = content.decode('utf-8', errors='replace')
    if raw:
        return text
    return json.loads(text) if text.strip() else {}


def chat_messages(system, user):
    return [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}]


def claude(spec, system, user, model, env, opener, *, http, messages, error, timeout):
    key = env.get('ANTHROPIC_API_KEY')
    if not key:
        raise error('ANTHROPIC_API_KEY is not configured')
    result = http('POST', spec['url'], {'x-api-key': key, 'anthropic-version': '2023-06-01'},
                  {'model': model, 'max_tokens': 4_000, 'system': system, 'messages': messages(system, user)[1:]},
                  timeout=timeout, opener=opener)
    return model, ''.join(block.get('text', '') for block in result.get('content', []) if block.get('type') == 'text')


def lmstudio_endpoint(model, env, opener, *, http, error):
    base = env.get('LMSTUDIO_BASE_URL', 'http://localhost:1234/v1').rstrip('/')
    if not model:
        loaded = http('GET', f'{base}/models', opener=opener).get('data', [])
        model = env.get('LMSTUDIO_MODEL') or (loaded[0]['id'] if loaded else '')
    if not model:
        raise error('No model is loaded in LM Studio')
    return f'{base}/chat/completions', None, model


def hosted_endpoint(provider, spec, model, env):
    key = env.get(spec['key'])
    if not key and provider == 'github-models':
        key = env.get('GITHUB_TOKEN')
    if not key:
        raise ChatError(f'{spec["key"]} is not configured')
    return spec['url'], key, model


def chat_completion(url, key, system, user, model, opener, *, http, bearer, messages, error, timeout):
    headers = bearer(key) if key else {}
    result = http('POST', url, headers,
                  {'model': model, 'max_tokens': 4_000, 'messages': messages(system, user)},
                  timeout=timeout, opener=opener)
    try:
        return model, result['choices'][0]['message']['content'] or ''
    except (KeyError, IndexError, TypeError):
        raise error('The model returned an unexpected response') from None
