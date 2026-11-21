#!/usr/bin/env python3
"""
Converse with Threatlint on a pull request (GitHub or Azure DevOps).

A developer comments `/threatlint <question>` (or mentions `@threatlint`) on a pull request.
This script collects bounded context, asks the configured model, and replies in the same
conversation:

  * the question and the earlier messages in that conversation,
  * pull request metadata and the diff (GitHub) or changed files (Azure DevOps),
  * the latest Threatlint report comment, found by its hidden `<!-- threatlint:report` marker.

Comments, diffs, reports, and PR descriptions are UNTRUSTED: they are wrapped in delimited blocks
and the model is told never to follow instructions inside them. PR code is never executed or
checked out. Replies are redacted for credentials, bounded in size, and carry a
`<!-- threatlint:chat -->` marker so the bot never answers itself.

Usage
-----
GitHub Actions (reads GITHUB_EVENT_PATH, GITHUB_REPOSITORY, GH_TOKEN; without it, a configured Threatlint GitHub App):
    python3 threatlint_chat.py --platform github --provider claude

Azure Pipelines (reads TL_EVENT_JSON from the service-hook webhook, SYSTEM_COLLECTIONURI,
SYSTEM_ACCESSTOKEN):
    python3 threatlint_chat.py --platform azure-devops --provider openai

Providers: claude (ANTHROPIC_API_KEY), openai (OPENAI_API_KEY), github-models (GH_TOKEN),
lmstudio (LMSTUDIO_BASE_URL, LMSTUDIO_MODEL). Dependency-free: only the standard library.
When copying outside a checkout, include all sibling _chat_*.py modules.
"""
import argparse
import json
import os
import re
import secrets
import sys
from pathlib import Path

# Installed scripts and file-based imports both resolve the bundled sibling helper.
_SCRIPT_DIR = str(Path(__file__).resolve().parent)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

import _chat_api
import _chat_azure
import _chat_content
import _chat_github
from _chat_api import chat_messages as _chat_messages, hosted_endpoint as _hosted_endpoint
from _chat_azure import (
    base_url as _ado_base_url, branch_name, display_name as _display_name,
    event_context as ado_event_context, pull_request as _ado_pr,
)
from _chat_github import (
    event_context as github_event_context, issue_comments_path,
    login as _login, pull_path, pull_request as _github_pr,
)
from _chat_content import bound, fence as _fence
from _chat_policy import (
    ADO_API, ADO_API_VERSION, ALLOWED_ASSOCIATIONS, CHAT_MARKER, DEFAULT_PROVIDER,
    GENERAL_MODEL, HTTP_TIMEOUT, MAX_ADO_FILE_CHARS, MAX_ADO_FILES,
    MAX_DESCRIPTION_CHARS, MAX_DIFF_CHARS, MAX_MESSAGE_CHARS, MAX_QUESTION_CHARS,
    MAX_REPLY_CHARS, MAX_REPORT_CHARS, MAX_RESPONSE_BYTES, MAX_THREAD_CHARS,
    MAX_THREAD_MESSAGES, MODEL_TIMEOUT, PROVIDERS, REPORT_MARKER, REVIEW_COMMENTS,
    SECRET_PATTERNS, TRIGGER_COMMAND, TRIGGER_MENTION,
    AdoComment, ChatError, GitHubComment, Message, PullRequest,
)


# ── Pure helpers (unit-tested) ────────────────────────────────────────────────

def redact(text):
    return _chat_content.redact(text, SECRET_PATTERNS)


def is_trigger(body):
    lowered = (body or '').lstrip().lower()
    return lowered.startswith(TRIGGER_COMMAND) or TRIGGER_MENTION in lowered


def should_respond(body, author='', author_type='', association=None, bot_names=()):
    """Return (respond, reason). association=None means the platform has no such concept."""
    body = body or ''
    if CHAT_MARKER in body or REPORT_MARKER in body:
        return False, 'comment was written by Threatlint'
    if author_type.lower() == 'bot' or author.lower().endswith('[bot]'):
        return False, 'comment author is a bot'
    if any(name and name.lower() in author.lower() for name in bot_names):
        return False, 'comment author is the build identity'
    if not is_trigger(body):
        return False, 'comment does not mention /threatlint or @threatlint'
    if association is not None and association.upper() not in ALLOWED_ASSOCIATIONS:
        return False, f'author association {association or "NONE"} is not allowed to invoke Threatlint'
    return True, 'triggered'


def extract_question(body):
    text = re.sub(r'(?i)^\s*/threatlint\b', '', body or '', count=1)
    text = re.sub(r'(?i)@threatlint\b', '', text).strip()
    return bound(text or 'Summarize the security findings for this pull request and what I should fix first.',
                 MAX_QUESTION_CHARS, 'question')


def build_prompt(question, pr, diff, report, thread, platform, nonce=None):
    """Return (system_prompt, user_prompt). All PR-derived text is delimited and untrusted."""
    limits = _chat_content.PromptLimits(MAX_DESCRIPTION_CHARS, MAX_REPORT_CHARS,
                                       MAX_DIFF_CHARS, MAX_THREAD_CHARS, MAX_THREAD_MESSAGES)
    return _chat_content.build_prompt(
        question, pr, diff, report, thread, platform, nonce or secrets.token_hex(8), limits,
        bound=bound, redact=redact, fence=_fence)


def format_reply(answer, provider, model):
    return _chat_content.format_reply(answer, provider, model, bound=bound, redact=redact,
                                      marker=CHAT_MARKER, max_chars=MAX_REPLY_CHARS)


def github_reply_request(repo, pr_number, body, review_comment_id=None):
    """(method, path, payload) for a reply in the same GitHub conversation."""
    if review_comment_id:
        path = pull_path(repo, pr_number, f'{REVIEW_COMMENTS}/{int(review_comment_id)}/replies')
    else:
        path = issue_comments_path(repo, pr_number)
    return 'POST', path, {'body': body}


def ado_reply_request(base, thread_id, parent_comment_id, body):
    """(method, url, payload) for a reply in the same Azure DevOps PR thread."""
    url = f'{base}/threads/{int(thread_id)}/comments?{ADO_API}'
    return 'POST', url, {'content': body, 'parentCommentId': int(parent_comment_id), 'commentType': 1}


# ── HTTP ─────────────────────────────────────────────────────────────────────

def bearer(token):
    return {'Authorization': f'Bearer {token}'}


def http(method, url, headers=None, payload=None, raw=False, timeout=HTTP_TIMEOUT, opener=None):
    return _chat_api.http(method, url, headers, payload, raw, timeout, opener,
                          max_bytes=MAX_RESPONSE_BYTES, error=ChatError)


# ── Model providers ──────────────────────────────────────────────────────────

def _claude(spec, system, user, model, env, opener):
    return _chat_api.claude(spec, system, user, model, env, opener, http=http,
                            messages=_chat_messages, error=ChatError, timeout=MODEL_TIMEOUT)


def _lmstudio_endpoint(model, env, opener):
    return _chat_api.lmstudio_endpoint(model, env, opener, http=http, error=ChatError)


def _chat_completion(url, key, system, user, model, opener):
    return _chat_api.chat_completion(url, key, system, user, model, opener, http=http,
                                     bearer=bearer, messages=_chat_messages,
                                     error=ChatError, timeout=MODEL_TIMEOUT)


def call_model(provider, system, user, model='', env=None, opener=None):
    """Return (model, answer) from the configured provider."""
    env = os.environ if env is None else env
    if provider not in PROVIDERS:
        raise ChatError(f'Unknown provider {provider}')
    spec = PROVIDERS[provider]
    if provider == DEFAULT_PROVIDER:
        model = model or env.get('THREATLINT_GENERAL_MODEL', '').strip() or spec['model']
        return _claude(spec, system, user, model, env, opener)
    model = model or spec['model']
    if provider == 'lmstudio':
        url, key, model = _lmstudio_endpoint(model, env, opener)
    else:
        url, key, model = _hosted_endpoint(provider, spec, model, env)
    return _chat_completion(url, key, system, user, model, opener)


# ── GitHub ───────────────────────────────────────────────────────────────────

class GitHub:
    def __init__(self, repo, token, api='https://api.github.com', opener=None):
        if not re.fullmatch(r'[\w.-]+/[\w.-]+', repo or ''):
            raise ChatError('GITHUB_REPOSITORY is invalid')
        self.repo, self.token, self.api, self.opener = repo, token, api.rstrip('/'), opener

    def call(self, method, path, payload=None, accept='application/vnd.github+json', raw=False):
        headers = {**bearer(self.token), 'Accept': accept, 'X-GitHub-Api-Version': '2022-11-28'}
        return http(method, f'{self.api}{path}', headers, payload, raw=raw, opener=self.opener)

    def pages(self, path, limit=5):
        items = []
        for page in range(1, limit + 1):
            batch = self.call('GET', f'{path}{"&" if "?" in path else "?"}per_page=100&page={page}')
            items.extend(batch)
            if len(batch) < 100:
                break
        return items


def _github_thread(client, number, context, issue_comments):
    """Earlier messages in the same conversation: the review thread, or prior /threatlint exchanges."""
    return _chat_github.thread(client, number, context, issue_comments, trigger=is_trigger,
                               bound=bound, marker=CHAT_MARKER, max_chars=MAX_MESSAGE_CHARS)


def github_token(env):
    """GH_TOKEN / GITHUB_TOKEN; when neither is set, a Threatlint GitHub App installation token (when threatlint is
    installed and an App is configured in ~/.threatlint/github-app.json). Never printed."""
    token = env.get('GH_TOKEN') or env.get('GITHUB_TOKEN')
    if token:
        return token
    try:
        from threatlint import github_app
    except ImportError:
        return ''
    if not github_app.configured():
        return ''
    try:
        return github_app.installation_token()
    except github_app.GitHubAppError as exc:
        raise ChatError(f'GitHub App token unavailable: {exc}') from None


def run_github(args, env, opener=None):
    with open(env['GITHUB_EVENT_PATH'], encoding='utf-8') as handle:
        event = json.load(handle)
    context = github_event_context(event, env.get('GITHUB_EVENT_NAME', ''))
    if not context.pr:
        return print('Skipping: the comment is not on a pull request.')
    respond, reason = should_respond(context.body, context.author, context.author_type, context.association)
    if not respond:
        return print(f'Skipping: {reason}.')
    client = GitHub(env.get('GITHUB_REPOSITORY', ''), github_token(env), env.get('GITHUB_API_URL', 'https://api.github.com'), opener)
    number = int(context.pr)
    pr = _github_pr(client, number)
    diff = client.call('GET', pull_path(client.repo, number), accept='application/vnd.github.diff', raw=True)
    issue_comments = client.pages(issue_comments_path(client.repo, number))
    reports = [item['body'] for item in issue_comments if REPORT_MARKER in (item.get('body') or '')]
    thread = _github_thread(client, number, context, issue_comments)
    reply = answer(args, context.body, pr, diff, reports[-1] if reports else '', thread, 'GitHub', env, opener)
    if args.dry_run:
        return print(reply)
    method, path, payload = github_reply_request(client.repo, number, reply, context.root_id)
    client.call(method, path, payload)
    print(f'Replied on pull request #{number}.')


# ── Azure DevOps ─────────────────────────────────────────────────────────────

def _ado_file_section(change, items_url, commit, headers, opener):
    return _chat_azure.file_section(
        change, items_url, commit, headers, opener, request=http, bound=bound,
        max_chars=MAX_ADO_FILE_CHARS, version=ADO_API_VERSION, error=ChatError)


def ado_changed_files(base, items_url, commit, headers, opener):
    """Changed files at the PR source commit; Azure DevOps has no unified diff API."""
    return _chat_azure.changed_files(
        base, items_url, commit, headers, opener, request=http, section=_ado_file_section,
        max_files=MAX_ADO_FILES, api=ADO_API)


def _ado_skip_reason(context, env):
    if not (context.pr and context.thread_id and context.comment_id):
        return 'the webhook payload is not a pull request comment'
    if context.comment_type == 'system':
        return 'system comment'
    bot_names = [name for name in (env.get('TL_BOT_NAME', ''), 'Build Service') if name]
    respond, reason = should_respond(context.body, context.author, bot_names=bot_names)
    return None if respond else reason


def _ado_report_and_thread(threads, context):
    return _chat_azure.report_and_thread(
        threads, context, marker=REPORT_MARKER, bound=bound, max_chars=MAX_MESSAGE_CHARS)


def run_azure(args, env, opener=None):
    context = ado_event_context(json.loads(env.get('TL_EVENT_JSON') or '{}'))
    reason = _ado_skip_reason(context, env)
    if reason:
        return print(f'Skipping: {reason}.')
    base, items_url = _ado_base_url(context, env)
    headers = {**bearer(env.get('SYSTEM_ACCESSTOKEN', '')), 'Accept': 'application/json'}
    pull = http('GET', f'{base}?{ADO_API}', headers, opener=opener)
    commit = (pull.get('lastMergeSourceCommit') or {}).get('commitId', '')
    diff = ado_changed_files(base, items_url, commit, headers, opener)
    threads = http('GET', f'{base}/threads?{ADO_API}', headers, opener=opener).get('value', [])
    report, history = _ado_report_and_thread(threads, context)
    reply = answer(args, context.body, _ado_pr(pull), diff, report, history, 'Azure DevOps', env, opener)
    if args.dry_run:
        return print(reply)
    method, url, payload = ado_reply_request(base, context.thread_id, context.comment_id, reply)
    http(method, url, headers, payload, opener=opener)
    print(f'Replied in thread {context.thread_id} on pull request {context.pr}.')


# ── Orchestration ────────────────────────────────────────────────────────────

def answer(args, body, pr, diff, report, thread, platform, env, opener=None):
    system, user = build_prompt(extract_question(body), pr, diff, report, thread, platform)
    if args.dry_run:
        print(user)
        return format_reply('(dry run: no model was called)', args.provider, args.model)
    try:
        model, text = call_model(args.provider, system, user, args.model, env, opener)
    except ChatError as exc:
        print(f'Model call failed: {exc}', file=sys.stderr)
        return format_reply(f'Sorry, I could not reach the configured model ({args.provider}). '
                            'A maintainer can check the pipeline logs and provider credentials.', args.provider, args.model)
    return format_reply(text, args.provider, model)


def main(argv=None, env=None, opener=None):
    env = os.environ if env is None else env
    parser = argparse.ArgumentParser(description='Reply to /threatlint questions on pull requests')
    parser.add_argument('--platform', choices=['github', 'azure-devops'], required=True)
    parser.add_argument('--provider', choices=list(PROVIDERS), default=env.get('TL_PROVIDER') or DEFAULT_PROVIDER)
    parser.add_argument('--model', default=env.get('TL_MODEL', ''))
    parser.add_argument('--dry-run', action='store_true', help='Print the prompt and skip the model call')
    args = parser.parse_args(argv)
    if args.model and not re.fullmatch(r'[A-Za-z0-9._:/@-]{1,120}', args.model):
        parser.error('invalid model name')
    try:
        (run_github if args.platform == 'github' else run_azure)(args, env, opener)
    except ChatError as exc:
        print(f'threatlint chat: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
