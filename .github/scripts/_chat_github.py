"""GitHub PR event normalization, API paths, and conversation selection."""
from _chat_policy import GitHubComment, Message, PullRequest, REVIEW_COMMENTS


def pull_path(repo, number, suffix=''):
    return f'/repos/{repo}/pulls/{int(number)}{suffix}'


def issue_comments_path(repo, number):
    return f'/repos/{repo}/issues/{int(number)}{REVIEW_COMMENTS}'


def login(record):
    return (record.get('user') or {}).get('login', '')


def event_context(event, event_name):
    comment = event.get('comment') or {}
    issue = event.get('issue') or {}
    pr_number = (event.get('pull_request') or {}).get('number') or issue.get('number')
    if event_name == 'issue_comment' and 'pull_request' not in issue:
        pr_number = None
    root_id = None
    if event_name == 'pull_request_review_comment':
        root_id = comment.get('in_reply_to_id') or comment.get('id')
    return GitHubComment(
        body=comment.get('body', ''), author=login(comment),
        author_type=(comment.get('user') or {}).get('type', ''),
        association=comment.get('author_association', 'NONE'),
        comment_id=comment.get('id'), root_id=root_id, pr=pr_number)


def pull_request(client, number):
    pull = client.call('GET', pull_path(client.repo, number))
    return PullRequest(
        title=pull.get('title', ''), description=pull.get('body') or '', author=login(pull),
        source=(pull.get('head') or {}).get('ref', ''),
        target=(pull.get('base') or {}).get('ref', ''), url=pull.get('html_url', ''))


def thread(client, number, context, issue_comments, *, trigger, bound, marker, max_chars):
    """Keep only the current review thread or earlier bot-command exchanges."""
    if context.root_id:
        review_comments = client.pages(pull_path(client.repo, number, REVIEW_COMMENTS))
        conversation = [item for item in review_comments if context.root_id in (item.get('id'), item.get('in_reply_to_id'))]
    else:
        conversation = [item for item in issue_comments if trigger(item.get('body')) or marker in (item.get('body') or '')]
    return [Message(login(item) or '?', bound(item.get('body') or '', max_chars))
            for item in conversation if item.get('id') != context.comment_id]
