"""Azure DevOps event normalization and bounded PR-context collection."""
import re
import urllib.parse

from _chat_policy import AdoComment, ChatError, Message, PullRequest


def branch_name(ref):
    return re.sub(r'^refs/heads/', '', ref or '')


def display_name(record, key='author'):
    return (record.get(key) or {}).get('displayName', '')


def event_context(event):
    resource = event.get('resource') or {}
    comment = resource.get('comment') or {}
    pull = resource.get('pullRequest') or {}
    links = ' '.join(str((comment.get('_links') or {}).get(name, {}).get('href', '')) for name in ('threads', 'self'))
    thread = re.search(r'/threads/(\d+)', links)
    author = comment.get('author') or {}
    repository = pull.get('repository') or {}
    return AdoComment(
        body=comment.get('content', ''), author=f'{display_name(comment)} {author.get("uniqueName", "")}'.strip(),
        comment_id=comment.get('id'), thread_id=int(thread.group(1)) if thread else None,
        comment_type=str(comment.get('commentType', 'text')).lower(), pr=pull.get('pullRequestId'),
        repository=repository.get('id'), project=(repository.get('project') or {}).get('id'))


def base_url(context, env):
    collection = env.get('SYSTEM_COLLECTIONURI', '').rstrip('/') + '/'
    if not collection.startswith('https://'):
        raise ChatError('SYSTEM_COLLECTIONURI must be an HTTPS Azure DevOps URL')
    project = context.project or env.get('SYSTEM_TEAMPROJECTID', '')
    for value in (project, context.repository):
        if not re.fullmatch(r'[0-9A-Fa-f-]{36}', str(value or '')):
            raise ChatError('The webhook payload has an invalid project or repository ID')
    repository = f'{collection}{project}/_apis/git/repositories/{context.repository}'
    return f'{repository}/pullRequests/{int(context.pr)}', f'{repository}/items'


def pull_request(pull):
    return PullRequest(
        title=pull.get('title', ''), description=pull.get('description') or '',
        author=display_name(pull, 'createdBy'), source=branch_name(pull.get('sourceRefName')),
        target=branch_name(pull.get('targetRefName')))


def file_section(change, items_url, commit, headers, opener, *, request, bound, max_chars, version, error):
    item = change.get('item') or {}
    path, kind = item.get('path', ''), change.get('changeType', 'edit')
    if not path or item.get('isFolder'):
        return None
    content = ''
    if 'delete' not in str(kind) and commit:
        query = urllib.parse.urlencode({
            'path': path, 'versionDescriptor.version': commit,
            'versionDescriptor.versionType': 'commit', 'includeContent': 'true', 'api-version': version})
        try:
            content = request('GET', f'{items_url}?{query}', headers, opener=opener).get('content', '')
        except error:
            content = '(content unavailable)'
    return f'--- {kind}: {path}\n{bound(content, max_chars, path)}'


def changed_files(base, items_url, commit, headers, opener, *, request, section, max_files, api):
    iterations = request('GET', f'{base}/iterations?{api}', headers, opener=opener).get('value', [])
    if not iterations:
        return ''
    latest = max(item.get('id', 0) for item in iterations)
    changes = request(
        'GET', f'{base}/iterations/{latest}/changes?{api}&$top={max_files}',
        headers, opener=opener).get('changeEntries', [])
    sections = [section(change, items_url, commit, headers, opener) for change in changes[:max_files]]
    return 'Changed files at the PR source commit (Azure DevOps has no unified diff API):\n\n' + '\n\n'.join(filter(None, sections))


def report_and_thread(threads, context, *, marker, bound, max_chars):
    comments = [comment for thread in threads for comment in thread.get('comments', []) if not comment.get('isDeleted')]
    reports = sorted((comment for comment in comments if marker in (comment.get('content') or '')), key=lambda item: item.get('publishedDate', ''))
    current = next((thread for thread in threads if thread.get('id') == context.thread_id), {})
    history = [Message(display_name(item) or '?', bound(item.get('content') or '', max_chars))
               for item in current.get('comments', []) if item.get('id') != context.comment_id and not item.get('isDeleted')]
    return (reports[-1]['content'] if reports else ''), history
