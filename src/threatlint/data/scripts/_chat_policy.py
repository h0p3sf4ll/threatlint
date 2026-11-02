"""Default PR-chat limits, provider metadata, and shared record types."""
import re
from typing import NamedTuple, Optional

CHAT_MARKER = '<!-- threatlint:chat -->'
REPORT_MARKER = '<!-- threatlint:report'
TRIGGER_COMMAND = '/threatlint'
TRIGGER_MENTION = '@threatlint'
DEFAULT_PROVIDER = 'claude'
REVIEW_COMMENTS = '/comments'
ALLOWED_ASSOCIATIONS = frozenset({'OWNER', 'MEMBER', 'COLLABORATOR'})

MAX_QUESTION_CHARS = 4_000
MAX_DIFF_CHARS = 60_000
MAX_REPORT_CHARS = 40_000
MAX_THREAD_CHARS = 12_000
MAX_THREAD_MESSAGES = 12
MAX_MESSAGE_CHARS = 2_000
MAX_DESCRIPTION_CHARS = 4_000
MAX_REPLY_CHARS = 60_000          # GitHub caps comments at 65,536 characters.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ADO_FILES = 25
MAX_ADO_FILE_CHARS = 6_000
HTTP_TIMEOUT = 60
ADO_API_VERSION = '7.1'
ADO_API = f'api-version={ADO_API_VERSION}'
MODEL_TIMEOUT = 300

# PR chat follows the general assistance model; explicit and environment overrides
# are resolved by the conversation entry point.
GENERAL_MODEL = 'claude-opus-5-5'
PROVIDERS = {
    DEFAULT_PROVIDER: {'url': 'https://api.anthropic.com/v1/messages', 'model': GENERAL_MODEL, 'key': 'ANTHROPIC_API_KEY'},
    'openai': {'url': 'https://api.openai.com/v1/chat/completions', 'model': 'gpt-4o', 'key': 'OPENAI_API_KEY'},
    'github-models': {'url': 'https://models.inference.ai.azure.com/chat/completions', 'model': 'openai/gpt-4o', 'key': 'GH_TOKEN'},
    'lmstudio': {'url': None, 'model': '', 'key': None},
}

SECRET_PATTERNS = [
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'), '[REDACTED PRIVATE KEY]'),
    (re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b'), '[REDACTED GITHUB TOKEN]'),
    (re.compile(r'\bgithub_pat_[A-Za-z0-9_]{20,}\b'), '[REDACTED GITHUB TOKEN]'),
    (re.compile(r'\bsk-ant-[A-Za-z0-9_-]{16,}\b'), '[REDACTED API KEY]'),
    (re.compile(r'\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b'), '[REDACTED API KEY]'),
    (re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'), '[REDACTED AWS KEY]'),
    (re.compile(r'\bxox[abposr]-[A-Za-z0-9-]{10,}\b'), '[REDACTED SLACK TOKEN]'),
    (re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b'), '[REDACTED GOOGLE KEY]'),
    (re.compile(r'(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}'), r'\1 [REDACTED]'),
    (re.compile(r'(?i)((?:password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*["\']?)[^\s"\'`,;]{8,}'), r'\1[REDACTED]'),
]


class PullRequest(NamedTuple):
    title: str = ''
    description: str = ''
    author: str = ''
    source: str = ''
    target: str = ''
    url: str = ''


class Message(NamedTuple):
    author: str
    body: str


class GitHubComment(NamedTuple):
    body: str
    author: str
    author_type: str
    association: str
    comment_id: Optional[int]
    root_id: Optional[int]       # review-thread root when the comment is on a diff line
    pr: Optional[int]


class AdoComment(NamedTuple):
    body: str
    author: str
    comment_id: Optional[int]
    thread_id: Optional[int]
    comment_type: str
    pr: Optional[int]
    repository: Optional[str]
    project: Optional[str]


class ChatError(Exception):
    """A failure that is safe to describe to the person who asked."""
