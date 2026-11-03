"""Base class and safety rails for secret validators.

A secret validator answers one question for the FP reviewer: **is this detected credential live right now?**

Safety contract (enforced here, not left to each validator):
  - A validator may contact only the HTTPS hosts it declares in `hosts`. Hosts are fixed provider API endpoints;
    a credential is never sent to a host taken from the scanned content, the finding, or a configuration file
    (that would let a crafted repository exfiltrate it).
  - Redirects are refused, every request has a short timeout, and responses are capped in size.
  - Only read-only identity / introspection calls are allowed (e.g. GET /user, Slack auth.test, AWS STS
    GetCallerIdentity). Validators must never create, change, or delete anything with the credential.
  - The secret value never leaves this module in output: results carry a masked form and a SHA-256 fingerprint.
    Identity details are limited to the fields a validator explicitly whitelists, truncated.
  - Validation can be switched off (THREATLINT_SECRET_VALIDATION=off, or --no-network) and then reports UNVERIFIED.

Statuses: VALID (the provider accepted the credential), INVALID (the provider rejected it: revoked, expired, or
never real), UNVERIFIED (no validator, validation disabled, network failure, rate limit, or an unexpected answer).
UNVERIFIED is never evidence either way.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from threatlint.integrations.common import Integration

KIND = "secret-validation"
VALID, INVALID, UNVERIFIED = "VALID", "INVALID", "UNVERIFIED"
STATUSES = (VALID, INVALID, UNVERIFIED)
TIMEOUT_S = 15
MAX_RESPONSE = 256 * 1024
_IDENTITY_MAX = 120
USER_AGENT = "threatlint-secret-validation"


def fingerprint(secret: str) -> str:
    """A non-reversible identifier for correlating the same credential across findings."""
    return "sha256:" + hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def mask(secret: str) -> str:
    """Enough to recognise the credential type and tell two apart; never enough to use it."""
    if len(secret) >= 24:
        return f"{secret[:4]}…{secret[-4:]} ({len(secret)} chars)"
    return f"…({len(secret)} chars)"


@dataclasses.dataclass
class Candidate:
    """One credential found in the scanned text. `secret` and `extra` stay in memory only."""

    validator: str
    secret: str
    line: int = 0
    extra: dict = dataclasses.field(default_factory=dict, repr=False)

    def __repr__(self) -> str:  # never print the value, even in a traceback
        return f"Candidate(validator={self.validator!r}, secret={mask(self.secret)!r}, line={self.line})"


@dataclasses.dataclass
class Result:
    status: str
    detail: str = ""
    identity: dict = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        self.detail = re.sub(r"\s+", " ", str(self.detail or ""))[:300]
        self.identity = {str(key)[:40]: str(value)[:_IDENTITY_MAX] for key, value in (self.identity or {}).items() if value not in (None, "")}


@dataclasses.dataclass
class Response:
    status: int
    headers: dict
    body: bytes

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def header(self, name: str) -> str:
        return str(self.headers.get(name.lower(), ""))


class HostNotAllowed(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D102 - refuse every redirect
        return None


class LockedHTTP:
    """HTTPS client that can reach only the validator's declared hosts and never follows redirects."""

    def __init__(self, hosts: tuple[str, ...]):
        self.hosts = frozenset(host.lower() for host in hosts)
        from threatlint.tls import ssl_context  # noqa: PLC0415
        self._opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ssl_context()))

    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None, data: bytes | None = None) -> Response:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or (parts.hostname or "").lower() not in self.hosts or parts.username or parts.password:
            raise HostNotAllowed(f"{parts.hostname or url!r} is not one of this validator's hosts")
        if method not in ("GET", "POST", "HEAD"):
            raise HostNotAllowed(f"method {method} is not allowed for validation")
        request = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": USER_AGENT, **(headers or {})})
        try:
            with self._opener.open(request, timeout=TIMEOUT_S) as response:  # noqa: S310 - host allow-listed above
                return Response(response.status, {k.lower(): v for k, v in response.headers.items()}, response.read(MAX_RESPONSE))
        except urllib.error.HTTPError as exc:
            return Response(exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read(MAX_RESPONSE) if exc.fp else b"")


class SecretValidator(Integration):
    """Detects one provider's credential format and checks it against that provider's identity endpoint.

    Subclasses set `name`, `label`, `hosts`, and `patterns` (group 1, else the whole match, is the secret) and
    implement `check`. Override `find` when a credential needs a second value (AWS key id + secret key)."""

    kind = KIND
    hosts: tuple[str, ...] = ()
    patterns: tuple[re.Pattern, ...] = ()
    endpoint = ""  # documentation only: the single call `check` makes

    def find(self, text: str, context: str = "", line: int = 0) -> list[Candidate]:
        """Credentials of this type in `text` (the flagged line). `context` holds nearby lines for paired values."""
        found = []
        for pattern in self.patterns:
            for match in pattern.finditer(text):
                found.append(Candidate(self.name, match.group(1) if match.groups() else match.group(0), line))
        return found

    def check(self, candidate: Candidate, http: LockedHTTP) -> Result:
        raise NotImplementedError

    def validate(self, candidate: Candidate) -> Result:
        """Run `check` inside the safety rails; any failure becomes UNVERIFIED with a value-free reason."""
        if not self.hosts:
            return Result(UNVERIFIED, f"{self.label} validator declares no hosts")
        try:
            return self.check(candidate, LockedHTTP(self.hosts))
        except HostNotAllowed as exc:
            return Result(UNVERIFIED, f"blocked: {exc}")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            return Result(UNVERIFIED, f"network error: {type(reason).__name__}")
        except Exception as exc:  # noqa: BLE001 - a validator bug must not leak the value or stop the run
            return Result(UNVERIFIED, f"validator error: {type(exc).__name__}")

    # Helpers for subclasses -----------------------------------------------------
    @staticmethod
    def by_status(response: Response, *, valid=(200,), invalid=(401,), identity: dict | None = None, valid_note: str = "") -> Result:
        if response.status in valid:
            return Result(VALID, valid_note or f"accepted (HTTP {response.status})", identity or {})
        if response.status in invalid:
            return Result(INVALID, f"rejected (HTTP {response.status})")
        if response.status == 429:
            return Result(UNVERIFIED, "rate limited (HTTP 429); retry later")
        return Result(UNVERIFIED, f"unexpected HTTP {response.status}")
