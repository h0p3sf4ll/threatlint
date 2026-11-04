"""The runtime red-team ruleset and its learned store.

A `Rule` is a bounded, declarative runtime test pattern. Its `kind` selects one of the vetted probe behaviours in
`dast_requests.plan_requests` / `dast_probe.assess` (active: xss, sqli, traversal, redirect, dirlist; passive:
cors, cookie, headers, disclosure, debug), so the ruleset decides *which* patterns run against *which* endpoints
without introducing any new, unvetted request shape. Rules never carry free-form payloads.

The `Ruleset` layers a per-user learned store over the built-in seed. Learning never invents exploits: an assessment
records, per rule, how often it was attempted and confirmed and on which endpoint shapes, then uses that to order
and prioritise rules so later assessments probe the highest-yield patterns and endpoints first. Stats and the
endpoint affinities are the only things that persist; the request shapes stay fixed in code.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, field, replace

# Active rules need a query/body parameter to target; passive rules observe any response.
ACTIVE_KINDS = ("xss", "sqli", "traversal", "redirect")
PASSIVE_KINDS = ("dirlist", "cors", "cookie", "headers", "disclosure", "debug")
KINDS = ACTIVE_KINDS + PASSIVE_KINDS


@dataclass
class Rule:
    """One runtime test pattern. `kind` maps to a vetted probe behaviour; `applies` bounds where it runs.

    `applies` keys (all optional): ``stacks`` (node/python/java/go; empty = any), ``needs_param`` (bool),
    ``methods`` (allowed HTTP methods for the endpoint). Learned fields (``runs``, ``hits``, ``affinity``,
    ``provenance``) are updated by assessments and persisted; everything else is fixed in the seed.
    """

    id: str
    title: str
    category: str          # OWASP Top 10 category, e.g. "A03:2021-Injection"
    cwe: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    kind: str
    applies: dict = field(default_factory=dict)
    source: str = "built-in"
    runs: int = 0
    hits: int = 0
    affinity: dict = field(default_factory=dict)   # path-segment token -> confirmed count
    provenance: list = field(default_factory=list)  # bounded list of {path, signal, run}

    @property
    def yield_rate(self) -> float:
        return self.hits / self.runs if self.runs else 0.0

    def priority(self) -> float:
        """Higher runs first. Confirmed yield dominates; unproven rules keep a prior so they still get tried."""
        prior = {"CRITICAL": 0.5, "HIGH": 0.4, "MEDIUM": 0.3, "LOW": 0.2, "INFO": 0.1}.get(self.severity, 0.2)
        return self.yield_rate + prior / (1 + self.runs)

    def to_dict(self) -> dict:
        return {key: value for key, value in self.__dict__.items()}

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        fields = {key: data[key] for key in cls.__dataclass_fields__ if key in data}
        return cls(**fields)


def _rule(identifier, title, category, cwe, severity, kind, **applies) -> Rule:
    return Rule(identifier, title, category, cwe, severity, kind, applies=applies)


# ── Built-in seed ruleset ──────────────────────────────────────────────────────
# Each rule reuses a probe behaviour already vetted in dast_probe/dast_passive; no new request shapes.

BUILT_IN: tuple[Rule, ...] = (
    _rule("RT-RT-SQLI", "SQL injection via a request parameter", "A03:2021-Injection", "CWE-89", "CRITICAL", "sqli", needs_param=True),
    _rule("RT-RT-XSS", "Reflected cross-site scripting", "A03:2021-Injection", "CWE-79", "HIGH", "xss", needs_param=True),
    _rule("RT-RT-TRAVERSAL", "Path traversal via a request parameter", "A01:2021-Broken Access Control", "CWE-22", "HIGH", "traversal", needs_param=True),
    _rule("RT-RT-REDIRECT", "Open redirect via a request parameter", "A01:2021-Broken Access Control", "CWE-601", "MEDIUM", "redirect", needs_param=True),
    _rule("RT-RT-DIRLIST", "Directory listing exposed", "A05:2021-Security Misconfiguration", "CWE-548", "LOW", "dirlist"),
    _rule("RT-RT-CORS", "CORS reflects an untrusted origin", "A05:2021-Security Misconfiguration", "CWE-942", "MEDIUM", "cors"),
    _rule("RT-RT-COOKIE", "Session cookie missing security flags", "A05:2021-Security Misconfiguration", "CWE-1004", "MEDIUM", "cookie"),
    _rule("RT-RT-HEADERS", "Missing security response headers", "A05:2021-Security Misconfiguration", "CWE-693", "LOW", "headers"),
    _rule("RT-RT-DISCLOSE", "Software version disclosed in responses", "A05:2021-Security Misconfiguration", "CWE-200", "INFO", "disclosure"),
    _rule("RT-RT-DEBUG", "Debug output or stack trace in responses", "A05:2021-Security Misconfiguration", "CWE-209", "MEDIUM", "debug"),
)

_PATH_TOKEN = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{2,}")


def endpoint_tokens(path: str) -> list[str]:
    """Stable, non-numeric path segments used as endpoint-shape keys for affinity (e.g. /api/users/42 -> api,users)."""
    return [token.lower() for token in _PATH_TOKEN.findall(path or "")][:6]


class Ruleset:
    """The built-in rules merged with a per-user learned store; selects and orders rules for an assessment."""

    def __init__(self, rules: list[Rule]):
        self.rules = {rule.id: rule for rule in rules}

    @classmethod
    def seed(cls) -> "Ruleset":
        return cls([replace(rule) for rule in BUILT_IN])

    def applicable(self, stack: str, endpoint: dict) -> list[Rule]:
        """Rules that may run against one endpoint, highest priority first, with learned affinity as a tie-breaker."""
        has_param = bool(endpoint.get("params"))
        method = (endpoint.get("method") or "GET").upper()
        tokens = set(endpoint_tokens(endpoint.get("path", "")))
        chosen = []
        for rule in self.rules.values():
            stacks = rule.applies.get("stacks") or ()
            methods = rule.applies.get("methods") or ()
            if stacks and stack not in stacks:
                continue
            if methods and method not in methods:
                continue
            if rule.applies.get("needs_param") and not has_param:
                continue
            chosen.append(rule)
        return sorted(chosen, key=lambda rule: (rule.priority() + 0.25 * bool(tokens & set(rule.affinity)), rule.id), reverse=True)

    def record(self, rule_id: str, endpoint: dict, confirmed: bool, signal: str, run_id: str) -> None:
        """Update one rule's learned stats after a probe. Confirmed probes add bounded provenance and affinity."""
        rule = self.rules.get(rule_id)
        if not rule:
            return
        rule.runs += 1
        if confirmed:
            rule.hits += 1
            for token in endpoint_tokens(endpoint.get("path", "")):
                rule.affinity[token] = rule.affinity.get(token, 0) + 1
            rule.provenance = ([{"path": endpoint.get("path", ""), "signal": signal[:200], "run": run_id}] + rule.provenance)[:20]

    def summary(self) -> list[dict]:
        return [{"id": rule.id, "kind": rule.kind, "severity": rule.severity, "runs": rule.runs, "hits": rule.hits,
                 "yield": round(rule.yield_rate, 3), "source": rule.source} for rule in
                sorted(self.rules.values(), key=lambda rule: (rule.hits, rule.runs), reverse=True)]


# ── Persistence (per-user learned store, atomic 0600 write) ─────────────────────

def _home() -> str:
    return os.environ.get("THREATLINT_HOME") or os.path.join(os.path.expanduser("~"), ".threatlint")


def store_path() -> str:
    return os.path.join(_home(), "redteam", "ruleset.json")


def load_ruleset(path: str | None = None) -> Ruleset:
    """The built-in seed merged with the learned store at `path` (default ~/.threatlint/redteam/ruleset.json).

    Built-in request shapes always come from code; only learned stats/affinity/provenance are read from disk. A new
    built-in rule appears automatically; a stored rule id no longer in the seed is kept as a learned-only rule.
    """
    ruleset = Ruleset.seed()
    try:
        with open(path or store_path(), encoding="utf-8") as handle:
            stored = json.load(handle)
    except (OSError, ValueError):
        return ruleset
    for entry in stored.get("rules", []) if isinstance(stored, dict) else []:
        if not isinstance(entry, dict) or not entry.get("id"):
            continue
        existing = ruleset.rules.get(entry["id"])
        if existing:
            existing.runs, existing.hits = int(entry.get("runs", 0)), int(entry.get("hits", 0))
            existing.affinity = {str(k): int(v) for k, v in (entry.get("affinity") or {}).items()}
            existing.provenance = [item for item in (entry.get("provenance") or []) if isinstance(item, dict)][:20]
        elif entry.get("kind") in KINDS:
            ruleset.rules[entry["id"]] = Rule.from_dict({**entry, "source": "learned"})
    return ruleset


def save_ruleset(ruleset: Ruleset, path: str | None = None) -> str:
    """Write the learned store atomically, readable only by the current user; returns the path."""
    target = path or store_path()
    os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
    payload = {"version": 1, "rules": [rule.to_dict() for rule in ruleset.rules.values()]}
    descriptor, temporary = tempfile.mkstemp(dir=os.path.dirname(target), prefix=".ruleset.", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=1)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        if os.name != "nt":
            os.chmod(target, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return target
