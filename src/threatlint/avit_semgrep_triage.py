"""Scoped Semgrep triage: ignore exactly the requested findings, record durable evidence, and verify the write.

`ignore` marks Semgrep findings as ignored / false_positive only inside one repository, branch, and rule:

  1. the request is checked (supported product, explicit positive IDs, exact scope);
  2. an audit record is written to ~/.threatlint/triage/<uuid>.json *before* anything changes;
  3. the findings are re-read in that scope; every requested ID must exist there and be open or already ignored;
  4. only the still-open IDs are submitted, and Semgrep's affected IDs and count must equal what was submitted;
  5. the scope is read back and every requested ID must now be ignored.

Each step updates the audit record (attempt → write_attempt → response_received → verified, or already_ignored /
unverified), so an interrupted or partially applied triage can be inspected instead of blindly retried.
"""

from __future__ import annotations

import json
import os
import tempfile
import urllib.parse
import uuid
from collections.abc import Callable, Iterable
from pathlib import Path

from threatlint.avit_report import ResolveError
from threatlint.avit_semgrep import scoped_findings

PRODUCTS = ("sast", "sca", "secrets")
TRIAGE_STATES = ("open", "ignored")
_NOTE_LIMIT = 3000


def _is_id(value: object) -> bool:
    """A positive integer finding ID (bool is an int subclass, so reject it explicitly)."""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _write_json(path: Path, payload: dict) -> None:
    """Atomically replace `path` with `payload`, fsynced so the evidence survives a crash."""
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(payload, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        except (OSError, TypeError, ValueError):
            temporary.unlink(missing_ok=True)
            raise
    os.replace(temporary, path)


class TriageAudit:
    """One triage attempt's evidence file; every `record` call persists the cumulative state."""

    def __init__(self, evidence: dict, directory: Path | None = None):
        directory = directory or Path(os.environ.get("THREATLINT_HOME") or Path.home() / ".threatlint") / "triage"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = directory / f"{uuid.uuid4().hex}.json"
        self.evidence = dict(evidence)
        _write_json(self.path, self.evidence)

    def record(self, status: str, **details) -> None:
        self.evidence.update(status=status, **details)
        _write_json(self.path, self.evidence)

    def __str__(self) -> str:
        return str(self.path)


def _check_request(kind: str, ids: Iterable, *, repository: str, ref: str, rule: str, deployment_id) -> list[int]:
    """The sorted, de-duplicated IDs, or ResolveError when the request is not narrowly scoped."""
    if not (repository and ref and rule):
        raise ResolveError("Semgrep triage requires an exact repository, branch, and rule")
    if kind not in PRODUCTS or (kind == "secrets" and not deployment_id):
        raise ResolveError("Semgrep triage requires a supported product and Secrets deployment ID")
    ids = list(ids)
    if not ids or not all(_is_id(value) for value in ids):
        raise ResolveError("Semgrep triage requires explicit positive finding IDs")
    return sorted(set(ids))


def _check_affected(response: object, submitted: list[int]) -> None:
    """Semgrep must report exactly the submitted IDs as triaged, no more and no fewer."""
    if not isinstance(response, dict):
        raise ResolveError("Semgrep returned an invalid triage response")
    affected, count = response.get("triaged_issues"), response.get("num_triaged")
    if not (isinstance(affected, list) and all(isinstance(value, int) and not isinstance(value, bool) for value in affected)
            and isinstance(count, int) and not isinstance(count, bool)
            and count == len(submitted) == len(affected) and set(affected) == set(submitted)):
        raise ResolveError("Semgrep affected IDs/count differ from the requested branch scope; do not retry automatically")


def ignore(token: str, slug: str, kind: str, ids: list[int], note: str, *, repository: str, ref: str, rule: str,
           query: Callable, deployment_id=None) -> int:
    """Ignore `ids` as false positives within one repository/branch/rule; returns how many were newly ignored."""
    requested = _check_request(kind, ids, repository=repository, ref=ref, rule=rule, deployment_id=deployment_id)
    audit = TriageAudit({"status": "attempt", "deployment": slug, "product": kind, "repository": repository,
                         "ref": ref, "rule": rule, "requested_ids": requested})
    dep = {"slug": slug, "id": deployment_id}

    def in_scope() -> dict[int, dict]:
        return {row["id"]: row for row in scoped_findings(token, dep, kind, repository, ref, rule, query=query) if row["id"] in requested}

    try:
        before = in_scope()
        if set(before) != set(requested) or any(row["status"] not in TRIAGE_STATES for row in before.values()):
            raise ResolveError("Requested findings are not open/ignored in the exact repository, branch, and rule")
        pending = [identifier for identifier in requested if before[identifier]["status"] == "open"]
        if not pending:
            audit.record("already_ignored", verified_ids=requested)
            print(f"  Triage audit: {audit}")
            return 0
        body = {"issue_type": kind, "issue_ids": pending, "repos": [repository], "ref": ref, "status": "open",
                "new_triage_state": "ignored", "new_triage_reason": "false_positive", "new_note": note[:_NOTE_LIMIT],
                **({"include_historical": False} if kind == "secrets" else {})}
        audit.record("write_attempt", submitted_ids=pending)
        response = query(f"/deployments/{urllib.parse.quote(slug)}/triage", token, body=body)
        audit.record("response_received", response=response)
        _check_affected(response, pending)
        after = in_scope()
        if any(row["status"] != "ignored" for row in after.values()):
            raise ResolveError("Semgrep did not persist ignored status for every requested finding")
        if set(after) != set(requested):
            raise ResolveError("Semgrep read-back could not verify every requested finding")
        audit.record("verified", verified_ids=sorted(after))
    except ResolveError as exc:
        audit.record("unverified", error=str(exc))
        raise ResolveError(f"{exc}. Inspect triage audit {audit} before retrying") from exc
    print(f"  Triage audit: {audit}")
    return len(pending)
