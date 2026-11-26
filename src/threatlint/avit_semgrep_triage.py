"""Scoped Semgrep triage: ignore exactly the requested findings, record durable evidence, and verify the write.

`ignore` marks Semgrep findings as ignored / false_positive only inside one repository, branch, and rule:

  1. the request is checked (supported product, explicit positive IDs, exact scope);
  2. an audit record is written to ~/.threatlint/triage/<uuid>.json *before* anything changes;
  3. the findings are re-read in that scope; every requested ID must exist there and be open or already ignored;
  4. check for cross-ref effects using match fingerprints for Code and Supply Chain, and same-rule peers for Secrets;
  5. only the still-open IDs are submitted, and Semgrep's affected IDs and count must equal what was submitted;
  6. the scope is read back and every requested ID must now be ignored.

Each step updates the audit record. A scope_blocked record identifies the peer findings that
prevented a write. A write_attempt, response_received, or unverified write needs reconciliation.
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
from threatlint.avit_semgrep import TriageScopeBlocked, scoped_findings

PRODUCTS = ("sast", "sca", "secrets")
TRIAGE_STATES = ("open", "ignored")
_NOTE_LIMIT = 3000
_UNRESOLVED_WRITE_STATES = ("write_attempt", "response_received", "unverified")


def _is_id(value: object) -> bool:
    """A positive integer finding ID (bool is an int subclass, so reject it explicitly)."""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _audit_directory() -> Path:
    return Path(os.environ.get("THREATLINT_HOME") or Path.home() / ".threatlint") / "triage"


def _positive_ids(values: object) -> list[int]:
    return [value for value in values if _is_id(value)] if isinstance(values, list) else []


def _prior_write(slug: str, kind: str, requested: list[int]) -> tuple[Path, list[int]] | None:
    """Find an unverified write for the same deployment, product, and findings."""
    requested_ids = set(requested)
    for path in sorted(_audit_directory().glob("*.json")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            evidence = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(evidence, dict) or evidence.get("status") not in _UNRESOLVED_WRITE_STATES:
            continue
        if evidence.get("deployment") != slug or evidence.get("product") != kind:
            continue
        submitted = _positive_ids(evidence.get("submitted_ids"))
        if not submitted:
            continue
        response = evidence.get("response")
        affected = _positive_ids(response.get("triaged_issues")) if isinstance(response, dict) else []
        if not requested_ids.isdisjoint(submitted) or not requested_ids.isdisjoint(affected):
            return path, affected
    return None


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
        directory = directory or _audit_directory()
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
        raise ResolveError("Semgrep returned an invalid triage response. Do not retry automatically")
    affected, count = response.get("triaged_issues"), response.get("num_triaged")
    if not (isinstance(affected, list) and all(_is_id(value) for value in affected)
            and isinstance(count, int) and not isinstance(count, bool)
            and count == len(submitted) == len(affected) and set(affected) == set(submitted)):
        raise ResolveError(f"Semgrep affected IDs/count differ from the requested branch scope. "
                           f"Semgrep reported finding IDs {_positive_ids(affected)}. Do not retry automatically")


def _match_fingerprint(row: dict) -> str:
    fingerprint = row.get("match_based_id")
    if not isinstance(fingerprint, str) or not fingerprint.strip():
        raise ResolveError("Semgrep omitted a match fingerprint needed to verify triage scope")
    return fingerprint


def _peer(row: dict) -> dict:
    return {key: row[key] for key in ("id", "ref", "status")}


def _fingerprint_peers(before: dict[int, dict], pending: list[int], rows: Iterable[dict], ref: str) -> list[dict]:
    """Find other records that Semgrep could triage with the requested fingerprints."""
    expected = {identifier: _match_fingerprint(before[identifier]) for identifier in pending}
    fingerprints = set(expected.values())
    confirmed = set()
    peers = []
    for row in rows:
        fingerprint = _match_fingerprint(row)
        identifier = row["id"]
        if identifier in expected:
            if row["ref"] != ref or row["status"] != "open" or fingerprint != expected[identifier]:
                raise ResolveError("Semgrep finding identity or state changed during triage preflight")
            confirmed.add(identifier)
        elif fingerprint in fingerprints:
            peers.append(_peer(row))
    if confirmed != set(expected):
        raise ResolveError("Semgrep did not return every requested finding in the all-ref triage preflight")
    return peers


def ignore(token: str, slug: str, kind: str, ids: list[int], note: str, *, repository: str, ref: str, rule: str,
           query: Callable, deployment_id=None) -> int:
    """Ignore `ids` as false positives within one repository/branch/rule; returns how many were newly ignored."""
    requested = _check_request(kind, ids, repository=repository, ref=ref, rule=rule, deployment_id=deployment_id)
    prior = _prior_write(slug, kind, requested)
    if prior:
        audit_path, affected = prior
        reported = f" Semgrep reported finding IDs {affected}." if affected else ""
        raise ResolveError(f"An earlier Semgrep triage write for these findings is still unverified.{reported} "
                           f"Inspect triage audit {audit_path}. No Semgrep triage write was sent")
    audit = TriageAudit({"status": "attempt", "deployment": slug, "product": kind, "repository": repository,
                         "ref": ref, "rule": rule, "requested_ids": requested})
    dep = {"slug": slug, "id": deployment_id}

    def findings(branch: str | None) -> Iterable[dict]:
        return scoped_findings(token, dep, kind, repository, branch, rule, query=query)

    try:
        before = {}
        peers = []
        for row in findings(None if kind == "secrets" else ref):
            if row["ref"] != ref:
                peers.append(_peer(row))
            elif row["id"] in requested:
                before[row["id"]] = row
        if set(before) != set(requested) or any(row["status"] not in TRIAGE_STATES for row in before.values()):
            raise ResolveError("Requested findings are not open/ignored in the exact repository, branch, and rule")
        pending = [identifier for identifier in requested if before[identifier]["status"] == "open"]
        if not pending:
            audit.record("already_ignored", verified_ids=requested)
            print(f"  Triage audit: {audit}")
            return 0
        if kind == "secrets":
            scope_reason = "Semgrep found Secrets findings under the same rule on another ref and does not expose their match fingerprints"
        else:
            peers = _fingerprint_peers(before, pending, findings(None), ref)
            scope_reason = "Semgrep triage could include additional findings with the same fingerprint"
        if peers:
            audit.record("scope_blocked", error=scope_reason, peers=peers)
            raise TriageScopeBlocked(f"Semgrep triage blocked: {scope_reason} "
                                     f"({len(peers)} outside the requested write). No Semgrep triage write was sent. "
                                     f"Review the peer finding IDs and refs in triage audit {audit}")
        body = {"issue_type": kind, "issue_ids": pending, "repos": [repository], "ref": ref, "status": "open",
                "new_triage_state": "ignored", "new_triage_reason": "false_positive", "new_note": note[:_NOTE_LIMIT],
                **({"include_historical": False} if kind == "secrets" else {})}
        audit.record("write_attempt", submitted_ids=pending)
        response = query(f"/deployments/{urllib.parse.quote(slug)}/triage", token, body=body)
        audit.record("response_received", response=response)
        _check_affected(response, pending)
        after = {row["id"]: row for row in findings(ref) if row["id"] in requested}
        if any(row["status"] != "ignored" for row in after.values()):
            raise ResolveError("Semgrep did not persist ignored status for every requested finding")
        if set(after) != set(requested):
            raise ResolveError("Semgrep read-back could not verify every requested finding")
        audit.record("verified", verified_ids=sorted(after))
    except TriageScopeBlocked:
        raise
    except ResolveError as exc:
        audit.record("unverified", error=str(exc))
        write_status = " No Semgrep triage write was sent." if "submitted_ids" not in audit.evidence else ""
        raise ResolveError(f"{exc}.{write_status} Inspect triage audit {audit} before retrying") from exc
    print(f"  Triage audit: {audit}")
    return len(pending)
