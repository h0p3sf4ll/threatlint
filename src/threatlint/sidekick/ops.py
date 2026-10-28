"""Sidekick operations: ownership, Find Projects, powered loadouts, AVIT bulk closure/reversal, bulk triage."""

from __future__ import annotations

import concurrent.futures
import contextlib
import datetime as dt
import json
import threading
from typing import Callable

from threatlint import semgrep_platform as sp
from threatlint.sidekick import store
from threatlint.sidekick.clients import Ado, ServiceNow, SidekickError, build_query
from threatlint.sidekick.reports import committer_email, ownership

CACHE_DAYS = 14
BATCH = 250


# ── Ownership Hub ─────────────────────────────────────────────────────────────

def owner_by_email(email: str, profile: str | None = None, refresh: bool = False) -> dict:
    key = f"email:{email.strip().lower()}"
    now = store.now_iso()
    with contextlib.closing(store.connect()) as db:
        if not refresh:
            row = db.execute("SELECT result FROM ownership_cache WHERE key=? AND expires_at>?", (key, now)).fetchone()
            if row:
                return {**json.loads(row["result"]), "cached": True}
    result = ownership(ServiceNow.from_config(profile), email.strip())
    expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=CACHE_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with contextlib.closing(store.connect()) as db, db:
        db.execute("INSERT OR REPLACE INTO ownership_cache VALUES (?,?,?)", (key, json.dumps(result), expires))
    return {**result, "cached": False}


def owner_by_repo(organization: str, project: str, repository: str, profile: str | None = None) -> dict:
    email = committer_email(Ado(organization).branch_stats(project, repository))
    if not email:
        raise SidekickError(f"{repository} has no committer email on any branch")
    return owner_by_email(email, profile)


def clear_ownership_cache() -> int:
    with contextlib.closing(store.connect()) as db, db:
        return db.execute("DELETE FROM ownership_cache").rowcount


# ── Find Projects ─────────────────────────────────────────────────────────────

def find_projects(names: list[str], organizations: list[str] | None = None, progress: Callable[[dict], None] = lambda _e: None) -> dict:
    """Locate repositories by name across the configured organizations; first organization wins on a tie."""
    orgs = organizations or store.organizations()
    if not orgs:
        raise SidekickError("No Azure DevOps organizations are configured (set adoOrganizations in ~/.threatlint/org.json)")
    index, skipped = {}, []
    for number, org in enumerate(orgs, start=1):
        try:
            for repo in Ado(org).repositories():
                index.setdefault(repo["name"].lower(), {"project": repo["project"], "organization": org, "repo": repo["name"]})
        except SidekickError as exc:
            skipped.append({"organization": org, "error": str(exc)[:200]})
        progress({"type": "progress", "current": number, "total": len(orgs)})
    if len(skipped) == len(orgs):
        raise SidekickError("No Azure DevOps organization could be read: " + "; ".join(f"{s['organization']}: {s['error']}" for s in skipped))
    results = []
    for name in dict.fromkeys(n.strip() for n in names if n.strip()):
        hit = index.get(name.lower())
        results.append({"repo": hit["repo"], "project": hit["project"], "organization": hit["organization"], "status": "found"} if hit
                       else {"repo": name, "project": None, "organization": None, "status": "missing"})
    return {"results": results, "skipped": skipped}


def csv_field(value: str) -> str:
    """CSV cell safe from spreadsheet formula execution."""
    value = str(value)
    if value[:1] in ("=", "+", "-", "@", "\t"):
        value = "'" + value
    return '"' + value.replace('"', '""') + '"' if any(c in value for c in ',"\n') else value


# ── Powered loadouts ──────────────────────────────────────────────────────────

def refresh_powered(powered_id: str, profile: str | None = None, limit: int = 20) -> dict:
    definition = store.POWERED.get(powered_id)
    if not definition:
        raise SidekickError(f"Unknown powered loadout {powered_id}")
    ranking = ServiceNow.from_config(profile).counts_by_repository(definition["query"])
    totals: dict[str, dict] = {}
    for row in ranking:
        entry = totals.setdefault(row["repo"].lower(), {"repo": row["repo"], "count": 0, "projects": []})
        entry["count"] += row["count"]
        entry["projects"].append(row["project"])
    ordered = sorted(totals.values(), key=lambda e: (-e["count"], e["repo"].lower()))
    located: dict[str, list[dict]] = {}
    for org in store.organizations():
        with contextlib.suppress(SidekickError):
            for repo in Ado(org).repositories():
                located.setdefault(repo["name"].lower(), []).append({"project": repo["project"], "organization": org})
    entries, unresolved, considered = [], [], 0
    for item in ordered:
        if len(entries) >= limit:
            break
        considered += 1
        places = located.get(item["repo"].lower(), [])
        if len(places) > 1:
            places = [p for p in places if p["project"] in item["projects"]] or places
        if len(places) == 1:
            entries.append({"repo": item["repo"], **places[0], "count": item["count"]})
        else:
            unresolved.append({"repo": item["repo"], "count": item["count"],
                               "reason": "not found in Azure DevOps" if not places else f"ambiguous: {len(places)} matches"})
    doc = store.read_json("powered_loadouts.json")
    doc[powered_id] = {"refreshedAt": store.now_iso(), "entries": entries, "unresolved": unresolved, "considered": considered}
    store.write_json("powered_loadouts.json", doc)
    store.journal("powered_loadout_refreshed", reason=definition["label"], subject=powered_id, succeeded=len(entries), failed=len(unresolved))
    return doc[powered_id]


# ── AVIT bulk closure and reversal ────────────────────────────────────────────

def _patch_all(snow: ServiceNow, sys_ids: list[str], body: dict, request_id: str, cancel: threading.Event,
               progress: Callable[[dict], None]) -> dict[str, str | None]:
    chunks = [sys_ids[i:i + BATCH] for i in range(0, len(sys_ids), BATCH)]
    outcome: dict[str, str | None] = {}
    done = [0]
    lock = threading.Lock()
    def run(chunk: list[str]) -> dict[str, str | None]:
        if cancel.is_set():
            return {}
        try:
            result = snow.batch_patch(chunk, body, request_id)
        except SidekickError as exc:
            result = {sys_id: str(exc)[:200] for sys_id in chunk}
        with lock:
            done[0] += len(chunk)
            progress({"type": "progress", "phase": "closing", "current": done[0], "total": len(sys_ids)})
        return result
    with concurrent.futures.ThreadPoolExecutor(10) as pool:
        for result in pool.map(run, chunks):
            outcome.update(result)
    return outcome


def collect(snow: ServiceNow, query: str, progress: Callable[[dict], None] = lambda _e: None) -> list[dict]:
    """Every matching record's {sys_id, state, active}, enumerated before anything changes."""
    _rows, total = snow.search(query, limit=1, fields="sys_id")
    page, out = 2000, []
    if total is not None:
        offsets = list(range(0, total, page))
        def fetch(offset: int) -> list[dict]:
            return snow.search(query, limit=page, offset=offset, fields="sys_id,state,active")[0]
        with concurrent.futures.ThreadPoolExecutor(10) as pool:
            for number, chunk in enumerate(pool.map(fetch, offsets), start=1):
                out += chunk
                progress({"type": "progress", "phase": "collecting", "current": min(number * page, total), "total": total})
    else:
        offset = 0
        while True:
            chunk = snow.search(query, limit=page, offset=offset, fields="sys_id,state,active")[0]
            out += chunk
            if len(chunk) < page:
                break
            offset += page
    return out


def close_avits(*, reason: str, conditions: list[dict] | None = None, records: list[dict] | None = None, profile: str | None = None,
                progress: Callable[[dict], None] = lambda _e: None, cancel: threading.Event | None = None) -> dict:
    """Close the given records, or every record matching `conditions`, and journal each one (reversible)."""
    reason = (reason or "").strip()
    if not reason:
        raise SidekickError("A closure reason is required")
    cancel = cancel or threading.Event()
    snow = ServiceNow.from_config(profile)
    query = build_query(conditions) if conditions else ""
    priors = records if records is not None else collect(snow, query, progress)
    if not priors:
        raise SidekickError("No AVITs match these conditions")
    ids = [str(r.get("sys_id") or r.get("sysId")) for r in priors]
    outcome = _patch_all(snow, ids, {"state": 3, "active": False, "work_notes": reason, "close_notes": reason}, "threatlint_close_avits", cancel, progress)
    targets = [{"sys_id": str(r.get("sys_id") or r.get("sysId")), "prior_state": r.get("state", ""),
                "prior_active": str(r.get("active", "true")).lower() == "true", "error": outcome.get(str(r.get("sys_id") or r.get("sysId")), "cancelled")}
               for r in priors]
    succeeded = sum(t["error"] is None for t in targets)
    run_id = store.journal("avit_close", reason=reason, subject=json.dumps(conditions) if conditions else "", succeeded=succeeded,
                           failed=len(targets) - succeeded, cancelled=cancel.is_set(), targets=targets)
    return {"actionId": run_id, "closed": succeeded, "failed": len(targets) - succeeded, "cancelled": cancel.is_set()}


def reverse_closure(action_id: str, reason: str, profile: str | None = None, progress: Callable[[dict], None] = lambda _e: None) -> dict:
    """Reopen every record an earlier closure closed. Partial results are journalled even if a batch fails."""
    reason = (reason or "").strip()
    if not reason:
        raise SidekickError("A reason is required to reverse a closure")
    with contextlib.closing(store.connect()) as db:
        run = db.execute("SELECT * FROM action_runs WHERE id=?", (action_id,)).fetchone()
        if not run or run["kind"] != "avit_close" or run["reversed_by"] or not run["succeeded"]:
            raise SidekickError("That action is not a reversible closure")
        ids = [r["sys_id"] for r in db.execute("SELECT sys_id FROM action_targets WHERE run_id=? AND error IS NULL", (action_id,))]
    snow = ServiceNow.from_config(profile)
    outcome: dict[str, str | None] = {}
    try:
        outcome = _patch_all(snow, ids, {"state": 1, "active": True, "work_notes": reason}, "threatlint_reopen_avits", threading.Event(), progress)
    finally:
        targets = [{"sys_id": sys_id, "prior_state": "3", "prior_active": False, "error": outcome.get(sys_id, "not attempted")} for sys_id in ids]
        succeeded = sum(t["error"] is None for t in targets)
        run_id = store.journal("avit_reopen", reason=reason, subject=action_id, succeeded=succeeded, failed=len(ids) - succeeded,
                               targets=targets, reverses=action_id)
    return {"actionId": run_id, "reopened": succeeded, "failed": len(ids) - succeeded}


# ── Semgrep bulk triage ───────────────────────────────────────────────────────

def bulk_triage(*, project: str, mode: str, rule: str = "", secret_type: str = "", note: str, workers: int = 4,
                profile: str | None = None, progress: Callable[[dict], None] = lambda _e: None, cancel: threading.Event | None = None) -> dict:
    """Ignore every open finding of one rule (or secret type) in a project as a false positive.

    Each call triages one seed finding, which Semgrep expands to its whole fingerprint cluster; workers repeat
    until Semgrep reports nothing left. Three consecutive failures in one worker stop the run."""
    project, note, mode = project.strip(), note.strip(), mode.strip().lower()
    if mode not in ("sast", "secrets") or not project or not note or not (rule.strip() if mode == "sast" else secret_type.strip()):
        raise SidekickError("Project, note, and a rule name (SAST) or secret type (Secrets) are required")
    token = sp.resolve_token(profile)[0]
    slug = sp.deployment(token)["slug"]
    body = {"repos": [project], "status": "open", "new_triage_state": "ignored", "new_triage_reason": "false_positive",
            "new_note": note, "limit": 1, "issue_type": mode, **({"rules": [rule.strip()]} if mode == "sast" else {"secret_types": [secret_type.strip()]})}
    cancel = cancel or threading.Event()
    exhausted = threading.Event()
    lock = threading.Lock()
    totals = {"triaged": 0, "seeds": 0}
    def worker() -> None:
        failures = 0
        while not exhausted.is_set() and not cancel.is_set():
            try:
                data = sp.call(f"/api/v1/deployments/{slug}/triage", token, method="POST", body=body)
            except sp.SemgrepError as exc:
                if "No issues were found" in str(exc) or "HTTP 400" in str(exc):
                    exhausted.set()
                    return
                failures += 1
                if failures >= 3:
                    cancel.set()
                    return
                continue
            failures = 0
            count = next((len(data[k]) for k in ("triaged_issues", "issue_ids", "triaged_issue_ids") if data.get(k)), int(data.get("num_triaged", 0) or 0))
            if not count:
                exhausted.set()
                return
            with lock:
                totals["triaged"] += count
                totals["seeds"] += 1
                progress({"type": "progress", **totals})
    with concurrent.futures.ThreadPoolExecutor(max(1, min(workers, 16))) as pool:
        for _ in pool.map(lambda _i: worker(), range(max(1, min(workers, 16)))):
            pass
    store.journal("bulk_triage", reason=note, subject=project, succeeded=totals["triaged"], cancelled=cancel.is_set() and not exhausted.is_set())
    return {**totals, "complete": exhausted.is_set()}
