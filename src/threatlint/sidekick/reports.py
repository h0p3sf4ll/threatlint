"""vReports, branch reports, imports, trends and scope accountability."""

from __future__ import annotations

import concurrent.futures
import contextlib
import datetime as dt
import re
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import Callable

from threatlint.sidekick import store
from threatlint.sidekick.clients import Ado, ServiceNow, SidekickError, _safe
from threatlint.sidekick.xlsx import read_xlsx, write_xlsx

HEADERS = ["repository", "project", "organization", "total_branches", "stale_branches", "secrets", "total_critical",
           "critical_over_60d", "total_high", "high_over_60d", "total_vulns", "total_over_60d", "repo_manager", "director", "ado_link"]
OVER_60 = "^sys_created_onRELATIVELT@dayofweek@ago@60"
MEASURES = {"totalVulns": "total_vulns", "totalCritical": "total_critical", "totalHigh": "total_high",
            "criticalOver60d": "critical_over_60d", "highOver60d": "high_over_60d", "totalOver60d": "total_over_60d",
            "openSecrets": "open_secrets", "staleBranches": "stale_branches"}
MOVER_METRICS = [("Critical Vulns", "total_critical"), ("Critical Over 60d", "critical_over_60d"), ("High Over 60d", "high_over_60d"),
                 ("Stale Branches", "stale_branches"), ("Open Secrets", "open_secrets"), ("Total Vulns", "total_vulns")]


def ado_link(org: str, project: str, repo: str) -> str:
    from urllib.parse import quote  # noqa: PLC0415
    return f"https://dev.azure.com/{quote(org)}/{quote(project)}/_git/{quote(repo)}"


def _parse_date(value: str) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def stale_count(branches: list[dict], stale_days: int, now: dt.datetime | None = None) -> int:
    """Branches whose head commit is older than `stale_days`; a branch with no date is not stale."""
    cutoff = (now or dt.datetime.now(dt.timezone.utc)) - dt.timedelta(days=stale_days)
    return sum(1 for b in branches if (d := _parse_date(b["date"])) and d < cutoff)


def committer_email(branches: list[dict]) -> str:
    """The main/master head committer, else the most recent committer."""
    for branch in branches:
        name = branch["name"].removeprefix("refs/heads/")
        if name in ("main", "master") or name.endswith(("/main", "/master")):
            if branch["email"]:
                return branch["email"]
    dated = [b for b in branches if b["email"] and _parse_date(b["date"])]
    return max(dated, key=lambda b: _parse_date(b["date"]))["email"] if dated else ""


def ownership(snow: ServiceNow, email: str) -> dict:
    """{user, chain, repoManager, director}: walk `manager` up to 15 levels; first 'director' title wins,
    and before it the first 'manager'/'principal' title that is not 'junior'/'assoc'."""
    result = {"user": None, "chain": [], "repoManager": "", "director": "", "committerEmail": email}
    if not email:
        return result
    try:
        user = snow.user(email)
    except SidekickError:
        return result
    seen = set()
    for _level in range(16):
        if not user or user.get("sys_id") in seen:
            break
        seen.add(user.get("sys_id"))
        title = str(user.get("title") or "").lower()
        role = "self" if not result["chain"] else ""
        if result["chain"]:
            if "director" in title and not result["director"]:
                result["director"] = user.get("name", "")
                role = "Director"
            elif not result["repoManager"] and ("manager" in title or "principal" in title) and not ("junior" in title or "assoc" in title):
                result["repoManager"] = user.get("name", "")
                role = "Manager"
        result["chain"].append({"name": user.get("name", ""), "title": user.get("title", ""), "gpid": user.get("user_name", ""),
                                "email": user.get("email", ""), "role": role})
        if result["director"]:
            break
        manager = user.get("manager")
        manager_id = manager.get("value") if isinstance(manager, dict) else manager
        if not manager_id:
            break
        user = snow.user_by_id(manager_id)
    result["user"] = result["chain"][0] if result["chain"] else None
    return result


def repo_row(target: dict, ado: Ado, snow: ServiceNow, stale_days: int, progress: Callable[[str], None] = lambda _m: None) -> dict:
    repo, project, org = target["repo"], target["project"], target["organization"]
    branches = ado.branch_stats(project, repo)
    progress(f"{repo}: {len(branches)} branches")
    base = f"project_name={_safe(project, 'project')}^u_repository={_safe(repo, 'repository')}^active=true^state=1"
    queries = {"total_critical": base + "^risk_rating=1", "critical_over_60d": base + "^risk_rating=1" + OVER_60,
               "total_high": base + "^risk_rating=2", "high_over_60d": base + "^risk_rating=2" + OVER_60,
               "total_vulns": base, "total_over_60d": base + OVER_60, "open_secrets": base + "^u_security_finding_sourceLIKESecret"}
    with concurrent.futures.ThreadPoolExecutor(len(queries)) as pool:
        counts = dict(zip(queries, pool.map(snow.count, queries.values())))
    owner = ownership(snow, committer_email(branches))
    return {"repository": repo, "project": project, "organization": org, "status": "complete",
            "total_branches": len(branches), "stale_branches": stale_count(branches, stale_days), **counts,
            "repo_manager": owner["repoManager"], "director": owner["director"]}


def workbook_rows(rows: list[dict]) -> list[list]:
    return [[r["repository"], r["project"], r["organization"], r.get("total_branches"), r.get("stale_branches"), r.get("open_secrets"),
             r.get("total_critical"), r.get("critical_over_60d"), r.get("total_high"), r.get("high_over_60d"), r.get("total_vulns"),
             r.get("total_over_60d"), r.get("repo_manager") or "", r.get("director") or "", ado_link(r["organization"], r["project"], r["repository"])]
            for r in rows]


def generate(loadout: str, targets: list[dict], *, stale_days: int = 90, workers: int = 10, profile: str | None = None,
             progress: Callable[[dict], None] = lambda _e: None, cancel: threading.Event | None = None) -> dict:
    """Build a vReport for `targets`; failed repositories are retried once, then recorded as failed rows."""
    if not targets:
        raise SidekickError("The loadout has no repositories")
    cancel = cancel or threading.Event()
    snow = ServiceNow.from_config(profile)
    clients = {org: Ado(org) for org in dict.fromkeys(t["organization"] for t in targets)}
    started, done, total = time.monotonic(), [0], len(targets)
    lock = threading.Lock()
    def work(target: dict) -> dict:
        if cancel.is_set():
            raise SidekickError("Cancelled")
        for attempt in (1, 2):
            try:
                row = repo_row(target, clients[target["organization"]], snow, stale_days,
                               lambda message: progress({"type": "log", "message": message}) if attempt == 1 else None)
                break
            except SidekickError as exc:
                if attempt == 2:
                    row = {"repository": target["repo"], "project": target["project"], "organization": target["organization"],
                           "status": "failed", "error_message": str(exc)[:300], **{m: 0 for m in store.METRICS}}
        with lock:
            done[0] += 1
            progress({"type": "progress", "current": done[0], "total": total, "repository": target["repo"]})
        return row
    with concurrent.futures.ThreadPoolExecutor(max(1, min(workers, 32))) as pool:
        rows = list(pool.map(work, targets))
    if cancel.is_set():
        raise SidekickError("Cancelled")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    workbook = store.data_dir() / "reports" / f"Vulnerability Report {stamp}_{uuid.uuid4().hex[:8]}.xlsx"
    write_xlsx(str(workbook), HEADERS, workbook_rows(rows), links={14: 14}, table_name="vReport")
    run_id = store.record_run(loadout, rows, stale_days=stale_days, duration=time.monotonic() - started, workbook=str(workbook))
    failed = sum(r["status"] != "complete" for r in rows)
    store.journal("report_generated", reason=loadout or "ad hoc", subject=run_id, succeeded=len(rows) - failed, failed=failed)
    return {"runId": run_id, "workbook": str(workbook), "rows": len(rows), "failed": failed}


def branch_report(organization: str, project: str, repository: str, stale_days: int = 90) -> dict:
    branches = Ado(organization).branch_stats(project, repository)
    now = dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(days=stale_days)
    stale = sorted(({"branch": b["name"].removeprefix("refs/heads/"), "last_commit_date": b["date"], "last_committer": b["email"],
                     "days_stale": (now - d).days} for b in branches if (d := _parse_date(b["date"])) and d < cutoff),
                   key=lambda r: -r["days_stale"])
    stamp = now.strftime("%Y-%m-%d_%H-%M-%S")
    safe_repo = re.sub(r"[^\w.-]", "_", repository)
    path = store.data_dir() / "reports" / f"Branch Report {safe_repo} {stamp}_{uuid.uuid4().hex[:8]}.xlsx"
    base = ado_link(organization, project, repository)
    write_xlsx(str(path), ["branch", "last_commit_date", "last_committer", "days_stale", "ado_link"],
               [[r["branch"], r["last_commit_date"], r["last_committer"], r["days_stale"], f"{base}?version=GB{r['branch']}"] for r in stale],
               links={4: 4}, table_name="Branches")
    return {"workbook": str(path), "total": len(branches), "stale": len(stale), "rows": stale}


def _norm(header) -> str:
    return re.sub(r"^_+|_+$", "", re.sub(r"[\s-]+", "_", str(header or "").strip().lower()))


ALIASES = {"repo": "repository", "org": "organization", "secrets": "open_secrets", "open_secrets": "open_secrets",
           "manager": "repo_manager", "repo_manager": "repo_manager"}


def import_report(path: str, loadout: str, date: str = "") -> dict:
    """File an externally produced vReport under a loadout and date (one run per loadout per day)."""
    date = date or dt.date.today().isoformat()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise SidekickError("The date must be YYYY-MM-DD")
    with contextlib.closing(store.connect()) as db:
        if db.execute("SELECT 1 FROM report_runs WHERE loadout=? AND substr(created_at,1,10)=?", (loadout, date)).fetchone():
            raise SidekickError(f"{loadout} already has a report on {date}")
    table = read_xlsx(path)
    if len(table) < 2:
        raise SidekickError("The workbook has a header but no rows")
    columns = [ALIASES.get(_norm(h), _norm(h)) for h in table[0]]
    if "repository" not in columns or "project" not in columns:
        raise SidekickError("The workbook needs repository and project columns")
    default_org = store.default_organization()
    rows = []
    for raw in table[1:]:
        record = {columns[i]: raw[i] for i in range(min(len(columns), len(raw)))}
        if not record.get("repository") or not record.get("project"):
            continue
        row = {"repository": str(record["repository"]), "project": str(record["project"]),
               "organization": str(record.get("organization") or default_org), "status": "complete",
               "repo_manager": record.get("repo_manager") or "", "director": record.get("director") or ""}
        for metric in store.METRICS:
            value = record.get(metric)
            try:
                row[metric] = int(float(value)) if value not in (None, "") else None
            except (TypeError, ValueError):
                row[metric] = None
        rows.append(row)
    if not rows:
        raise SidekickError("No rows with a repository and project")
    copy = store.data_dir() / "reports" / f"{Path(path).stem}_imported_{uuid.uuid4().hex[:8]}.xlsx"
    shutil.copyfile(path, copy)
    run_id = store.record_run(loadout, rows, stale_days=90, duration=0, workbook=str(copy), created_at=f"{date}T12:00:00Z", imported=True)
    store.journal("report_imported", reason=loadout, subject=run_id, succeeded=len(rows))
    return {"runId": run_id, "rows": len(rows), "workbook": str(copy)}


# ── History and trends ────────────────────────────────────────────────────────

def runs(loadout: str = "", limit: int = 50, offset: int = 0) -> list[dict]:
    with contextlib.closing(store.connect()) as db:
        query = "SELECT r.*, COUNT(x.repository) rows, " + ", ".join(f"SUM(x.{m}) {m}" for m in store.METRICS) + \
                " FROM report_runs r LEFT JOIN report_rows x ON x.run_id=r.id" + (" WHERE r.loadout=?" if loadout else "") + \
                " GROUP BY r.id ORDER BY r.created_at DESC LIMIT ? OFFSET ?"
        return [dict(row) for row in db.execute(query, ((loadout,) if loadout else ()) + (limit, offset))]


def run_rows(run_id: str, project: str = "", repository: str = "", limit: int = 500, offset: int = 0) -> list[dict]:
    with contextlib.closing(store.connect()) as db:
        clauses, params = ["run_id=?"], [run_id]
        if project:
            clauses.append("project=?")
            params.append(project)
        if repository:
            clauses.append("repository LIKE ?")
            params.append(f"%{repository}%")
        return [dict(row) for row in db.execute(f"SELECT * FROM report_rows WHERE {' AND '.join(clauses)} ORDER BY project, repository LIMIT ? OFFSET ?",
                                                (*params, limit, offset))]


def delete_run(run_id: str) -> bool:
    with contextlib.closing(store.connect()) as db, db:
        row = db.execute("SELECT workbook FROM report_runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            return False
        db.execute("DELETE FROM report_runs WHERE id=?", (run_id,))
    with contextlib.suppress(OSError):
        Path(row["workbook"]).unlink()
    return True


KEY = "x.organization=y.organization AND x.project=y.project AND x.repository=y.repository"


def movers(baseline: str, current: str, limit: int = 15) -> list[dict]:
    with contextlib.closing(store.connect()) as db:
        pairs = db.execute(f"SELECT x.*, " + ", ".join(f"y.{m} AS new_{m}" for _l, m in MOVER_METRICS) +
                           f" FROM report_rows x JOIN report_rows y ON {KEY} WHERE x.run_id=? AND y.run_id=? "
                           "AND x.status='complete' AND y.status='complete'", (baseline, current)).fetchall()
    out = []
    for row in pairs:
        for label, metric in MOVER_METRICS:
            before, after = row[metric] or 0, row[f"new_{metric}"] or 0
            if before != after:
                out.append({"repository": row["repository"], "project": row["project"], "organization": row["organization"],
                            "metric": label, "before": before, "after": after, "delta": after - before})
    return sorted(out, key=lambda m: (-abs(m["delta"]), m["repository"].lower()))[:limit]


def scope_delta(baseline: str, current: str) -> dict:
    """How much of a change came from repositories joining or leaving the loadout, and both runs over shared repos."""
    sums = ", ".join(f"COALESCE(SUM(x.{m}),0) {m}" for m in store.METRICS)
    with contextlib.closing(store.connect()) as db:
        def side(run: str, other: str, exists: bool) -> tuple[list[dict], dict]:
            where = f"x.run_id=? AND {'' if exists else 'NOT '}EXISTS (SELECT 1 FROM report_rows y WHERE y.run_id=? AND {KEY})"
            names = [dict(r) for r in db.execute(f"SELECT x.organization, x.project, x.repository FROM report_rows x WHERE {where} LIMIT 100", (run, other))]
            total = dict(db.execute(f"SELECT COUNT(*) repositories, {sums} FROM report_rows x WHERE {where}", (run, other)).fetchone())
            return names, total
        added, added_total = side(current, baseline, False)
        removed, removed_total = side(baseline, current, False)
        _shared, baseline_common = side(baseline, current, True)
        _shared, current_common = side(current, baseline, True)
    return {"added": added, "removed": removed, "addedTotals": added_total, "removedTotals": removed_total,
            "baselineCommon": baseline_common, "currentCommon": current_common,
            "membershipChanged": bool(added_total["repositories"] or removed_total["repositories"])}


def trends(loadout: str, months: int = 12) -> dict:
    """Daily series (last run per day), headline, movers and scope attribution for one loadout."""
    history = list(reversed(runs(loadout, limit=10_000)))
    if not history:
        raise SidekickError(f"{loadout} has no reports yet")
    by_day = {}
    for run in history:
        by_day[run["created_at"][:10]] = run
    series = list(by_day.values())
    if months:
        start = (dt.date.today().replace(day=1) - dt.timedelta(days=31 * (months - 1))).isoformat()
        window = [run for run in series if run["created_at"][:10] >= start] or series[-1:]
    else:
        window = series
    baseline, current = window[0], window[-1]
    scope = scope_delta(baseline["id"], current["id"])
    before = scope["baselineCommon"]["total_vulns"] if scope["membershipChanged"] else (baseline["total_vulns"] or 0)
    after = scope["currentCommon"]["total_vulns"] if scope["membershipChanged"] else (current["total_vulns"] or 0)
    delta = after - before
    return {"loadout": loadout, "baseline": baseline, "current": current, "likeForLike": scope["membershipChanged"],
            "headline": {"before": before, "after": after, "delta": delta, "percent": round(delta / before * 100) if before else None,
                         "posture": "Improving" if delta < 0 else "Worsening" if delta > 0 else "Steady"},
            "attribution": {"raw": (current["total_vulns"] or 0) - (baseline["total_vulns"] or 0),
                            "fromScope": scope["addedTotals"]["total_vulns"] - scope["removedTotals"]["total_vulns"],
                            "fromExisting": scope["currentCommon"]["total_vulns"] - scope["baselineCommon"]["total_vulns"]},
            "series": [{"date": run["created_at"][:10], "repositories": run["rows"], **{k: run[v] or 0 for k, v in MEASURES.items()}} for run in window],
            "movers": movers(baseline["id"], current["id"]), "scope": scope}
