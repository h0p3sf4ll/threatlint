"""Sidekick persistence: everything lives under ~/.threatlint/sidekick (THREATLINT_HOME relocates it).

  loadouts.json            {name: [{repo, project, organization}]}
  powered_loadouts.json    {id: {refreshedAt, entries, unresolved, considered}}
  avit_queries.json        {name: [conditions]}
  sidekick.sqlite3         report runs and rows, the action journal, the ownership cache
  reports/                 generated and imported .xlsx workbooks

JSON files are written atomically (temp file + os.replace) under a lock file, so the CLI and the Workbench
can run at the same time on macOS, Linux and Windows.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import os
import re
import sqlite3
import time
import uuid
from pathlib import Path

from threatlint import org_config

REPO_NAME = re.compile(r"^[A-Za-z0-9._\- ]+$")


def data_dir() -> Path:
    path = Path(os.environ.get("THREATLINT_HOME") or Path.home() / ".threatlint") / "sidekick"
    (path / "reports").mkdir(parents=True, exist_ok=True)
    return path


def organizations() -> list[str]:
    """Azure DevOps organizations Sidekick spans; the first is the default."""
    return org_config.values("adoOrganizations")


def default_organization() -> str:
    orgs = organizations()
    return orgs[0] if orgs else ""


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── JSON documents ────────────────────────────────────────────────────────────

@contextlib.contextmanager
def _locked(path: Path):
    """A cross-platform advisory lock: create-exclusive a .lock file, retrying briefly; stale locks expire."""
    lock = path.with_suffix(path.suffix + ".lock")
    deadline = time.monotonic() + 10
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            break
        except FileExistsError:
            try:
                if time.time() - lock.stat().st_mtime > 30:
                    lock.unlink(missing_ok=True)
                    continue
            except OSError:
                pass
            if time.monotonic() > deadline:
                raise TimeoutError(f"{path.name} is locked by another Threatlint process")
            time.sleep(0.05)
    try:
        yield
    finally:
        lock.unlink(missing_ok=True)


def read_json(name: str) -> dict:
    try:
        value = json.loads((data_dir() / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def write_json(name: str, value: dict) -> None:
    path = data_dir() / name
    with _locked(path):
        temp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        temp.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temp, path)


# ── Loadouts ──────────────────────────────────────────────────────────────────

def _entry(raw, default_org: str) -> dict | None:
    if isinstance(raw, dict):
        repo, project, org = raw.get("repo") or raw.get("repository"), raw.get("project"), raw.get("organization") or raw.get("org")
    elif isinstance(raw, (list, tuple)) and len(raw) >= 2:
        repo, project, org = raw[0], raw[1], raw[2] if len(raw) > 2 else ""
    else:
        return None
    if not repo or not project:
        return None
    return {"repo": str(repo).strip(), "project": str(project).strip(), "organization": str(org or default_org).strip()}


def _key(entry: dict) -> tuple[str, str, str]:
    return entry["repo"].lower(), entry["project"].lower(), entry["organization"].lower()


def loadouts() -> dict[str, list[dict]]:
    default_org = default_organization()
    out = {}
    for name, entries in read_json("loadouts.json").items():
        parsed = [_entry(raw, default_org) for raw in entries if _entry(raw, default_org)] if isinstance(entries, list) else []
        out[name] = parsed
    return out


def validate_loadout_name(name: str, existing: dict, current: str = "") -> str:
    name = (name or "").strip()
    if len(name) < 3:
        raise ValueError("A loadout name needs at least 3 characters")
    if name.lower() in POWERED and name.lower() != current.lower():
        raise ValueError(f"{name} is reserved for a powered loadout")
    if any(other.lower() == name.lower() and other != current for other in existing):
        raise ValueError(f"A loadout named {name} already exists")
    return name


def save_loadout(name: str, entries: list, previous: str = "") -> dict:
    """Create or replace a loadout (renaming from `previous`); returns {added, removed} for the journal."""
    current = loadouts()
    name = validate_loadout_name(name, current, previous or name if (previous or name) in current else "")
    default_org = default_organization()
    clean, seen = [], set()
    for raw in entries:
        entry = _entry(raw, default_org)
        if not entry or not REPO_NAME.fullmatch(entry["repo"]) or _key(entry) in seen:
            continue
        seen.add(_key(entry))
        clean.append(entry)
    before = {_key(e) for e in current.get(previous or name, [])}
    if previous and previous != name:
        current.pop(previous, None)
    current[name] = clean
    write_json("loadouts.json", current)
    return {"added": len(seen - before), "removed": len(before - seen)}


def delete_loadout(name: str) -> bool:
    current = loadouts()
    if name not in current:
        return False
    del current[name]
    write_json("loadouts.json", current)
    return True


def parse_loadout_text(text: str, organization: str = "") -> tuple[list[dict], list[str]]:
    """`repo, project[, org]` per line; `# org: X` sets the organization for the lines below it."""
    org = organization or default_organization()
    entries, warnings, seen = [], [], set()
    for number, line in enumerate(str(text or "").splitlines(), start=1):
        line = line.strip()
        directive = re.match(r"^#\s*org:\s*(\S+)", line, re.I)
        if directive:
            org = directive.group(1)
            continue
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 2 or not parts[0] or not parts[1]:
            warnings.append(f"Line {number}: expected `repo, project[, org]`")
            continue
        if not REPO_NAME.fullmatch(parts[0]):
            warnings.append(f"Line {number}: {parts[0]} is not a valid repository name")
            continue
        entry = {"repo": parts[0], "project": parts[1], "organization": parts[2] if len(parts) > 2 and parts[2] else org}
        if _key(entry) in seen:
            warnings.append(f"Line {number}: duplicate of an earlier line, skipped")
            continue
        seen.add(_key(entry))
        entries.append(entry)
    return entries, warnings


# Powered loadouts: top repositories ranked by open ServiceNow findings, refreshed on demand.
POWERED = {
    "secrets-top-20": {"label": "Top 20 by open secrets", "query": "active=true^state=1^u_security_finding_source=Secret"},
    "vulnerabilities-top-20": {"label": "Top 20 by open critical and high", "query": "active=true^state=1^risk_ratingIN1,2"},
}


# ── sqlite: report history, action journal, ownership cache ────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS report_runs (
  id TEXT PRIMARY KEY, created_at TEXT NOT NULL, loadout TEXT, organization TEXT, stale_days INTEGER,
  duration_seconds REAL, workbook TEXT, imported INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS report_rows (
  run_id TEXT NOT NULL REFERENCES report_runs(id) ON DELETE CASCADE,
  repository TEXT NOT NULL, project TEXT NOT NULL, organization TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'complete', error_message TEXT,
  total_branches INTEGER, stale_branches INTEGER, open_secrets INTEGER, total_critical INTEGER,
  critical_over_60d INTEGER, total_high INTEGER, high_over_60d INTEGER, total_vulns INTEGER,
  total_over_60d INTEGER, repo_manager TEXT, director TEXT,
  PRIMARY KEY (run_id, organization, project, repository));
CREATE INDEX IF NOT EXISTS report_runs_loadout ON report_runs(loadout, created_at);
CREATE TABLE IF NOT EXISTS action_runs (
  id TEXT PRIMARY KEY, created_at TEXT NOT NULL, kind TEXT NOT NULL, reason TEXT, subject TEXT,
  succeeded INTEGER DEFAULT 0, failed INTEGER DEFAULT 0, cancelled INTEGER DEFAULT 0, reverses TEXT, reversed_by TEXT);
CREATE TABLE IF NOT EXISTS action_targets (
  run_id TEXT NOT NULL REFERENCES action_runs(id) ON DELETE CASCADE, sys_id TEXT NOT NULL,
  prior_state TEXT DEFAULT '', prior_active INTEGER DEFAULT 1, error TEXT, PRIMARY KEY (run_id, sys_id));
CREATE INDEX IF NOT EXISTS action_runs_created ON action_runs(created_at DESC);
CREATE INDEX IF NOT EXISTS action_targets_sys ON action_targets(sys_id);
CREATE TABLE IF NOT EXISTS ownership_cache (key TEXT PRIMARY KEY, result TEXT NOT NULL, expires_at TEXT NOT NULL);
"""
ACTION_KINDS = ("report_generated", "report_imported", "summary_exported", "loadout_changed", "powered_loadout_refreshed",
                "avit_close", "avit_reopen", "bulk_triage")
METRICS = ("total_branches", "stale_branches", "open_secrets", "total_critical", "critical_over_60d", "total_high",
           "high_over_60d", "total_vulns", "total_over_60d")


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(data_dir() / "sidekick.sqlite3", timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA journal_mode = WAL")
    db.executescript(SCHEMA)
    return db


def record_run(loadout: str, rows: list[dict], *, stale_days: int, duration: float, workbook: str,
               created_at: str = "", imported: bool = False) -> str:
    run_id = uuid.uuid4().hex
    orgs = " + ".join(dict.fromkeys(row.get("organization", "") for row in rows if row.get("organization")))
    with contextlib.closing(connect()) as db, db:
        db.execute("INSERT INTO report_runs VALUES (?,?,?,?,?,?,?,?)",
                   (run_id, created_at or now_iso(), loadout, orgs, stale_days, duration, workbook, int(imported)))
        for row in rows:
            db.execute(f"INSERT OR REPLACE INTO report_rows VALUES (?,?,?,?,?,?,{','.join('?' * len(METRICS))},?,?)",
                       (run_id, row["repository"], row["project"], row.get("organization", ""),
                        "complete" if row.get("status", "complete") in ("complete", "completed") else row["status"],
                        row.get("error_message"), *[row.get(metric) for metric in METRICS], row.get("repo_manager"), row.get("director")))
    return run_id


def journal(kind: str, *, reason: str = "", subject: str = "", succeeded: int = 0, failed: int = 0, cancelled: bool = False,
            targets: list[dict] | None = None, reverses: str = "") -> str:
    """Record an action. `targets` are {sys_id, prior_state, prior_active, error}; a reversal marks the original."""
    if kind not in ACTION_KINDS:
        raise ValueError(f"Unknown action kind {kind}")
    run_id = uuid.uuid4().hex
    with contextlib.closing(connect()) as db, db:
        db.execute("INSERT INTO action_runs VALUES (?,?,?,?,?,?,?,?,?,NULL)",
                   (run_id, now_iso(), kind, reason, subject, succeeded, failed, int(cancelled), reverses or None))
        for target in targets or []:
            db.execute("INSERT OR REPLACE INTO action_targets VALUES (?,?,?,?,?)",
                       (run_id, target["sys_id"], str(target.get("prior_state", "")), int(bool(target.get("prior_active", True))), target.get("error")))
        if reverses:
            marked = db.execute("UPDATE action_runs SET reversed_by=? WHERE id=? AND reversed_by IS NULL", (run_id, reverses)).rowcount
            if not marked:
                raise ValueError(f"Action {reverses} was already reversed")
    return run_id


def purge_actions(days: int, keep_reversible: bool = True) -> int:
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    guard = " AND NOT (kind='avit_close' AND reversed_by IS NULL AND succeeded>0)" if keep_reversible else ""
    with contextlib.closing(connect()) as db:
        with db:
            removed = db.execute(f"DELETE FROM action_runs WHERE created_at < ?{guard}", (cutoff,)).rowcount
        if removed:
            db.execute("VACUUM")
    return removed
