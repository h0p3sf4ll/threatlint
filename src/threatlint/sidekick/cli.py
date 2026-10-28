"""`threatlint sidekick …`: every command prints one JSON document on stdout (progress as JSON lines on
stderr), so the Workbench can drive it the same way it drives `threatlint avit`."""

from __future__ import annotations

import contextlib
import json
import signal
import sys
import threading

from threatlint import servicenow as sn
from threatlint.sidekick import ops, reports, store
from threatlint.sidekick.clients import SidekickError


def _progress(event: dict) -> None:
    print(json.dumps(event), file=sys.stderr, flush=True)


def _out(value) -> int:
    print(json.dumps(value, default=str))
    return 0


def add_sidekick_parser(sub) -> None:
    p = sub.add_parser("sidekick", help="Portfolio reporting and bulk operations (vReports, loadouts, trends, ownership, AVIT closure, bulk triage)")
    a = p.add_subparsers(dest="sk_command", required=True)
    for name, text in (("loadouts", "List loadouts"), ("orgs", "List configured Azure DevOps organizations")):
        a.add_parser(name, help=text)
    save = a.add_parser("loadout-save", help="Create or replace a loadout from `repo, project[, org]` lines on stdin")
    save.add_argument("name")
    save.add_argument("--rename-from", default="")
    save.add_argument("--organization", default="")
    delete = a.add_parser("loadout-delete", help="Delete a loadout")
    delete.add_argument("name")
    gen = a.add_parser("report", help="Generate a vReport (.xlsx) for a loadout")
    gen.add_argument("loadout")
    gen.add_argument("--stale-days", type=int, default=90)
    gen.add_argument("--workers", type=int, default=10)
    gen.add_argument("--only-failed-from", default="", help="Re-run only the failed rows of this run id")
    imp = a.add_parser("import", help="File an external vReport .xlsx under a loadout and date")
    imp.add_argument("path")
    imp.add_argument("--loadout", required=True)
    imp.add_argument("--date", default="")
    lst = a.add_parser("runs", help="List report runs")
    lst.add_argument("--loadout", default="")
    lst.add_argument("--limit", type=int, default=50)
    lst.add_argument("--offset", type=int, default=0)
    rows = a.add_parser("rows", help="Rows of a run")
    rows.add_argument("run_id")
    rows.add_argument("--project", default="")
    rows.add_argument("--repository", default="")
    rows.add_argument("--limit", type=int, default=500)
    rows.add_argument("--offset", type=int, default=0)
    drop = a.add_parser("run-delete", help="Delete a run and its workbook")
    drop.add_argument("run_id")
    branch = a.add_parser("branches", help="Stale-branch report for one repository")
    branch.add_argument("repository")
    branch.add_argument("--project", required=True)
    branch.add_argument("--organization", default="")
    branch.add_argument("--stale-days", type=int, default=90)
    trend = a.add_parser("trends", help="Trend summary for a loadout")
    trend.add_argument("loadout")
    trend.add_argument("--months", type=int, default=12, help="0 for all history")
    find = a.add_parser("find", help="Find repositories by name (names on stdin, one per line)")
    owner = a.add_parser("owner", help="Repository ownership by email, or by --repository/--project")
    owner.add_argument("--email", default="")
    owner.add_argument("--repository", default="")
    owner.add_argument("--project", default="")
    owner.add_argument("--organization", default="")
    owner.add_argument("--refresh", action="store_true")
    a.add_parser("owner-cache-clear", help="Clear the ownership cache")
    powered = a.add_parser("powered", help="Refresh a powered loadout (top repositories by open findings)")
    powered.add_argument("id", choices=sorted(store.POWERED))
    query = a.add_parser("avit-search", help="Search AVITs with conditions JSON on stdin")
    query.add_argument("--limit", type=int, default=100)
    query.add_argument("--offset", type=int, default=0)
    close = a.add_parser("avit-close", help="Close AVITs: {conditions} or {records} JSON on stdin")
    close.add_argument("--reason", required=True)
    close.add_argument("--yes", action="store_true")
    rev = a.add_parser("avit-reverse", help="Reopen everything an earlier closure closed")
    rev.add_argument("action_id")
    rev.add_argument("--reason", required=True)
    rev.add_argument("--yes", action="store_true")
    tri = a.add_parser("triage", help="Bulk-ignore a rule's or secret type's open Semgrep findings as false positives")
    tri.add_argument("--project", required=True)
    tri.add_argument("--mode", choices=["sast", "secrets"], required=True)
    tri.add_argument("--rule", default="")
    tri.add_argument("--secret-type", default="")
    tri.add_argument("--note", required=True)
    tri.add_argument("--workers", type=int, default=4)
    tri.add_argument("--yes", action="store_true")
    hist = a.add_parser("actions", help="Action history")
    hist.add_argument("--limit", type=int, default=200)
    hist.add_argument("--id", default="")
    purge = a.add_parser("actions-purge", help="Delete history older than N days (keeps reversible closures)")
    purge.add_argument("days", type=int)
    purge.add_argument("--include-reversible", action="store_true")
    for action in a.choices.values():
        action.add_argument("--aws-profile", default=None)
        action.add_argument("--cancel-file", default="", help=argparse_suppress())


def argparse_suppress():
    import argparse  # noqa: PLC0415
    return argparse.SUPPRESS


def _watch_cancel(path: str, cancel: threading.Event) -> None:
    """The Workbench cancels a job by creating this file (portable; signals differ on Windows)."""
    import os  # noqa: PLC0415
    import time  # noqa: PLC0415
    def poll():
        while not cancel.is_set():
            if os.path.exists(path):
                cancel.set()
                return
            time.sleep(0.5)
    threading.Thread(target=poll, daemon=True).start()


def _confirm(args, question: str) -> None:
    if not getattr(args, "yes", False):
        if not sys.stdin.isatty():
            raise SidekickError("Confirmation required: rerun with --yes")
        if input(f"{question} [y/N] ").strip().lower() not in ("y", "yes"):
            raise SidekickError("Cancelled")


def cmd_sidekick(args) -> int:
    cancel = threading.Event()
    with contextlib.suppress(ValueError):
        signal.signal(signal.SIGINT, lambda *_a: cancel.set())
    profile, c = args.aws_profile, args.sk_command
    if args.cancel_file:
        _watch_cancel(args.cancel_file, cancel)
    try:
        if c == "orgs":
            return _out({"organizations": store.organizations(), "default": store.default_organization()})
        if c == "loadouts":
            powered = store.read_json("powered_loadouts.json")
            return _out({"loadouts": store.loadouts(), "powered": {k: {**v, **powered.get(k, {})} for k, v in store.POWERED.items()}})
        if c == "loadout-save":
            entries, warnings = store.parse_loadout_text(sys.stdin.read(), args.organization)
            change = store.save_loadout(args.name, entries, args.rename_from)
            if change["added"] or change["removed"] or args.rename_from:
                store.journal("loadout_changed", reason=f"{change['added']} added, {change['removed']} removed", subject=args.name)
            return _out({"name": args.name, "entries": len(entries), "warnings": warnings, **change})
        if c == "loadout-delete":
            return _out({"deleted": store.delete_loadout(args.name)})
        if c == "report":
            if args.only_failed_from:
                targets = [{"repo": r["repository"], "project": r["project"], "organization": r["organization"]}
                           for r in reports.run_rows(args.only_failed_from, limit=100_000) if r["status"] != "complete"]
                loadout = ""
            else:
                powered = store.read_json("powered_loadouts.json").get(args.loadout)
                targets = powered["entries"] if powered else store.loadouts().get(args.loadout)
                if targets is None:
                    raise SidekickError(f"No loadout named {args.loadout}")
                loadout = args.loadout
            return _out(reports.generate(loadout, targets, stale_days=args.stale_days, workers=args.workers, profile=profile, progress=_progress, cancel=cancel))
        if c == "import":
            return _out(reports.import_report(args.path, args.loadout, args.date))
        if c == "runs":
            return _out({"runs": reports.runs(args.loadout, args.limit, args.offset)})
        if c == "rows":
            return _out({"rows": reports.run_rows(args.run_id, args.project, args.repository, args.limit, args.offset)})
        if c == "run-delete":
            return _out({"deleted": reports.delete_run(args.run_id)})
        if c == "branches":
            return _out(reports.branch_report(args.organization or store.default_organization(), args.project, args.repository, args.stale_days))
        if c == "trends":
            return _out(reports.trends(args.loadout, args.months))
        if c == "find":
            return _out(ops.find_projects(sys.stdin.read().splitlines(), progress=_progress))
        if c == "owner":
            if args.email:
                return _out(ops.owner_by_email(args.email, profile, args.refresh))
            if not (args.repository and args.project):
                raise SidekickError("Give --email, or --repository and --project")
            return _out(ops.owner_by_repo(args.organization or store.default_organization(), args.project, args.repository, profile))
        if c == "owner-cache-clear":
            return _out({"cleared": ops.clear_ownership_cache()})
        if c == "powered":
            return _out(ops.refresh_powered(args.id, profile))
        if c == "avit-search":
            from threatlint.sidekick.clients import ServiceNow, build_query  # noqa: PLC0415
            conditions = json.loads(sys.stdin.read() or "[]")
            rows, total = ServiceNow.from_config(profile).search(build_query(conditions), args.limit, args.offset)
            return _out({"rows": rows, "total": total})
        if c == "avit-close":
            spec = json.loads(sys.stdin.read() or "{}")
            _confirm(args, "Close the matching AVITs in ServiceNow?")
            return _out(ops.close_avits(reason=args.reason, conditions=spec.get("conditions"), records=spec.get("records"),
                                        profile=profile, progress=_progress, cancel=cancel))
        if c == "avit-reverse":
            _confirm(args, f"Reopen every AVIT closed by {args.action_id}?")
            return _out(ops.reverse_closure(args.action_id, args.reason, profile, _progress))
        if c == "triage":
            _confirm(args, f"Ignore matching findings in {args.project} as false positives?")
            return _out(ops.bulk_triage(project=args.project, mode=args.mode, rule=args.rule, secret_type=args.secret_type, note=args.note,
                                        workers=args.workers, profile=profile, progress=_progress, cancel=cancel))
        if c == "actions":
            with contextlib.closing(store.connect()) as db:
                if args.id:
                    run = db.execute("SELECT * FROM action_runs WHERE id=?", (args.id,)).fetchone()
                    targets = [dict(t) for t in db.execute("SELECT * FROM action_targets WHERE run_id=?", (args.id,))]
                    return _out({"action": dict(run) if run else None, "targets": targets})
                rows = [dict(r) for r in db.execute("SELECT * FROM action_runs ORDER BY created_at DESC LIMIT ?", (args.limit,))]
                stats = dict(db.execute("SELECT COUNT(*) runs, MIN(created_at) oldest FROM action_runs").fetchone())
            return _out({"actions": [{**r, "reversible": r["kind"] == "avit_close" and not r["reversed_by"] and r["succeeded"] > 0} for r in rows], "stats": stats})
        if c == "actions-purge":
            return _out({"removed": store.purge_actions(args.days, not args.include_reversible)})
    except (SidekickError, ValueError, sn.ServiceNowError, TimeoutError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 2
