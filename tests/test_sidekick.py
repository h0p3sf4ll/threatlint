from __future__ import annotations

import contextlib
import datetime as dt
import json
import zipfile

import pytest

from threatlint.sidekick import clients, ops, reports, store, xlsx


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    monkeypatch.setenv("THREATLINT_ADO_ORGANIZATIONS", "contoso,fabrikam")
    return tmp_path


def test_loadout_text_uses_org_directives_and_skips_duplicates():
    entries, warnings = store.parse_loadout_text("api, Platform\n# org: fabrikam\nweb, Shop\nweb, Shop\nbad/name, X\nsolo\n")
    assert [(e["repo"], e["organization"]) for e in entries] == [("api", "contoso"), ("web", "fabrikam")]
    assert len(warnings) == 3


def test_loadout_save_rename_and_journal_counts():
    assert store.save_loadout("Team A", [{"repo": "api", "project": "P"}]) == {"added": 1, "removed": 0}
    change = store.save_loadout("Team B", [{"repo": "web", "project": "P"}], previous="Team A")
    assert change == {"added": 1, "removed": 1} and list(store.loadouts()) == ["Team B"]
    with pytest.raises(ValueError, match="at least 3"):
        store.save_loadout("ab", [])
    with pytest.raises(ValueError, match="reserved"):
        store.save_loadout("secrets-top-20", [])


def test_same_repository_in_two_organizations_does_not_break_a_run():
    rows = [{"repository": "api", "project": "P", "organization": org, "total_vulns": 1} for org in ("contoso", "fabrikam")]
    run = store.record_run("L", rows, stale_days=90, duration=1, workbook="x")
    assert len(reports.run_rows(run)) == 2


def test_imported_rows_are_complete_so_movers_work(tmp_path):
    path = tmp_path / "in.xlsx"
    xlsx.write_xlsx(str(path), ["Repo", "Project", "Total Vulns", "Open Secrets"], [["api", "P", 5, 1]])
    first = reports.import_report(str(path), "Loadout X", "2026-09-01")["runId"]
    xlsx.write_xlsx(str(path), ["Repo", "Project", "Total Vulns", "Open Secrets"], [["api", "P", 2, 1]])
    second = reports.import_report(str(path), "Loadout X", "2026-10-01")["runId"]
    assert reports.movers(first, second) == [{"repository": "api", "project": "P", "organization": "contoso", "metric": "Total Vulns",
                                               "before": 5, "after": 2, "delta": -3}]
    with pytest.raises(clients.SidekickError, match="already has a report"):
        reports.import_report(str(path), "Loadout X", "2026-10-01")


def test_scope_delta_separates_membership_change_from_real_progress():
    base = [{"repository": "shared", "project": "P", "organization": "contoso", "total_vulns": 10},
            {"repository": "leaving", "project": "P", "organization": "contoso", "total_vulns": 7}]
    cur = [{"repository": "shared", "project": "P", "organization": "contoso", "total_vulns": 6},
           {"repository": "joining", "project": "P", "organization": "contoso", "total_vulns": 50}]
    a = store.record_run("L", base, stale_days=90, duration=0, workbook="", created_at="2026-09-01T12:00:00Z")
    b = store.record_run("L", cur, stale_days=90, duration=0, workbook="", created_at="2026-10-01T12:00:00Z")
    scope = reports.scope_delta(a, b)
    assert scope["membershipChanged"] and scope["baselineCommon"]["total_vulns"] == 10 and scope["currentCommon"]["total_vulns"] == 6
    trend = reports.trends("L", months=0)
    assert trend["attribution"] == {"raw": 39, "fromScope": 43, "fromExisting": -4}
    assert trend["headline"]["posture"] == "Improving" and trend["likeForLike"]


def test_stale_branches_and_committer():
    now = dt.datetime(2026, 10, 27, tzinfo=dt.timezone.utc)
    branches = [{"name": "refs/heads/main", "date": "2026-10-01T00:00:00Z", "email": "lead@example.com"},
                {"name": "refs/heads/old", "date": "2025-01-01T00:00:00Z", "email": "x@example.com"},
                {"name": "refs/heads/nodate", "date": "", "email": ""}]
    assert reports.stale_count(branches, 90, now) == 1
    assert reports.committer_email(branches) == "lead@example.com"


def test_xlsx_round_trip_keeps_formula_text_as_text(tmp_path):
    path = tmp_path / "r.xlsx"
    xlsx.write_xlsx(str(path), ["repository", "ado_link"], [["=HYPERLINK(1)", "https://dev.azure.com/o/p/_git/r"]], links={1: 1})
    with zipfile.ZipFile(path) as book:
        sheet = book.read("xl/worksheets/sheet1.xml").decode()
        assert "<f>" not in sheet and 'TableStyleMedium2' in book.read("xl/tables/table1.xml").decode()
    assert xlsx.read_xlsx(str(path)) == [["repository", "ado_link"], ["=HYPERLINK(1)", "https://dev.azure.com/o/p/_git/r"]]


def test_query_builder_rejects_injection_and_unknown_fields():
    assert clients.build_query([{"field": "state", "operator": "=", "value": "1"},
                                {"field": "u_repository", "operator": "LIKE", "value": "api", "join": "OR"},
                                {"field": "project_branch", "operator": "ISEMPTY"}]) == "state=1^ORu_repositoryLIKEapi^project_branchISEMPTY"
    with pytest.raises(clients.SidekickError, match=r"\^"):
        clients.build_query([{"field": "number", "operator": "=", "value": "AVIT1^active=false"}])
    with pytest.raises(clients.SidekickError, match="Unknown field"):
        clients.build_query([{"field": "assigned_to", "operator": "=", "value": "x"}])


class FakeSnow(clients.ServiceNow):
    def __init__(self, fail_after: int | None = None):
        self.instance, self.limit, self.calls, self.fail_after = "https://x.service-now.com", contextlib.nullcontext(), [], fail_after

    def request(self, path, *, query=None, body=None, method=None):
        self.calls.append((path, body))
        if self.fail_after is not None and len(self.calls) > self.fail_after:
            raise clients.SidekickError("HTTP 502 from x")
        served = [{"id": r["id"], "status_code": 200} for r in body["rest_requests"]]
        return {"serviced_requests": served[:-1] if len(self.calls) == 1 and len(served) > 1 else served}, {}


def test_batch_api_body_and_unserviced_resubmission():
    snow = FakeSnow()
    outcome = snow.batch_patch(["a", "b", "c"], {"state": 3, "active": False, "work_notes": "r"}, "id")
    assert outcome == {"a": None, "b": None, "c": None} and len(snow.calls) == 2
    request = snow.calls[0][1]["rest_requests"][0]
    import base64
    assert request["method"] == "PATCH" and json.loads(base64.b64decode(request["body"]))["state"] == 3


def test_closure_is_journalled_reversible_once_and_partial_reversal_is_recorded(monkeypatch):
    snow = FakeSnow()
    monkeypatch.setattr(clients.ServiceNow, "from_config", classmethod(lambda cls, profile=None: snow))
    closed = ops.close_avits(reason="cleanup", records=[{"sys_id": f"s{i}", "state": "1", "active": "true"} for i in range(3)])
    assert closed["closed"] == 3
    failing = FakeSnow(fail_after=0)
    monkeypatch.setattr(clients.ServiceNow, "from_config", classmethod(lambda cls, profile=None: failing))
    reversed_ = ops.reverse_closure(closed["actionId"], "undo")
    assert reversed_["reopened"] == 0 and reversed_["failed"] == 3, "a failed batch is still journalled"
    with pytest.raises(clients.SidekickError, match="not a reversible"):
        ops.reverse_closure(closed["actionId"], "again")


def test_purge_keeps_unreversed_closures(monkeypatch):
    store.journal("report_generated", reason="old")
    store.journal("avit_close", reason="keep", succeeded=1, targets=[{"sys_id": "a"}])
    with contextlib.closing(store.connect()) as db, db:
        db.execute("UPDATE action_runs SET created_at='2020-01-01T00:00:00Z'")
    assert store.purge_actions(30) == 1
    assert store.purge_actions(30, keep_reversible=False) == 1


def test_csv_field_defuses_formulas():
    assert ops.csv_field("=cmd") == "'=cmd" and ops.csv_field('a,"b"') == '"a,""b"""' and ops.csv_field("plain") == "plain"


def test_organizations_include_those_with_a_saved_pat(monkeypatch):
    from threatlint import ado_login
    monkeypatch.setattr(ado_login, "organizations", lambda: ["fabrikam", "northwind"])
    assert store.organizations() == ["contoso", "fabrikam", "northwind"]
    monkeypatch.delenv("THREATLINT_ADO_ORGANIZATIONS")
    assert store.default_organization() == "fabrikam"
