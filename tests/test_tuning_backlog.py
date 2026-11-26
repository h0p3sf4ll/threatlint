"""Semgrep tuning, triage, and scanner follow-ups are logged for repair later and never fail a review."""

import json
import os

from threatlint import tuning_backlog

CONTEXT = {"rule": "python.example.rule", "scm_tool": "ADO", "organization": "contoso", "project": "Platform",
           "repository": "svc", "branch": "main", "file_path": "app/db.py", "line": "349", "finding_source": "SAST"}
REPORT = ("**Disposition**: FALSE POSITIVE\n**Tuned rule**:\n```yaml\nrules:\n  - id: python.example.rule.tuned\n"
          "    pattern: foo(...)\n```\n")


def test_record_appends_one_private_entry_with_the_finding_and_proposed_rule(capsys):
    assert tuning_backlog.record("AVIT000000000000001", "tuning", "Missed ruleid lines 37, 47", context=CONTEXT,
                                 markdown=REPORT, report_attachment="AVIT000000000000001-threatlint-fp-review.docx")
    [entry] = tuning_backlog.entries()
    assert entry["avit"] == "AVIT000000000000001" and entry["stage"] == "tuning" and entry["status"] == "open"
    assert entry["reason"] == "Missed ruleid lines 37, 47"
    assert (entry["rule"], entry["repository"], entry["branch"], entry["file_path"], entry["line"]) == (
        "python.example.rule", "svc", "main", "app/db.py", "349")
    assert entry["tuned_rule"].startswith("rules:\n  - id: python.example.rule.tuned")
    assert entry["report_attachment"] == "AVIT000000000000001-threatlint-fp-review.docx"
    assert oct(os.stat(tuning_backlog.path()).st_mode & 0o777) == "0o600"
    assert "Logged for Semgrep triage and repair later (tuning)" in capsys.readouterr().out


def test_entries_accumulate_and_unknown_stages_are_semgrep():
    tuning_backlog.record("AVIT000000000000001", "tuning", "first", context=CONTEXT)
    tuning_backlog.record("AVIT000000000000002", "something-else", "second", context=CONTEXT)
    assert [(item["avit"], item["stage"]) for item in tuning_backlog.entries()] == [
        ("AVIT000000000000001", "tuning"), ("AVIT000000000000002", "semgrep")]


def test_a_logging_failure_never_raises(monkeypatch, tmp_path, capsys):
    blocker = tmp_path / "file-not-folder"
    blocker.write_text("x")
    monkeypatch.setenv("THREATLINT_HOME", str(blocker))
    assert tuning_backlog.record("AVIT000000000000001", "tuning", "reason", context=CONTEXT) is False
    assert "could not be logged" in capsys.readouterr().err


def test_backlog_command_lists_entries_and_json(capsys):
    from types import SimpleNamespace
    assert tuning_backlog.cmd_backlog(SimpleNamespace(json=False)) == 0
    assert "No Semgrep follow-ups logged" in capsys.readouterr().out
    tuning_backlog.record("AVIT000000000000001", "triage", "4 peer findings share the fingerprint", context=CONTEXT)
    capsys.readouterr()
    assert tuning_backlog.cmd_backlog(SimpleNamespace(json=False)) == 0
    listed = capsys.readouterr().out
    assert "AVIT000000000000001  [triage]  python.example.rule" in listed and "svc@main app/db.py:349" in listed
    assert tuning_backlog.cmd_backlog(SimpleNamespace(json=True)) == 0
    assert json.loads(capsys.readouterr().out.strip())["reason"] == "4 peer findings share the fingerprint"


def test_resolve_logs_a_workbench_tuning_reason_when_the_avit_closes(monkeypatch, tmp_path):
    from test_avit_resolve import FakeServiceNow, REPORT as FP_REPORT, _args
    from threatlint import avit_resolve as ar, servicenow as sn

    monkeypatch.setattr(sn, "_request_json", FakeServiceNow())
    monkeypatch.setattr(sn, "resolve_credentials", lambda _p: ("id", "secret"))
    args = _args(tmp_path, FP_REPORT, tuning_reason="Semgrep could not validate the proposal.")
    args.skip_semgrep = True
    assert ar.cmd_resolve(args) == 0
    [entry] = tuning_backlog.entries()
    assert entry["stage"] == "tuning" and entry["reason"] == "Semgrep could not validate the proposal."
