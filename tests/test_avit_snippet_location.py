"""Recover unnumbered AVIT scanner occurrences without guessing between matches."""

import json
from types import SimpleNamespace

import pytest

from threatlint import avit_repositories, avit_resolve, avit_tuning, semgrep_platform, servicenow
from threatlint.avit_report import ResolveError

AVIT = "AVIT000000000000019"
TARGET = {"scm": "github", "name": "repo", "organization": "example", "branch": "release", "web_url": "repo"}


def scanner_record(snippet):
    return {"in_view": True, "context": {"file_path": "app.py", "rule": "test.rule"},
            "fields": servicenow._flatten({"u_code_snippet": {"display_value": snippet}})}


def test_checkout_preserves_indentation_to_separate_occurrences(tmp_path, capsys, monkeypatch):
    snippet = "        load(value)"
    (tmp_path / "app.py").write_bytes(b"    load(value)\r\n        load(value)\r\n")
    record = scanner_record(snippet)
    monkeypatch.setattr(servicenow, "repository_target", lambda _: TARGET)
    result = avit_repositories.cmd_checkout(
        SimpleNamespace(number=AVIT, dir=str(tmp_path)), session=lambda *_: ("", ""),
        read_record=lambda *_: record, checkout_branch=lambda *_: TARGET, renamed_repository=None,
    )
    output = capsys.readouterr().out
    target = json.loads(output.splitlines()[-1])
    assert result == 0 and target["line"] == "2" and target["line_source"] == "scanner_snippet"
    assert snippet.strip() not in output
    assert avit_tuning.flagged_location(tmp_path, target, "", AVIT) == (tmp_path / "app.py", 2)


@pytest.mark.parametrize(("snippet", "blocker"), [
    ("    load(value)", "more than once"),
    ("load(value)", "does not match"),
    ("    load(value)\npass", "multi-line"),
    ("x" * 4000, "truncated"),
])
def test_ambiguous_stale_and_partial_evidence_blocks_even_with_a_report_line(tmp_path, snippet, blocker):
    (tmp_path / "app.py").write_text("    load(value)\n    load(value)\n")
    record = scanner_record(snippet)
    location = avit_repositories.scanner_snippet_location(record, tmp_path, TARGET)
    report = f"Original finding: {AVIT}; rule; app.py:1\n"
    with pytest.raises(ResolveError, match=blocker):
        avit_tuning.flagged_location(tmp_path, {**record["context"], **location}, report, AVIT)


def test_snippet_lookup_respects_file_branch_and_explicit_scanner_line(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (tmp_path / "outside").write_text("load(value)\n")
    (root / "app.py").symlink_to(tmp_path / "outside")
    record = scanner_record("load(value)")
    assert "line_blocker" in avit_repositories.scanner_snippet_location(record, root, TARGET)
    assert avit_repositories.scanner_snippet_location(record, root, {**TARGET, "branch_deleted": "release"}) == {}
    record["context"]["line"] = "2"
    assert avit_repositories.scanner_snippet_location(record, root, TARGET) == {}


def test_resolver_corroborates_the_same_line_before_writing(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("pass\n    load(value)\n")
    record = scanner_record("    load(value)")
    args = SimpleNamespace(checkout=str(tmp_path), aws_profile=None)
    monkeypatch.setattr(servicenow, "repository_target", lambda _: TARGET)
    monkeypatch.setattr(avit_resolve, "semgrep_token", lambda _: "test-token")
    monkeypatch.setattr(semgrep_platform, "original_rule_yaml", lambda *_: "original")
    monkeypatch.setattr(semgrep_platform, "live_rule_matches", lambda *_: [])
    monkeypatch.setattr(avit_resolve, "semgrep_matches", lambda *_: ({"product": "sast"}, []))
    with pytest.raises(ResolveError, match="did not reproduce"):
        avit_resolve._locate_scanner_snippet(record, args)
    assert "line" not in record["context"]
    checked = []
    monkeypatch.setattr(semgrep_platform, "live_rule_matches", lambda *args: checked.append(args) or [2])
    avit_resolve._locate_scanner_snippet(record, args)
    assert checked == [("original", str(tmp_path / "app.py"), 2)]
    assert record["context"]["line"] == "2"
    assert record["context"]["snippet_match"] == "checkout"


@pytest.mark.parametrize("change", [{}, {"ref": "other"}, {"project": "other/repo"}, {"line": 3},
                                     {"path": "other/app.py"}, {"rule": "other.rule"}, {"status": "fixed"}])
def test_cloud_confirmation_requires_one_exact_scanner_finding(tmp_path, monkeypatch, change):
    context = {**TARGET, "file_path": "app.py", "rule": "test.rule"}
    match = {"id": 8, "rule": "test.rule", "line": 2, "path": "app.py", "product": "sast",
             "ref": "release", "project": "example/repo", "status": "open", **change}
    def query(token, kind, target, wanted, deployment):
        assert wanted["line_source"] == "scanner_snippet" and wanted["line"] == "2"
        return {"product": "sast"}, [match]
    monkeypatch.setattr(avit_resolve, "semgrep_matches", query)
    if change:
        with pytest.raises(ResolveError, match="exact finding"):
            avit_tuning.confirm_snippet_match(context, tmp_path / "app.py", 2, "token", reproduced=False)
    else:
        assert avit_tuning.confirm_snippet_match(context, tmp_path / "app.py", 2, "token", reproduced=False) == "semgrep"
