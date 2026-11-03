"""Mutation scope, retained response evidence, idempotency, and stored-state checks."""

import json
import os
import urllib.parse

import pytest

from threatlint import avit_semgrep_triage as triage
from threatlint.avit_report import ResolveError

REPOSITORY = "org/project/repo"


@pytest.fixture
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    return tmp_path


def row(identifier=1, status="open", **changes):
    return {"id": identifier, "repository": {"name": REPOSITORY}, "ref": "feature", "rule_name": "r",
            "location": {"file_path": "file.py", "line": 42}, "status": status, **changes}


def ignore(query, **changes):
    options = {"repository": REPOSITORY, "ref": "feature", "rule": "r", **changes}
    return triage.ignore("synthetic", "deployment", "sast", [1], "reviewed FP", query=query, **options)


def audits(home):
    return [json.loads(path.read_text()) for path in (home / "triage").glob("*.json")]


def test_scope_and_returned_ids_are_verified_and_durable(home):
    posted, state = [], "open"

    def query(path, token, *, body=None):
        nonlocal state
        if body is not None:
            posted.append(body)
            state = "ignored"
            return {"num_triaged": 1, "triaged_issues": [1]}
        page = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["page"][0]
        return {"findings": [row(status=state)] if page == "0" else []}

    assert ignore(query) == 1
    assert posted[0]["issue_ids"] == [1]
    assert posted[0]["ref"] == "feature" and posted[0]["repos"] == [REPOSITORY]
    assert posted[0]["status"] == "open" and posted[0]["new_triage_reason"] == "false_positive"
    evidence = audits(home)[0]
    assert evidence["status"] == "verified" and evidence["verified_ids"] == [1]
    assert evidence["response"]["triaged_issues"] == [1]
    if os.name != "nt":
        assert next((home / "triage").glob("*.json")).stat().st_mode & 0o777 == 0o600


def test_cross_branch_expansion_is_an_error_and_all_affected_ids_survive(home):
    writes = []

    def query(path, token, *, body=None):
        if body is not None:
            writes.append(body)
            return {"num_triaged": 2, "triaged_issues": [1, 200]}
        page = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["page"][0]
        return {"findings": [row()] if page == "0" else []}

    with pytest.raises(ResolveError, match="do not retry automatically.*audit"):
        ignore(query)
    assert len(writes) == 1
    assert audits(home)[0]["response"]["triaged_issues"] == [1, 200]
    assert audits(home)[0]["status"] == "unverified"


def test_ignored_targets_do_not_repeat_writes(home):
    def query(path, token, *, body=None):
        assert body is None
        page = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["page"][0]
        return {"findings": [row(status="ignored")] if page == "0" else []}

    assert ignore(query) == 0
    assert audits(home)[0]["status"] == "already_ignored"


def test_wrong_branch_cannot_reach_the_mutation(home):
    def query(path, token, *, body=None):
        assert body is None
        return {"findings": [row(ref="other")]}

    with pytest.raises(ResolveError, match="branch"):
        ignore(query)
    assert audits(home)[0]["status"] == "unverified"


def test_unstored_result_does_not_report_success(home):
    def query(path, token, *, body=None):
        if body is not None:
            return {"num_triaged": 1, "triaged_issues": [1]}
        page = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["page"][0]
        return {"findings": [row()] if page == "0" else []}

    with pytest.raises(ResolveError, match="persist ignored"):
        ignore(query)


@pytest.mark.parametrize("field", ["repository", "ref", "rule"])
def test_incomplete_scope_never_queries_or_mutates(home, field):
    with pytest.raises(ResolveError, match="exact repository"):
        ignore(lambda *args, **kwargs: pytest.fail("No incomplete-scope request"), **{field: ""})
    assert not (home / "triage").exists()
