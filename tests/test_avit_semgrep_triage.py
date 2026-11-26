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
            "location": {"file_path": "file.py", "line": 42}, "match_based_id": f"fingerprint-{identifier}",
            "status": status, **changes}


def ignore(query, kind="sast", **changes):
    options = {"repository": REPOSITORY, "ref": "feature", "rule": "r", **changes}
    return triage.ignore("synthetic", "deployment", kind, [1], "reviewed FP", query=query, **options)


def audits(home):
    return [json.loads(path.read_text()) for path in (home / "triage").glob("*.json")]


def test_scope_and_returned_ids_are_verified_and_durable(home):
    posted, preflight_pages, state = [], [], "open"

    def query(path, token, *, body=None):
        nonlocal state
        if body is not None:
            posted.append(body)
            state = "ignored"
            return {"num_triaged": 1, "triaged_issues": [1]}
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
        page = params["page"][0]
        if "ref" not in params:
            preflight_pages.append(page)
            assert params["dedup"] == ["false"] and params["rules"] == ["r"] and "status" not in params
            if page == "1":
                return {"findings": [row(2, ref="main")]}
            if page == "2":
                return {"findings": []}
        return {"findings": [row(status=state)] if page == "0" else []}

    assert ignore(query) == 1
    assert preflight_pages == ["0", "1", "2"]
    assert posted[0]["issue_ids"] == [1]
    assert posted[0]["ref"] == "feature" and posted[0]["repos"] == [REPOSITORY]
    assert posted[0]["status"] == "open" and posted[0]["new_triage_reason"] == "false_positive"
    evidence = audits(home)[0]
    assert evidence["status"] == "verified" and evidence["verified_ids"] == [1]
    assert evidence["response"]["triaged_issues"] == [1]
    if os.name != "nt":
        assert next((home / "triage").glob("*.json")).stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("kind", ["sast", "sca"])
def test_same_fingerprint_peers_across_pages_are_audited_before_write(home, kind):
    def query(path, token, *, body=None):
        assert body is None
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
        if params["page"] == ["0"]:
            return {"findings": [row()]}
        if "ref" not in params and params["page"] == ["1"]:
            return {"findings": [row(2, ref="main", match_based_id="fingerprint-1")]}
        if "ref" not in params and params["page"] == ["2"]:
            return {"findings": [row(3, "ignored", match_based_id="fingerprint-1"), row(4, ref="other")]}
        return {"findings": []}

    with pytest.raises(triage.TriageScopeBlocked, match="Semgrep triage blocked:.*2 outside the requested write") as failure:
        ignore(query, kind=kind)
    assert "No Semgrep triage write was sent" in str(failure.value)
    assert str(next((home / "triage").glob("*.json"))) in str(failure.value)
    [audit] = audits(home)
    assert audit["status"] == "scope_blocked" and "submitted_ids" not in audit
    assert audit["peers"] == [{"id": 2, "ref": "main", "status": "open"},
                              {"id": 3, "ref": "feature", "status": "ignored"}]
    assert failure.value.peers == audit["peers"], "the block carries the peers for the tuned-rule decision"


@pytest.mark.parametrize("preflight,reason", [
    ([row(match_based_id=None)], "match fingerprint"),
    ([row(), row(2, ref="main", match_based_id=None)], "match fingerprint"),
    ([row(), row(2, ref=None)], "branch or rule"),
    ([row(), row(2, rule_name=None)], "branch or rule"),
    ([row(), row(1, ref="main", match_based_id="different")], "identity or state changed"),
    ([row(status="ignored")], "identity or state changed"),
    ([row(match_based_id="changed")], "identity or state changed"),
    ([], "did not return every requested finding"),
])
def test_incomplete_or_inconsistent_preflight_blocks_write(home, preflight, reason):
    def query(path, token, *, body=None):
        assert body is None
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
        return {"findings": ([row()] if "ref" in params else preflight) if params["page"] == ["0"] else []}

    with pytest.raises(ResolveError, match=reason):
        ignore(query)
    assert "submitted_ids" not in audits(home)[0]


def test_secrets_same_rule_on_another_ref_blocks_automatic_write(home):
    reads = []

    def query(path, token, *, body=None):
        assert body is None
        reads.append(path)
        fields = {"repository": {"name": REPOSITORY}, "ruleHashId": "r", "findingPath": "file.py:42",
                  "status": "FINDING_STATUS_OPEN"}
        return {"findings": [{**fields, "id": "1", "ref": "feature"}, {**fields, "id": "2", "ref": "main"}]}

    with pytest.raises(triage.TriageScopeBlocked, match="Secrets findings under the same rule on another ref"):
        ignore(query, kind="secrets", deployment_id=123)
    assert len(reads) == 1
    [audit] = audits(home)
    assert audit["status"] == "scope_blocked" and "submitted_ids" not in audit
    assert audit["peers"] == [{"id": 2, "ref": "main", "status": "open"}]


def test_cross_branch_expansion_is_an_error_and_all_affected_ids_survive(home):
    writes = []

    def query(path, token, *, body=None):
        if body is not None:
            writes.append(body)
            return {"num_triaged": 2, "triaged_issues": [1, 200]}
        page = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["page"][0]
        return {"findings": [row()] if page == "0" else []}

    with pytest.raises(ResolveError, match=r"finding IDs \[1, 200\].*Do not retry automatically.*audit"):
        ignore(query)
    assert len(writes) == 1
    assert audits(home)[0]["response"]["triaged_issues"] == [1, 200]
    assert audits(home)[0]["status"] == "unverified"


@pytest.mark.parametrize("status,submitted,response", [
    ("unverified", [1], {"num_triaged": 2, "triaged_issues": [1, 200]}),
    ("unverified", [200], {"num_triaged": 2, "triaged_issues": [200, 1]}),
    ("write_attempt", [1], None),
    ("response_received", [1], {"num_triaged": 1, "triaged_issues": [1]}),
])
def test_prior_unverified_write_blocks_rerun_before_reporting_already_ignored(home, status, submitted, response):
    audit = triage.TriageAudit({"status": status, "deployment": "deployment", "product": "sast",
                               "requested_ids": submitted, "submitted_ids": submitted, "response": response})

    def query(path, token, *, body=None):
        pytest.fail("A repeated operation must stop at the earlier audit before reading or writing")

    with pytest.raises(ResolveError, match="earlier Semgrep triage write.*still unverified.*No Semgrep triage write was sent") as failure:
        ignore(query)
    assert str(audit.path) in str(failure.value)
    if response:
        assert str(response["triaged_issues"]) in str(failure.value)
    assert len(audits(home)) == 1


@pytest.mark.parametrize("changes", [
    {"status": "verified"},
    {"deployment": "another-deployment"},
    {"product": "sca"},
    {"submitted_ids": [200]},
    {"submitted_ids": []},
])
def test_only_related_unverified_writes_block_reruns(home, changes):
    triage.TriageAudit({"status": "unverified", "deployment": "deployment", "product": "sast",
                       "requested_ids": [1], "submitted_ids": [1], **changes})

    def query(path, token, *, body=None):
        assert body is None
        page = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["page"][0]
        return {"findings": [row(status="ignored")] if page == "0" else []}

    assert ignore(query) == 0
    assert "already_ignored" in {audit["status"] for audit in audits(home)}


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
