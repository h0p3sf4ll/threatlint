"""Real checkout and patch proof drive follow-up reviews before a mocked draft PR."""

from pathlib import Path

import pytest

from threatlint import ado_login, avit_headless, avit_pr, avit_resolve, dast, servicenow as sn
from threatlint.finding_review import normalize_report
from test_avit_headless import _args
from test_avit_pr import AVIT, ORIGIN, PAT, SOURCE, TARGET, FakeAdo, git, report


def confirmed_report(*, patch=True):
    return (report() if patch else report(patch="")) + (
        "**Exploit path**: app.py:1 accepts caller-controlled text; app.py:2 passes it directly to eval "
        "without a validation guard, permitting expression execution.\n"
        "**Fix rationale**: Parse literals with ast.literal_eval rather than executing arbitrary expressions.\n"
        "**Regression assertions**: Accept '[1]' and reject '__import__(\"os\")'; preserve literal parsing. "
        "Tests NOT RUN.\n"
    )


@pytest.fixture
def workflow(monkeypatch):
    state = {"reviews": [], "resolved": [], "api": None}
    def checkout(_item, _args, repo):
        repo.mkdir()
        git(repo, "init", "-b", "main")
        git(repo, "config", "user.name", "Fixture")
        git(repo, "config", "user.email", "fixture@example.test")
        (repo / "app.py").write_bytes(SOURCE.encode("utf-8"))
        git(repo, "add", "app.py")
        git(repo, "commit", "-m", "fixture")
        git(repo, "remote", "add", "origin", ORIGIN)
        state["api"] = FakeAdo(repo.resolve())
        state["repo"] = repo
        return {**TARGET, "file_path": "app.py", "line": "2"}
    monkeypatch.setattr(avit_headless, "_checkout", checkout)
    monkeypatch.setattr(avit_headless, "_rule_base", lambda *_: "Original scanner rule: dangerous eval use")
    monkeypatch.setattr(sn, "avits_markdown", lambda *_: f"AVIT evidence for {AVIT}, app.py:2")
    monkeypatch.setattr(sn, "finding_kind", lambda *_: "sast")
    monkeypatch.setattr(dast, "to_docx", lambda _md, docx: Path(docx).write_bytes(b"PKword"))
    monkeypatch.setattr(ado_login, "service_account_pat", lambda *_: (PAT, "service account"))
    monkeypatch.setattr(avit_pr, "_request", lambda *args, **kwargs: state["api"](*args, **kwargs))
    def resolve(args):
        assert not any(body for _, _, body in state["api"].calls), "no provider mutation before final write-back"
        state["resolved"].append(Path(args.report).read_text(encoding="utf-8"))
        return 0
    monkeypatch.setattr(avit_resolve, "cmd_resolve", resolve)
    return state


def run_workflow(monkeypatch, state, drafts):
    def review(_provider, _system, prompt, repo, *_args):
        assert (repo / "app.py").read_text() == SOURCE
        assert "Original scanner rule" in prompt
        state["reviews"].append(prompt)
        return drafts[min(len(state["reviews"]) - 1, len(drafts) - 1)]
    monkeypatch.setattr(avit_headless, "_run_review_model", review)
    item = {"fields": {"number": AVIT}, "context": {"file_path": "app.py", "line": "2", "rule": "unsafe-eval"}}
    return avit_headless._review_one(_args(AVIT), item, "https://test.service-now.com", "reviewer", "fixture", "1.99")


def test_investigates_conservative_tp_then_repairs_missing_patch_and_publishes(monkeypatch, workflow):
    initial = report(patch="", basis="**Decision basis**: CONSERVATIVE DEFAULT\n**Blocking Evidence**: Inspect the callers and guards.\n")
    final = confirmed_report()
    outcome = run_workflow(monkeypatch, workflow, [initial, confirmed_report(patch=False), final])
    assert outcome["completed"] is True and outcome["pull_request"]["status"] == "created"
    assert outcome["unverified"] is False
    assert len(workflow["reviews"]) == 3
    assert "app.py" in workflow["reviews"][1] and "caller" in workflow["reviews"][1].lower()
    assert "patch" in workflow["reviews"][2].lower()
    assert workflow["resolved"] == [normalize_report(final)], "only the confirmed final review is attached"
    assert sum(path == "/pushes" for path, _, _ in workflow["api"].calls) == 1
    assert not workflow["repo"].exists()


def test_confirmed_complete_review_publishes_without_followup(monkeypatch, workflow):
    outcome = run_workflow(monkeypatch, workflow, [confirmed_report()])
    assert outcome["completed"] and outcome["pull_request"]["draft"] is True
    assert len(workflow["reviews"]) == 1


@pytest.mark.parametrize("declaration", ["", "**Disposition**: TRUE POSITIVE and FALSE POSITIVE\n", "**Disposition**: NEEDS REVIEW\n"])
def test_investigation_repairs_invalid_disposition_before_writeback(monkeypatch, workflow, declaration):
    incomplete = confirmed_report().replace("**Disposition**: TRUE POSITIVE\n", declaration)
    outcome = run_workflow(monkeypatch, workflow, [incomplete, confirmed_report()])
    assert outcome["completed"] and outcome["pull_request"]["status"] == "created"
    assert len(workflow["reviews"]) == 2
    assert "unambiguous disposition" in workflow["reviews"][1]
    assert workflow["resolved"] == [normalize_report(confirmed_report())]


def test_unresolved_evidence_exhausts_investigation_without_claiming_confirmation(monkeypatch, workflow):
    uncertain = report(patch="", basis="**Decision basis**: CONSERVATIVE DEFAULT\n**Blocking Evidence**: Runtime caller identity is unavailable.\n")
    outcome = run_workflow(monkeypatch, workflow, [uncertain])
    assert len(workflow["reviews"]) == 3
    assert workflow["resolved"] == [normalize_report(uncertain)]
    assert outcome["completed"] is False and outcome["unverified"] is True
    assert outcome["pull_request"]["status"] == "blocked"
    assert workflow["api"].calls == []
    assert not workflow["repo"].exists()


def test_investigation_can_disprove_finding_and_use_fp_path(monkeypatch, workflow):
    initial = report(patch="", basis="**Decision basis**: CONSERVATIVE DEFAULT\n")
    disproved = report(patch="", disposition="FALSE POSITIVE")
    proven = []
    monkeypatch.setattr(avit_headless, "_guard_fp_rule", lambda *_: proven.append("guard"))
    monkeypatch.setattr(avit_headless, "_prove_tuned_rule", lambda *_: proven.append("proof"))
    outcome = run_workflow(monkeypatch, workflow, [initial, disproved])
    assert outcome["completed"] is True and outcome["disposition"] == "FALSE POSITIVE"
    assert "pull_request" not in outcome and workflow["api"].calls == []
    assert proven == ["guard", "proof"]
    assert workflow["resolved"] == [normalize_report(disproved)]


@pytest.mark.parametrize("followup", [False, True], ids=["initial-review", "evidence-followup"])
@pytest.mark.parametrize("safe_label", ["- **Verified Safe Behavior**:", "- **Verified Safe Behavior:**"])
def test_canonical_fp_proof_keeps_tuning_path_without_demanding_source_fix(monkeypatch, workflow, followup, safe_label):
    disproved = (
        "# Finding Review: synthetic fixture\n\n"
        "The reported expression is a FALSE POSITIVE; no source-fix patch is warranted.\n\n"
        "#### [FP-001] — Synthetic expected value\n"
        f"**Original finding**: {AVIT}; fixture-rule; scanner; app.py:2\n"
        "**Disposition**: FALSE POSITIVE\n**Confidence**: CONFIRMED\n"
        "##### Evidence\n\n"
        "| Stage | Inspected evidence |\n|---|---|\n"
        "| Test setup | `app.py:1-2` — the synthetic expected value belongs to the mocked call. |\n\n"
        f"{safe_label} The expected value is fixture data in a mocked assertion and never reaches a real client.\n"
        "- **Proposed Tuning**: Keep live-client detections while excluding the proven fixture expression.\n"
    )
    validated = []
    monkeypatch.setattr(avit_headless, "_guard_fp_rule", lambda *_: validated.append("rule guard"))
    monkeypatch.setattr(avit_headless, "_prove_tuned_rule", lambda *_: validated.append("tuning proof"))
    initial = report(patch="", basis="**Decision basis**: CONSERVATIVE DEFAULT\n")
    outcome = run_workflow(monkeypatch, workflow, [initial, disproved] if followup else [disproved])

    assert outcome["completed"] is True and outcome["disposition"] == "FALSE POSITIVE"
    assert len(workflow["reviews"]) == (2 if followup else 1)
    assert validated == ["rule guard", "tuning proof"]
    assert workflow["resolved"] == [normalize_report(disproved)]
    assert "CONSERVATIVE DEFAULT" not in workflow["resolved"][0]
    assert "pull_request" not in outcome and workflow["api"].calls == []
    assert not workflow["repo"].exists()
