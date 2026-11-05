"""Evidence refinement uses real local source/Git and never calls cloud services."""

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from threatlint import ado_login, avit_cli, avit_evidence as evidence, avit_pr, servicenow
from test_avit_pr import AVIT, PATCH, SOURCE, TARGET, checkout, git, report


def confirmed(patch=PATCH):
    return report(patch).replace(
        "**Evidence**: app.py:2 evaluates caller-controlled text.",
        "**Evidence**: `app.py:1-2` accepts the caller's value and passes it to `eval(value)` without validation.\n"
        "**Exploit path**: The caller controls value, which reaches eval at app.py:2 without a guard and can execute an expression.\n"
        "**Fix rationale**: Literal parsing accepts existing literal inputs and rejects executable expressions.\n"
        "**Regression assertions**: Accept a list literal and reject function calls; tests NOT RUN.",
    )


@pytest.fixture(autouse=True)
def no_cloud(monkeypatch):
    monkeypatch.setattr(ado_login, "service_account_pat", lambda *_: pytest.fail("No credentials during evidence preparation"))
    monkeypatch.setattr(avit_pr, "_request", lambda *_a, **_k: pytest.fail("No network during evidence preparation"))
    monkeypatch.setattr(servicenow, "resolve_credentials", lambda *_a, **_k: pytest.fail("No tracker authentication during evidence preparation"))


def assess(repo, text, **target):
    return evidence.assess_review(AVIT, text, str(repo), {**TARGET, "file_path": "app.py", "line": "2", **target})


def test_complete_confirmed_proposal_is_ready_without_mutating_checkout(checkout):
    index = (checkout / ".git" / "index").read_bytes()
    objects = sorted(path.relative_to(checkout) for path in (checkout / ".git" / "objects").rglob("*"))
    assert assess(checkout, confirmed()) == {"status": "ready", "issues": [], "prompt": ""}
    assert (checkout / "app.py").read_text() == SOURCE
    assert (checkout / ".git" / "index").read_bytes() == index
    assert sorted(path.relative_to(checkout) for path in (checkout / ".git" / "objects").rglob("*")) == objects


def test_conservative_report_collects_real_source_and_specific_followup(checkout):
    text = confirmed().replace("**Confidence**: CONFIRMED", "**Confidence**: PLAUSIBLE\n**Decision basis**: CONSERVATIVE DEFAULT")
    result = assess(checkout, text)
    assert result["status"] == "refine"
    assert any("unverified" in issue for issue in result["issues"])
    assert "app.py\n1: def parse(value):\n2:     return eval(value)" in result["prompt"]
    assert git(checkout, "rev-parse", "HEAD") in result["prompt"]
    assert "not a request to relabel uncertainty" in result["prompt"]
    assert "read-only repository tools" in result["prompt"]
    assert "FALSE POSITIVE with Verified Safe Behavior" in result["prompt"]
    assert "Tests remain NOT RUN" in result["prompt"]


@pytest.mark.parametrize("field", ["Evidence", "Exploit path", "Fix rationale", "Regression assertions"])
def test_missing_proof_or_fix_section_requests_substantive_work(checkout, field):
    text = "\n".join(line for line in confirmed().splitlines() if not line.startswith(f"**{field}**:")) + "\n"
    result = assess(checkout, text)
    assert result["status"] == "refine"
    assert any(field in issue for issue in result["issues"])


@pytest.mark.parametrize("location", ["app.py:999", "app.py:0", "missing.py:1", "../outside.py:1", "linked.py:1"])
def test_invalid_source_citation_does_not_confirm_a_finding(checkout, tmp_path, location):
    outside = tmp_path / "outside.py"
    outside.write_text("outside-sensitive-evidence\n")
    (checkout / "linked.py").symlink_to(outside)
    git(checkout, "add", "linked.py")
    git(checkout, "commit", "-m", "symlink fixture")
    result = assess(checkout, confirmed().replace("app.py:1-2", location))
    assert result["status"] == "refine"
    assert any("invalid source citation" in issue for issue in result["issues"])
    assert "outside-sensitive-evidence" not in result["prompt"]


@pytest.mark.parametrize("patch", ["", PATCH.replace("return eval(value)", "return not_the_source(value)")])
def test_missing_or_inapplicable_fix_requests_repair_before_publication(checkout, patch):
    result = assess(checkout, confirmed(patch))
    assert result["status"] == "refine"
    assert any("patch" in issue or "proposed fix" in issue for issue in result["issues"])


def test_legacy_ambiguous_and_unverified_validation_are_refined(checkout):
    for text in (confirmed().replace("**Disposition**: TRUE POSITIVE", "**Disposition**: AMBIGUOUS"),
                 confirmed() + "\n**Validation status**: UNVERIFIED\n"):
        assert assess(checkout, text)["status"] == "refine"


def test_report_for_multiple_findings_cannot_become_ready(checkout):
    text = confirmed() + confirmed().replace(AVIT, "AVIT000000000000002").replace("FP-001", "FP-002")
    result = assess(checkout, text)
    assert result["status"] == "refine" and any("AVIT alone" in issue for issue in result["issues"])


def test_false_positive_returns_to_existing_tuning_path(checkout):
    result = assess(checkout, report(disposition="FALSE POSITIVE"))
    assert result["status"] == "skipped" and "scanner-tuning" in result["issues"][0]


@pytest.mark.parametrize("change", [
    {"scm": "unsupported"}, {"branch": ""}, {"branch_deleted": "release"},
    {"branch": "other"},
])
def test_missing_checkout_prerequisites_are_concrete_blockers(checkout, change):
    result = assess(checkout, confirmed(), **change)
    assert result["status"] == "skipped" and result["issues"] and not result["prompt"]


def test_missing_git_checkout_and_dirty_checkout_are_skipped(checkout, tmp_path):
    assert assess(tmp_path, confirmed())["status"] == "skipped"
    (checkout / "app.py").write_text("unreviewed edit\n")
    assert "not clean" in assess(checkout, confirmed())["issues"][0]


def test_protocol_aliases_are_accepted(checkout):
    text = confirmed().replace("**Exploit path**", "**Assessment and alternative interpretation**").replace(
        "**Fix rationale**", "**Implementation Notes**").replace("**Regression assertions**", "**Regression Tests**")
    assert assess(checkout, text)["status"] == "ready"


def test_untrusted_source_and_prior_report_are_bounded_and_redacted(checkout):
    secret = "synthetic-secret-value-12345678901234567890"
    (checkout / "app.py").write_text(SOURCE + f'password = "{secret}"\n')
    git(checkout, "add", "app.py")
    git(checkout, "commit", "-m", "synthetic credential fixture")
    result = assess(checkout, confirmed("") + f'\npassword = "{secret}"\n' + "x " * 50_000)
    assert result["status"] == "refine" and secret not in result["prompt"]
    assert "[REDACTED]" in result["prompt"]
    assert len(result["prompt"]) < 90_000


def test_original_location_can_supply_evidence_for_a_malformed_report(checkout):
    text = report(patch="")
    result = evidence.assess_review(AVIT, text, str(checkout), TARGET)
    assert result["status"] == "refine" and "return eval(value)" in result["prompt"]


def test_stale_source_location_is_investigated_and_can_be_recovered(checkout):
    text = confirmed().replace("app.py", "old_app.py")
    result = assess(checkout, text, file_path="old_app.py")
    assert result["status"] == "refine"
    assert any("repository search" in issue for issue in result["issues"])
    assert "Glob/Grep" in result["prompt"]
    assert assess(checkout, confirmed(), file_path="old_app.py")["status"] == "ready"


def test_remaining_blocker_is_named_and_redacted_in_issues(checkout):
    text = confirmed().replace("**Confidence**: CONFIRMED", "**Confidence**: PLAUSIBLE\n**Decision basis**: CONSERVATIVE DEFAULT")
    text += "\n**Blocking Evidence**: The deployed route registration is unavailable in this checkout.\n"
    text += "**Resolution Plan**: Inspect the deployment's routing configuration to determine exposure.\n"
    result = assess(checkout, text)
    assert any("deployed route registration is unavailable" in issue for issue in result["issues"])
    assert any("routing configuration" in issue for issue in result["issues"])


def test_prepare_fix_cli_does_not_require_confirmation_or_authentication(checkout, tmp_path, monkeypatch, capsys):
    markdown = tmp_path / "review.md"
    markdown.write_text(confirmed())
    target = tmp_path / "target.json"
    target.write_text(json.dumps({**TARGET, "avit": AVIT, "file_path": "app.py"}))
    monkeypatch.setattr(avit_cli, "confirm", lambda *_: pytest.fail("Local inspection needs no confirmation"))
    args = SimpleNamespace(number=AVIT, report=str(markdown), checkout=str(checkout), target=str(target))
    assert avit_cli.cmd_prepare_fix(args) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "ready"


def test_prepare_fix_cli_rejects_other_avit_target(checkout, tmp_path):
    markdown = tmp_path / "review.md"
    markdown.write_text(confirmed())
    target = tmp_path / "target.json"
    target.write_text(json.dumps({**TARGET, "avit": "AVIT000000000000002"}))
    args = SimpleNamespace(number=AVIT, report=str(markdown), checkout=str(checkout), target=str(target))
    with pytest.raises(evidence.ResolveError, match="does not belong"):
        avit_cli.cmd_prepare_fix(args)


def test_prepare_fix_command_dispatches_without_tracker_settings(checkout, tmp_path):
    markdown = tmp_path / "review.md"
    markdown.write_text(confirmed())
    target = tmp_path / "target.json"
    target.write_text(json.dumps({**TARGET, "avit": AVIT, "file_path": "app.py"}))
    result = subprocess.run([sys.executable, "-c", "from threatlint.cli import main; main()",
                             "avit", "prepare-fix", AVIT, "--report", str(markdown), "--checkout", str(checkout),
                             "--target", str(target), "--aws-profile", "no-authentication-needed"],
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "ready"
