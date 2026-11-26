"""Evidence refinement uses real local source/Git and never calls cloud services."""

import json
import re
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
    assert result["status"] == "refine" and result["unverified"] is True
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
    assert result.get("phase") == ("patch" if field in ("Fix rationale", "Regression assertions") else None)


@pytest.mark.parametrize("location", ["app.py:999", "app.py:0", "missing.py:1", "../outside.py:1", "linked.py:1"])
def test_invalid_source_citation_does_not_confirm_a_finding(checkout, tmp_path, location):
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"outside-sensitive-evidence\n")
    (checkout / "linked.py").symlink_to(outside)
    git(checkout, "add", "linked.py")
    git(checkout, "commit", "-m", "symlink fixture")
    result = assess(checkout, confirmed().replace("app.py:1-2", location))
    assert result["status"] == "refine"
    assert any("invalid source citation" in issue for issue in result["issues"])
    assert "outside-sensitive-evidence" not in result["prompt"]


def commit_files(repo, files):
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_bytes(text.encode("utf-8"))
        git(repo, "add", name)
    git(repo, "commit", "-m", "nested fixture")


@pytest.mark.parametrize("cited", ["Startup.cs:2", "Web/Startup.cs:1-2", "./svc/Web/Startup.cs:2"])
def test_unique_short_or_project_relative_citation_resolves_to_the_tracked_file(checkout, cited):
    commit_files(checkout, {"svc/Web/Startup.cs": "class Startup {\n  // auth disabled\n}\n"})
    text = confirmed().replace("reaches eval at app.py:2", f"reaches eval at app.py:2 with authentication disabled at {cited}")
    result = assess(checkout, text)
    assert result == {"status": "ready", "issues": [], "prompt": ""}


def test_resolved_citation_supplies_source_excerpt_under_its_full_path(checkout):
    commit_files(checkout, {"svc/Web/Startup.cs": "class Startup {\n  // auth disabled\n}\n"})
    text = confirmed().replace("reaches eval at app.py:2", "reaches eval with authentication disabled at Startup.cs:2")
    text = text.replace("**Confidence**: CONFIRMED", "**Confidence**: PLAUSIBLE")
    result = assess(checkout, text, file_path="")
    assert "File: svc/Web/Startup.cs\n1: class Startup {" in result["prompt"]
    assert not any("invalid source citation" in issue for issue in result["issues"])


@pytest.mark.parametrize(("cited", "detail"), [
    ("Startup.cs:1", "Startup.cs:1 (matches 2 tracked files; cite the full repository-relative path)"),
    ("Web/Startup.cs:9", "Web/Startup.cs:9 (matches 2 tracked files"),
    ("one/Web/Startup.cs:2-9", "one/Web/Startup.cs:2-9 (the file has 3 lines)"),
    ("Missing.cs:4", "Missing.cs:4 (no readable tracked file)"),
])
def test_ambiguous_missing_or_out_of_range_citations_fail_and_are_named(checkout, cited, detail):
    commit_files(checkout, {"one/Web/Startup.cs": "a\nb\nc\n", "two/Web/Startup.cs": "a\nb\nc\n"})
    text = confirmed().replace("reaches eval at app.py:2", f"reaches eval at app.py:2 and {cited}")
    result = assess(checkout, text)
    assert result["status"] == "refine"
    issue = next(issue for issue in result["issues"] if "invalid source citation" in issue)
    assert detail in issue
    assert detail in result["prompt"]


def test_clock_times_are_not_source_citations(checkout):
    text = confirmed().replace("reaches eval at app.py:2", "reaches eval at app.py:2 (traced 14:03 UTC, scan 08:10)")
    assert assess(checkout, text) == {"status": "ready", "issues": [], "prompt": ""}


def test_short_citation_never_resolves_to_a_symlink(checkout, tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"outside-sensitive-evidence\n")
    (checkout / "pkg").mkdir()
    (checkout / "pkg" / "linked.py").symlink_to(outside)
    git(checkout, "add", "pkg/linked.py")
    git(checkout, "commit", "-m", "symlink fixture")
    result = assess(checkout, confirmed().replace("app.py:1-2", "linked.py:1"))
    assert result["status"] == "refine"
    assert any("linked.py:1 (no readable tracked file)" in issue for issue in result["issues"])
    assert "outside-sensitive-evidence" not in result["prompt"]


@pytest.mark.parametrize("patch", ["", PATCH.replace("return eval(value)", "return not_the_source(value)")])
def test_missing_or_inapplicable_fix_requests_repair_before_publication(checkout, patch):
    result = assess(checkout, confirmed(patch))
    assert result["status"] == "refine" and result["phase"] == "patch"
    assert any("patch" in issue or "proposed fix" in issue for issue in result["issues"])
    assert "exactly one line reading **Proposed fix patch**:" in result["prompt"]


@pytest.mark.parametrize(("change", "unverified"), [
    ("conservative", True), ("nonconfirmed", True), ("explicitly unverified", True),
    ("missing source", False), ("multiple findings", False),
])
def test_fix_preparation_waits_for_single_confirmed_finding_with_source(checkout, monkeypatch, change, unverified):
    text = confirmed(patch="")
    if change == "conservative":
        text += "\n**Decision basis**: CONSERVATIVE DEFAULT\n"
    elif change == "nonconfirmed":
        text = text.replace("CONFIRMED", "PLAUSIBLE")
    elif change == "explicitly unverified":
        text += "\n**Validation status**: UNVERIFIED\n"
    elif change == "missing source":
        text = text.replace("app.py:", "missing.py:")
    else:
        text += text.replace(AVIT, "AVIT000000000000002").replace("FP-001", "FP-002")
    text = "\n".join(line for line in text.splitlines() if not line.startswith(("**Fix rationale**", "**Regression assertions**")))
    monkeypatch.setattr(evidence, "_patch", lambda *_: pytest.fail("Do not read patches during evidence investigation"))
    result = assess(checkout, text)
    assert result["status"] == "refine" and "phase" not in result
    assert ("unverified" in result) is unverified
    assert not any("patch" in issue.lower() or "Fix rationale" in issue or "Regression assertions" in issue for issue in result["issues"])
    assert "exactly one line reading **Proposed fix patch**:" not in result["prompt"]


def test_ignored_files_cannot_supply_review_evidence(checkout):
    (checkout / ".git" / "info" / "exclude").write_text("ignored.py\n", encoding="utf-8")
    (checkout / "ignored.py").write_text("untracked fixture\nsecond line\n", encoding="utf-8")
    text = confirmed().replace("app.py:", "ignored.py:")
    result = assess(checkout, text, file_path="ignored.py")
    assert result["status"] == "refine" and "phase" not in result
    assert any("invalid source citation" in issue for issue in result["issues"])
    assert "untracked fixture" not in result["prompt"]


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
    (checkout / "app.py").write_bytes(b"unreviewed edit\n")
    assert "not clean" in assess(checkout, confirmed())["issues"][0]


def test_protocol_aliases_are_accepted(checkout):
    text = confirmed().replace("**Exploit path**", "**Assessment and alternative interpretation**").replace(
        "**Fix rationale**", "**Implementation Notes**").replace("**Regression assertions**", "**Regression Tests**")
    assert assess(checkout, text)["status"] == "ready"


@pytest.mark.parametrize("prefix", ["", "- ", "  + "])
def test_formatted_confirmed_proposal_is_ready(checkout, prefix):
    text = re.sub(r"(?m)^\*\*([^*\n]+)\*\*:", rf"{prefix}**\1:**", confirmed())
    assert assess(checkout, text)["status"] == "ready"


def test_fenced_metadata_examples_do_not_block_confirmed_proposal(checkout):
    text = confirmed() + (
        "\n```md\n**Original finding**: AVIT000000000000002\n"
        "**Disposition**: AMBIGUOUS\n**Decision basis**: CONSERVATIVE DEFAULT\n"
        "**Validation status**: UNVERIFIED\n```\n"
    )
    assert assess(checkout, text)["status"] == "ready"


def test_formatted_unverified_status_still_requires_investigation(checkout):
    result = assess(checkout, confirmed() + "\n- **Validation status:** UNVERIFIED\n")
    assert result["status"] == "refine" and result["unverified"] is True
    assert any("still unverified" in issue for issue in result["issues"])


def test_placeholder_section_cannot_borrow_the_next_field(checkout):
    text = re.sub(r"(?m)^\*\*Exploit path\*\*:.*$", "**Exploit path:** unknown", confirmed())
    text = text.replace("**Fix rationale**:", "- **Fix rationale:**")
    result = assess(checkout, text)
    assert result["status"] == "refine"
    assert "Provide substantive Exploit path grounded in the reviewed source" in result["issues"]


def test_untrusted_source_and_prior_report_are_bounded_and_redacted(checkout):
    secret = "synthetic-secret-value-12345678901234567890"
    (checkout / "app.py").write_bytes((SOURCE + f'password = "{secret}"\n').encode("utf-8"))
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
    text = confirmed(patch="").replace("**Confidence**: CONFIRMED", "**Confidence**: PLAUSIBLE\n**Decision basis**: CONSERVATIVE DEFAULT")
    text += "\n**Blocking Evidence**: The deployed route registration is unavailable in this checkout.\n"
    text += "**Resolution Plan**: Inspect the deployment's routing configuration to determine exposure.\n"
    result = assess(checkout, text)
    assert any("deployed route registration is unavailable" in issue for issue in result["issues"])
    assert any("routing configuration" in issue for issue in result["issues"])
    assert not any("patch" in issue.lower() for issue in result["issues"])


def test_prepare_fix_cli_does_not_require_confirmation_or_authentication(checkout, tmp_path, monkeypatch, capsys):
    markdown = tmp_path / "review.md"
    markdown.write_text(confirmed(), encoding="utf-8")
    target = tmp_path / "target.json"
    target.write_text(json.dumps({**TARGET, "avit": AVIT, "file_path": "app.py"}), encoding="utf-8")
    monkeypatch.setattr(avit_cli, "confirm", lambda *_: pytest.fail("Local inspection needs no confirmation"))
    args = SimpleNamespace(number=AVIT, report=str(markdown), checkout=str(checkout), target=str(target))
    assert avit_cli.cmd_prepare_fix(args) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "ready"


def test_prepare_fix_cli_rejects_other_avit_target(checkout, tmp_path):
    markdown = tmp_path / "review.md"
    markdown.write_text(confirmed(), encoding="utf-8")
    target = tmp_path / "target.json"
    target.write_text(json.dumps({**TARGET, "avit": "AVIT000000000000002"}), encoding="utf-8")
    args = SimpleNamespace(number=AVIT, report=str(markdown), checkout=str(checkout), target=str(target))
    with pytest.raises(evidence.ResolveError, match="does not belong"):
        avit_cli.cmd_prepare_fix(args)


def test_prepare_fix_command_dispatches_without_tracker_settings(checkout, tmp_path):
    markdown = tmp_path / "review.md"
    markdown.write_text(confirmed(), encoding="utf-8")
    target = tmp_path / "target.json"
    target.write_text(json.dumps({**TARGET, "avit": AVIT, "file_path": "app.py"}), encoding="utf-8")
    result = subprocess.run([sys.executable, "-c", "from threatlint.cli import main; main()",
                             "avit", "prepare-fix", AVIT, "--report", str(markdown), "--checkout", str(checkout),
                             "--target", str(target), "--aws-profile", "no-authentication-needed"],
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "ready"


@pytest.mark.parametrize("heading", [
    "**Evidence (checkout abc1234, path prefix svc/)**:",
    "**Evidence (checkout abc1234):**",
    "## Evidence (traced statically)",
    "**Evidence** (checkout `abc1234`; short excerpts, credential values redacted):",
    "**Evidence** (static analysis; **NOT RUN**):",
    "**Evidence** (checkout `abc1234`; paths are relative to `svc/Web/`)",
])
def test_qualified_section_labels_are_read(heading):
    from threatlint.finding_review import report_section
    body = f"{heading}\n`app.py:1-2` passes the caller's value to eval without validation.\n**Exploit path**: caller to eval.\n"
    assert report_section(body, ("Evidence",)).startswith("`app.py:1-2` passes the caller's value")


def test_label_with_extra_words_is_not_mistaken_for_the_section():
    from threatlint.finding_review import report_section
    assert report_section("**Evidence for closure**: not the proof.\n", ("Evidence",)) == ""
    assert report_section("**Evidence (a) (b)**: nested qualifiers are not a label.\n", ("Evidence",)) == ""


def test_qualified_evidence_and_exploit_labels_pass_readiness(checkout):
    text = confirmed().replace("**Evidence**:", "**Evidence (checkout fixture, path prefix ./)**:")
    text = text.replace("**Exploit path**:", "**Exploit path (traced statically, not executed)**:")
    assert assess(checkout, text) == {"status": "ready", "issues": [], "prompt": ""}


def test_qualifier_after_the_bold_label_passes_readiness(checkout):
    # The exact shape a reviewer returned for a live AVIT: the note follows the closing ** and may hold bold text.
    text = confirmed().replace("**Evidence**:", "**Evidence** (checkout `fixture`; short excerpts, credential values redacted):")
    text = text.replace("**Exploit path**:", "**Exploit path** (static analysis; **NOT RUN**):")
    assert assess(checkout, text) == {"status": "ready", "issues": [], "prompt": ""}


def test_labelled_list_under_a_section_label_stays_in_that_section():
    from threatlint.finding_review import report_section
    body = ("**Exploit path** (static analysis; **NOT RUN**):\n"
            "- **Entry:** An anonymous client sends value to the handler (app.py:1).\n"
            "- **Execution:** The value reaches eval at app.py:2.\n"
            "\n"
            "**Bypass variants considered:**\n- quoting\n"
            "**Assessment and alternative interpretation**: a separate report field.\n")
    section = report_section(body, ("Exploit path",))
    assert section.startswith("- **Entry:** An anonymous client") and "**Execution:** The value reaches eval" in section
    assert "Bypass variants considered" in section, "an unknown sub-label stays in the section"
    assert "separate report field" not in section, "a known report field ends the section"


def test_paragraph_then_sub_labelled_points_stay_in_a_line_ending_section():
    from threatlint.finding_review import report_section
    body = ("**Finding and impact**\n"
            "The handler formats the request value into SQL.\n"
            "- **Source**: model binding fills value from the query string.\n"
            "- **Impact**: an attacker can read and change ledger rows.\n"
            "**Evidence**: `app.py:2`\n")
    section = report_section(body, ("Finding and impact",))
    assert section.startswith("The handler formats") and "an attacker can read and change ledger rows" in section
    assert "app.py:2" not in section


def test_sibling_bullet_fields_still_end_a_bulleted_label():
    from threatlint.finding_review import report_section
    body = ("- **Evidence**:\n"
            "  - `app.py:2` passes the value to eval.\n"
            "- **Exploit path**: The caller reaches eval.\n")
    assert report_section(body, ("Evidence",)) == "- `app.py:2` passes the value to eval."
    assert report_section(body, ("Exploit path",)) == "The caller reaches eval."
    assert report_section("- **Evidence**:\n- **Exploit path**: x\n", ("Evidence",)) == ""


def test_live_report_shape_with_labelled_exploit_list_passes_readiness(checkout):
    text = confirmed().replace(
        "**Exploit path**: The caller controls value, which reaches eval at app.py:2 without a guard and can execute an expression.",
        "**Exploit path** (static analysis; **NOT RUN**):\n"
        "- **Entry:** The caller supplies value to parse (app.py:1).\n"
        "- **Execution:** value reaches eval at app.py:2 without a guard and can execute an expression.\n")
    text = text.replace("**Evidence**:", "**Evidence** (checkout `fixture`; short excerpts):")
    assert assess(checkout, text) == {"status": "ready", "issues": [], "prompt": ""}


@pytest.mark.parametrize(("stated", "expected"), [
    ("CONFIRMED.", "CONFIRMED"), ("CONFIRMED (static path only; no exploit was run)", "CONFIRMED"),
    ("CONFIRMED, static proof", "CONFIRMED"), ("PLAUSIBLE.", "PLAUSIBLE"), ("Not confirmed.", "Not"),
])
def test_confidence_ignores_trailing_punctuation_and_notes(stated, expected):
    from threatlint.avit_report import verdict_for
    text = confirmed().replace("**Confidence**: CONFIRMED", f"**Confidence**: {stated}")
    assert verdict_for(text, AVIT)["confidence"] == expected


def test_confirmed_with_a_full_stop_is_not_treated_as_unverified(checkout):
    assert assess(checkout, confirmed().replace("**Confidence**: CONFIRMED", "**Confidence**: CONFIRMED.")) == {
        "status": "ready", "issues": [], "prompt": ""}


def test_label_note_without_a_colon_passes_readiness(checkout):
    # The shape a reviewer returned for a live AVIT: the note ends the line and no colon follows.
    text = confirmed().replace("**Evidence**: `app.py:1-2`", "**Evidence** (checkout `fixture`; paths are relative to the repository root)\n`app.py:1-2`")
    assert assess(checkout, text) == {"status": "ready", "issues": [], "prompt": ""}
