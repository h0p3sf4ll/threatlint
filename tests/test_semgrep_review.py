"""Local report tuning must preserve FP/TP proof and must never publish."""

from pathlib import Path

import pytest

from threatlint import semgrep_platform as sp, semgrep_review as review


def report(*, rule="python.synthetic", location="example.py:2", disposition="FALSE POSITIVE"):
    return f"""# Finding Review: example
#### [FP-001] — Literal-only query
**Original finding**: SG-001; {rule}; Semgrep; example.py:2
**Disposition**: {disposition}
**Evidence**: example.py:2 — a quoted literal reaches execute.
**Verified Safe Behavior**: The argument is constant on every caller path, disproving the injection claim.
**Semgrep rule**: {rule}
**Location**: {location}
**Tuned rule**:
```yaml
rules:
  - id: {rule}.tuned
    languages: [python]
    severity: ERROR
    message: synthetic
    pattern: unsafe($X)
```
**Tuned rule fixtures**:
```python
# ruleid: {rule}.tuned
unsafe(value)
# ok: {rule}.tuned
safe('constant')
```
"""


@pytest.fixture
def setup(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "example.py").write_text("# test\nexecute('literal')\n")
    monkeypatch.setattr(sp, "resolve_token", lambda profile: ("synthetic-token", "native settings"))
    monkeypatch.setattr(sp, "engine_flags", lambda engine: ["--pro"], raising=False)
    monkeypatch.setattr(sp, "publish", lambda *args: pytest.fail("local tuning must not publish"))
    monkeypatch.setattr(sp, "call", lambda *args, **kwargs: pytest.fail("local tuning must not change cloud policies"))
    calls = []
    def validate(*args):
        calls.append(args)
        return {"fixtures": True, "original_checked": True, "reproduced": True, "dropped": True}
    monkeypatch.setattr(sp, "validate_tuned_rule", validate)
    return repo, tmp_path / "bundle", calls


def test_local_bundle_proves_each_location_without_cloud_mutation(setup):
    repo, output, calls = setup
    result = review.tune_report(report(), repo, output)
    assert result["complete"] and result["cloud_upload"] is False
    assert result["findings"][0]["status"] == "VALIDATED LOCALLY"
    assert (output / result["rules"][0]["file"]).is_file()
    assert calls[0][2:4] == (str(repo / "example.py"), 2)
    manifest = (output / "tuning-manifest.json").read_text()
    assert "synthetic-token" not in manifest
    assert "no cloud policies were changed" in manifest


@pytest.mark.parametrize("location", ["../outside.py:2", "/etc/passwd:2", "example.py:0", "example.py"])
def test_invalid_location_blocks_tuning(setup, location):
    repo, output, calls = setup
    result = review.tune_report(report(location=location), repo, output)
    assert not result["complete"] and not result["rules"] and not calls
    assert result["findings"][0]["status"] == "BLOCKED"


def test_missing_proof_does_not_become_success_or_publish(setup, monkeypatch):
    repo, output, _ = setup
    monkeypatch.setattr(sp, "validate_tuned_rule", lambda *args: {"fixtures": True, "original_checked": True,
                                                               "reproduced": False, "dropped": None})
    result = review.tune_report(report(), repo, output)
    assert not result["complete"] and not list(output.glob("*.yaml"))
    assert "reproduce" in result["findings"][0]["reason"]


def test_multiple_fp_locations_share_one_cumulative_rule(setup):
    repo, output, calls = setup
    markdown = report() + report().replace("FP-001", "FP-002")
    result = review.tune_report(markdown, repo, output)
    assert result["complete"] and len(calls) == 2 and len(result["rules"]) == 1
    assert len(result["findings"]) == 2


def test_conflicting_replacements_are_blocked_instead_of_reintroducing_other_fps(setup):
    repo, output, calls = setup
    markdown = report() + report().replace("FP-001", "FP-002").replace("pattern: unsafe($X)", "pattern: other($X)")
    result = review.tune_report(markdown, repo, output)
    assert not result["complete"] and not calls and not result["rules"]
    assert all(row["status"] == "BLOCKED" for row in result["findings"])


@pytest.mark.parametrize("disposition", ["TRUE POSITIVE", "AMBIGUOUS"])
def test_true_and_legacy_uncertain_findings_never_get_tuned(setup, disposition):
    repo, output, calls = setup
    result = review.tune_report(report(disposition=disposition), repo, output)
    assert not calls and not result["findings"] and not result["rules"]


def test_cli_exposes_local_tuning_without_publish_option():
    from threatlint.cli import build_parser
    args = build_parser().parse_args(["semgrep", "tune-report", "--report", "review.md", "--repo", ".", "--output-dir", "bundle"])
    assert args.semgrep_command == "tune-report"
    assert not hasattr(args, "publish")


def test_runner_records_blocked_tuning_and_returns_incomplete(setup, monkeypatch):
    repo, output, _ = setup
    monkeypatch.setattr(sp, "validate_tuned_rule", lambda *args: (_ for _ in ()).throw(sp.SemgrepError("TP fixture was lost")))
    text, complete = review.finish_review(report(), repo, output)
    assert complete is False
    assert "| FP-001 | BLOCKED | TP fixture was lost |" in text
    assert "**Disposition**: FALSE POSITIVE" in text  # Tuning failure does not rewrite a proved verdict.


def test_rule_context_fetches_only_semgrep_rules_and_never_publishes(tmp_path, monkeypatch):
    import json
    source = tmp_path / "scan.sarif"
    source.write_text(json.dumps({"runs": [
        {"tool": {"driver": {"name": "Semgrep"}}, "results": [{"ruleId": "python.safe"}, {"ruleId": "python.safe"}]},
        {"tool": {"driver": {"name": "Other"}}, "results": [{"ruleId": "other.rule"}]},
    ]}))
    calls = []
    monkeypatch.setattr(sp, "resolve_token", lambda: ("synthetic", "native"))
    monkeypatch.setattr(sp, "original_rule_yaml", lambda rule, token: calls.append(rule) or "rules: synthetic")
    context = review.rule_context(source)
    assert calls == ["python.safe"]
    assert "UNTRUSTED EVIDENCE" in context and "rules: synthetic" in context


def test_generic_semgrep_fp_missing_tuning_is_rejected_before_tracker_write(tmp_path):
    from types import SimpleNamespace
    from threatlint.integrations.findings_management.base import FindingsManagementPlatform
    from threatlint.integrations.common import IntegrationError
    platform = FindingsManagementPlatform()
    item = {"context": {"finding_source": "Semgrep", "finding_type": "sast", "rule": "python.synthetic", "file_path": "example.py"}}
    with pytest.raises(IntegrationError, match="checkout"):
        platform.before_resolve(item, {"disposition": "FALSE POSITIVE"}, report(), SimpleNamespace())
