"""The Workbench preflight validates the exact draft before external write-back."""

import json
from pathlib import Path

import pytest

from threatlint import avit_cli, avit_resolve, cli, semgrep_platform as sp

AVIT = "AVIT0001234"
HEADER = f"""#### [FP-001] — Literal example
**Original finding**: {AVIT}; demo.literal; Semgrep Code; src.py:1
**Disposition**: FALSE POSITIVE
**Evidence**: `src.py:1` passes the documented literal.
**Verified Safe Behavior**: The flagged call only passes the approved literal.
"""
RULE = """**Tuned rule**:
```yaml
rules:
  - id: demo.literal.tuned
    pattern: "log($VALUE)"
```
"""
FIXTURES = """**Tuned rule fixtures**:
```python
# ruleid: demo.literal.tuned
log(value)
# ok: demo.literal.tuned
log("example")
```
"""


@pytest.fixture
def check(tmp_path, monkeypatch, capsys):
    flagged = tmp_path / "src.py"
    flagged.write_text('log("example")\n')
    base = tmp_path / "base.yaml"
    report = tmp_path / "report.md"
    target = tmp_path / "target.json"
    monkeypatch.setattr(avit_resolve, "_session", lambda *_: pytest.fail("Preflight cannot access ServiceNow"))
    monkeypatch.setattr(sp, "publish", lambda *_: pytest.fail("Preflight cannot publish rules"))

    def run(markdown=HEADER + RULE, *, live=False, omit_base=False, **target_fields):
        base.write_text(("# Tuning base: live tuned rule org.demo.literal.tuned" if live else "# Tuning base: original rule demo.literal")
                        + "\nrules:\n  - id: demo.literal\n")
        report.write_text(markdown, encoding="utf-8")  # reports are UTF-8; Windows' default is cp1252
        target.write_text(json.dumps({"avit": AVIT, "kind": "sast", "rule": "demo.literal",
                                     "line": "1", "file_path": "src.py", **target_fields}))
        params = ["avit", "prepare-tuning", AVIT, "--report", str(report), "--checkout", str(tmp_path),
                  "--target", str(target), "--aws-profile", "test"]
        if not omit_base:
            params.extend(["--rule-base", str(base)])
        assert avit_cli.cmd_prepare_tuning(cli.build_parser().parse_args(params)) == 0
        return json.loads(capsys.readouterr().out)

    return run


def test_missing_fixtures_are_repairable_before_proof(check, monkeypatch):
    monkeypatch.setattr(avit_resolve, "semgrep_token", lambda *_: pytest.fail("Missing fixtures are detectable locally"))
    result = check()
    assert result["status"] == "refine" and result["disposition"] == "FALSE POSITIVE"
    assert "fixtures" in result["reason"]
    assert check(HEADER + RULE + FIXTURES.replace("ok: demo", "ok: other"))["status"] == "refine"


def test_preflight_requires_executed_proof(check, monkeypatch):
    monkeypatch.setattr(avit_resolve, "semgrep_token", lambda profile: profile)
    checked = []
    def validate(rule, original, source, line, fixtures, token, **kwargs):
        checked.append((rule, original, source, line, fixtures, token))
    monkeypatch.setattr(sp, "validate_tuned_rule", validate)
    assert check(HEADER + RULE + FIXTURES)["status"] == "ready"
    (rule, original, source, line, fixtures, token), = checked
    assert original == "demo.literal" and "demo.literal.tuned" in rule
    assert line == 1 and Path(source).name == "src.py" and token == "test"
    assert "# ok: demo.literal.tuned" in fixtures

    def unavailable(*_args, **_kwargs):
        raise sp.SemgrepError("Matching Semgrep Pro engine is unavailable")
    monkeypatch.setattr(sp, "validate_tuned_rule", unavailable)
    assert check(HEADER + RULE + FIXTURES)["status"] == "blocked"


def test_live_rule_only_suffices_if_it_clears_the_exact_flagged_line(check, monkeypatch):
    calls = []
    def covered(rule, source, line, *, exact):
        calls.append((rule, source, line, exact))
        return []
    monkeypatch.setattr(sp, "_matches", covered)
    assert check(live=True)["status"] == "ready"
    assert calls[0][2:] == (1, True)
    monkeypatch.setattr(sp, "_matches", lambda *_args, **_kwargs: [1])
    assert check(live=True)["status"] == "refine"


def test_preflight_distinguishes_inapplicable_and_inaccessible_targets(check):
    assert check(HEADER.replace("FALSE POSITIVE", "TRUE POSITIVE"), omit_base=True)["status"] == "skipped"
    assert check(kind="sca", omit_base=True)["status"] == "skipped"
    assert check(code_security=False, omit_base=True)["status"] == "skipped"
    assert check(kind="sca", branch_deleted="deleted", omit_base=True)["status"] == "blocked"
    assert check(omit_base=True)["status"] == "blocked"
    assert check(HEADER + RULE + FIXTURES, file_path="../outside.py")["status"] == "blocked"


def test_line_blocker_precedes_fixture_refinement(check):
    reason = "The scanner snippet occurs more than once in the flagged file."
    result = check(line="", line_blocker=reason)
    assert result["status"] == "blocked" and result["reason"] == reason


def test_live_rule_with_an_inferred_line_needs_a_reproducible_original_or_fixture_proof(check, monkeypatch):
    monkeypatch.setattr(avit_resolve, "semgrep_token", lambda _: "test-token")
    monkeypatch.setattr(sp, "_matches", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(sp, "original_rule_yaml", lambda *_args: "original")
    monkeypatch.setattr(sp, "live_rule_matches", lambda *_args: [])
    assert check(live=True, line_source="scanner_snippet")["status"] == "refine"
    monkeypatch.setattr(sp, "live_rule_matches", lambda *_args: [1])
    assert check(live=True, line_source="scanner_snippet")["status"] == "ready"
