"""Local engine boundaries retain original scanner and environment seams."""

import json
import os
import shutil
from types import SimpleNamespace

import pytest

from threatlint import semgrep_platform as sp
from threatlint import semgrep_engine as engine


@pytest.mark.parametrize(
    ("line", "exact", "expected"),
    [(None, False, [6, 10, 13, 14]), (10, False, [10, 13]), (10, True, [10])],
)
def test_scan_matching_uses_the_original_engine_and_pro_flag_seams(monkeypatch, line, exact, expected):
    calls = []
    monkeypatch.setattr(sp, "_pro_flags", lambda: ["--pro"])
    result = SimpleNamespace(returncode=0, stdout=json.dumps({"results": [{"start": {"line": n}} for n in [6, 10, 13, 14]]}))
    monkeypatch.setattr(sp, "_semgrep", lambda args: calls.append(args) or result)
    assert sp._matches("synthetic.yaml", "synthetic.py", line, exact) == expected
    assert "--pro" in calls[0]


def test_engine_execution_keeps_original_environment_and_process_seams(monkeypatch):
    monkeypatch.setattr(sp.shutil, "which", lambda name: "/synthetic/semgrep")
    monkeypatch.setattr(sp, "tool_env", lambda: {"AWS_CA_BUNDLE": "synthetic-ca"})
    seen = []
    monkeypatch.setattr(sp.subprocess, "run", lambda command, **kwargs: seen.append((command, kwargs)) or "done")
    assert sp._semgrep(["--validate"], token="synthetic") == "done"
    command, kwargs = seen[0]
    assert command == ["/synthetic/semgrep", "--validate"]
    assert kwargs["env"] == {
        "AWS_CA_BUNDLE": "synthetic-ca", "REQUESTS_CA_BUNDLE": "synthetic-ca",
        "SEMGREP_SEND_METRICS": "off", "SEMGREP_APP_TOKEN": "synthetic",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
    }


def test_invalid_tuning_pattern_returns_its_yaml_location_without_echoing_source(tmp_path, monkeypatch):
    from threatlint.avit_tuning import repairable_rule_error

    def validate(args):
        assert "--validate" in args and "--json" in args
        error = {"type": ["PatternParseError", ["pattern-not-inside", "0", "patterns"]],
                 "message": "Pattern parse error in rule demo: const token = [REDACTED]\"sha256\"",
                 "spans": [{"config_path": ["rules", "0", "patterns", "0", "pattern-not-inside"]}]}
        return SimpleNamespace(returncode=2, stdout=json.dumps({"errors": [error]}), stderr="Configuration is invalid")

    monkeypatch.setattr(sp, "_semgrep", validate)
    with pytest.raises(sp.SemgrepError) as failed:
        sp.validate_tuned_rule("rules:\n  - id: demo\n", "demo", "fixture.ts", 1, work=tmp_path)
    diagnostic = str(failed.value)
    assert "rules.0.patterns.0.pattern-not-inside" in diagnostic and "$VALUE" in diagnostic
    assert "sha256" not in diagnostic and "[REDACTED]" not in diagnostic
    assert repairable_rule_error(failed.value)


@pytest.mark.parametrize(("message", "advice"), [
    ('Invalid YAML file /temp/synthetic-token.yaml:\nwhile parsing a block mapping\n  in "<file>", line 395, column 9'
     '\nexpected <block end>, but found an item\n  in "<file>", line 398, column 9', "line 395, column 9 and line 398, column 9"),
    ("Rule parse error in rule synthetic-token:\n Must occur directly under a patterns:", "under the same patterns list"),
    ("Rule parse error in rule synthetic-token:\n you cannot negate in an Or; you can only negate inside an And", "under the same patterns list"),
])
def test_invalid_rule_structure_produces_repairable_guidance(message, advice):
    from threatlint.avit_tuning import repairable_rule_error
    result = SimpleNamespace(stdout=json.dumps({"errors": [{"message": message}]}), stderr="")
    diagnostic = engine._rule_validation_error(result)
    assert advice in diagnostic and "synthetic-token" not in diagnostic
    assert repairable_rule_error(sp.SemgrepError(diagnostic))


def test_failed_fixture_proof_reports_exact_lines_without_source_or_temp_paths(tmp_path):
    from threatlint.avit_tuning import repairable_rule_error
    rule, fixture = tmp_path / "access-token.tuned.yaml", tmp_path / "access-token.tuned.py"
    checks = {rule.stem: {"passed": False, "matches": {str(fixture): {"expected_lines": [2, 8], "reported_lines": [4, 8, 20]}}}}
    result = SimpleNamespace(returncode=1, stdout=json.dumps({"results": {str(rule): {"checks": checks}}}))
    with pytest.raises(sp.SemgrepError) as failure:
        engine._check_fixture_result(result, rule, fixture, [2, 8], [4], error_type=sp.SemgrepError)
    assert "Missed ruleid lines 2." in str(failure.value)
    assert "Matched ok lines 4." in str(failure.value)
    assert "Matched unmarked lines 20 (ruleid 2, 8, ok 4)." in str(failure.value)
    assert str(tmp_path) not in str(failure.value) and repairable_rule_error(failure.value)


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="requires the Semgrep CLI")
def test_real_semgrep_proves_fixture_repair_keeps_positive_control(tmp_path):
    rule = tmp_path / "fixture-proof.yaml"
    fixture = tmp_path / "fixture-proof.py"
    fixture.write_text("# ruleid: fixture-proof\nrecord(sample(1))\n"
                       "# ok: fixture-proof\nrecord(preview(1))\nrecord(preview(2))\n")

    def prove(pattern):
        rule.write_text("rules:\n  - id: fixture-proof\n    languages: [python]\n    message: Synthetic check\n"
                        f"    severity: INFO\n    pattern: {pattern}\n")
        result = engine.run(["--test", "--json", "--metrics", "off", str(tmp_path)],
                            environment=lambda: {"PATH": os.environ["PATH"],
                                                 "SEMGREP_SETTINGS_FILE": str(tmp_path / ".settings")},
                            error_type=sp.SemgrepError)
        engine._check_fixture_result(result, rule, fixture, [2], [4], error_type=sp.SemgrepError)

    with pytest.raises(sp.SemgrepError) as failure:
        prove("record(preview(...))")
    assert "Missed ruleid lines 2." in str(failure.value)
    assert "Matched ok lines 4." in str(failure.value)
    assert "Matched unmarked lines 5 " in str(failure.value)
    prove("record(sample(...))")


@pytest.mark.parametrize("deferred", ["todook", "todoruleid"])
def test_deferring_an_extra_fixture_match_cannot_make_a_proposal_pass(monkeypatch, tmp_path, deferred):
    def validate(args):
        assert "--validate" in args
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(sp, "_semgrep", validate)
    fixtures = ("# ruleid: r.tuned\nsample(1)\n# ok: r.tuned\npreview(1)\n"
                f"# {deferred}: r.tuned\nsample(2)\n")
    with pytest.raises(sp.SemgrepError, match="deferred test annotations on lines 5"):
        sp.validate_tuned_rule("rules:\n  - id: r.tuned\n", "r", "fixture.py", 1, fixtures, work=tmp_path)


@pytest.mark.parametrize("payload", [
    {"results": {}}, {"config_with_errors": [{"error": "private diagnostic"}], "results": {}},
    {"results": {"unexpected.yaml": {"checks": {}}}},
])
def test_missing_executed_fixture_check_blocks_even_with_zero_exit(tmp_path, payload):
    from threatlint.avit_tuning import repairable_rule_error
    result = SimpleNamespace(returncode=0, stdout=json.dumps(payload))
    with pytest.raises(sp.SemgrepError) as failure:
        engine._check_fixture_result(result, tmp_path / "r.yaml", tmp_path / "r.py", [2], [4], error_type=sp.SemgrepError)
    assert not repairable_rule_error(failure.value) and "private diagnostic" not in str(failure.value)


@pytest.mark.parametrize(("errors", "code"), [(["private diagnostic"], 1), ([], 2)])
def test_partial_fixture_result_does_not_trigger_model_repair(tmp_path, errors, code):
    from threatlint.avit_tuning import repairable_rule_error
    rule, fixture = tmp_path / "r.yaml", tmp_path / "r.py"
    check = {"passed": False, "errors": errors, "matches": {str(fixture): {"expected_lines": [2], "reported_lines": [20]}}}
    result = SimpleNamespace(returncode=code, stdout=json.dumps({"results": {str(rule): {"checks": {"r": check}}}}))
    with pytest.raises(sp.SemgrepError) as failure:
        engine._check_fixture_result(result, rule, fixture, [2], [20], error_type=sp.SemgrepError)
    assert not repairable_rule_error(failure.value) and "private diagnostic" not in str(failure.value)


def test_tuned_match_blocks_even_when_the_original_misses_the_flagged_line(tmp_path):
    target = tmp_path / "target.py"
    target.write_text("observe('fixture')\n")
    original, tuned = tmp_path / "original.yaml", tmp_path / "tuned.yaml"
    def only_tuned_matches(config, path, line, *, exact):
        assert path == target and line == 1 and exact
        return [1] if config == str(tuned) else []

    with pytest.raises(sp.SemgrepError, match="false-positive location at checkout line 1"):
        engine._check_location(original, tuned, target, 1, matches=only_tuned_matches, error_type=sp.SemgrepError)
    result = engine._check_location(original, tuned, target, 1, matches=lambda *a, **kw: [], error_type=sp.SemgrepError)
    assert result == {"reproduced": False, "dropped": None}


def test_invalid_scan_json_uses_the_original_public_error_class(monkeypatch):
    monkeypatch.setattr(sp, "_pro_flags", lambda: [])
    monkeypatch.setattr(sp, "_semgrep", lambda args: SimpleNamespace(returncode=0, stdout="invalid", stderr="synthetic failure"))
    with pytest.raises(sp.SemgrepError, match="synthetic failure"):
        sp._matches("synthetic.yaml", "synthetic.py", None)


@pytest.mark.parametrize("ready", [False, True])
def test_pro_is_explicit_and_never_silently_downgrades(monkeypatch, ready):
    monkeypatch.setattr(sp, "engine_status", lambda: {"cli_version": "1.2.3", "pro_ready": ready})
    if ready:
        assert sp.engine_flags() == ["--pro"]
    else:
        with pytest.raises(sp.SemgrepError, match="no Community Edition fallback"):
            sp.engine_flags()
    assert sp.engine_flags("oss") == ["--oss-only"]


def test_pro_readiness_requires_matching_stamp_and_working_binary(monkeypatch, tmp_path):
    binary = tmp_path / "semgrep-core-proprietary"
    binary.write_text("synthetic executable")
    binary.chmod(0o700)
    stamp = tmp_path / "pro-installed-by.txt"
    monkeypatch.setattr(engine.shutil, "which", lambda _: "/synthetic/semgrep")
    monkeypatch.setattr(engine, "_pro_candidates", lambda _: [binary])
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="1.2.3\n", stderr="")
    monkeypatch.setattr(engine.subprocess, "run", run)
    assert engine.engine_status(environment=dict)["pro_ready"] is False
    stamp.write_text("0.0.1")
    assert engine.engine_status(environment=dict)["pro_ready"] is False
    stamp.write_text("1.2.3\n")
    assert engine.engine_status(environment=dict)["pro_ready"] is True
    assert calls[-1] == [str(binary), "-pro_version"]


@pytest.mark.parametrize("result", [SimpleNamespace(returncode=2, stdout='{"results": []}'),
                                    SimpleNamespace(returncode=0, stdout='{"errors": [{"message":"failed"}], "results": []}')])
def test_scan_failure_never_looks_like_false_positive_removal(monkeypatch, result):
    monkeypatch.setattr(sp, "_pro_flags", lambda: ["--pro"])
    monkeypatch.setattr(sp, "_semgrep", lambda _: result)
    with pytest.raises(sp.SemgrepError):
        sp._matches("rule.yml", "source.py", 1)


@pytest.mark.parametrize("logged_in,scan_ok", [(False, True), (True, False), (True, True)])
def test_scanner_auto_selection_requires_login_and_successful_pro_execution(monkeypatch, logged_in, scan_ok):
    monkeypatch.setattr(engine, "engine_status", lambda **_: {"cli_version": "1.2", "pro_ready": True})
    monkeypatch.setattr(engine.shutil, "which", lambda _: "/synthetic/semgrep")
    calls = []

    def execute(argv, **kwargs):
        calls.append(argv)
        if "deployment" in argv:
            return SimpleNamespace(returncode=0 if logged_in else 1, stdout='{"id":1}', stderr="")
        return SimpleNamespace(returncode=0 if scan_ok else 2, stdout='{"results":[{"check_id":"threatlint-pro-check"}]}', stderr="")

    monkeypatch.setattr(engine.subprocess, "run", execute)
    status = engine.scanner_status(environment=dict)
    assert status["engine"] == ("pro" if logged_in and scan_ok else "oss")
    assert status["pro_enabled"] is (True if logged_in and scan_ok else None)
    if logged_in:
        assert "--pro" in calls[-1]
