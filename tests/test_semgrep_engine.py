"""Local engine boundaries retain original scanner and environment seams."""

import json
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
