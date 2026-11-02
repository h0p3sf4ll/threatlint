"""Local engine boundaries retain original scanner and environment seams."""

import json
from types import SimpleNamespace

import pytest

from threatlint import semgrep_platform as sp


@pytest.mark.parametrize(
    ("line", "exact", "expected"),
    [(None, False, [6, 10, 13, 14]), (10, False, [10, 13]), (10, True, [10])],
)
def test_scan_matching_uses_the_original_engine_and_pro_flag_seams(monkeypatch, line, exact, expected):
    calls = []
    monkeypatch.setattr(sp, "_pro_flags", lambda: ["--pro"])
    result = SimpleNamespace(stdout=json.dumps({"results": [{"start": {"line": n}} for n in [6, 10, 13, 14]]}))
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
    }


def test_invalid_scan_json_uses_the_original_public_error_class(monkeypatch):
    monkeypatch.setattr(sp, "_pro_flags", lambda: [])
    monkeypatch.setattr(sp, "_semgrep", lambda args: SimpleNamespace(stdout="invalid", stderr="synthetic failure"))
    with pytest.raises(sp.SemgrepError, match="synthetic failure"):
        sp._matches("synthetic.yaml", "synthetic.py", None)
