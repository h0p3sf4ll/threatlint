"""ServiceNow AVIT import and the Semgrep prerequisite for FP review. No network or AWS calls."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from threatlint import cli, servicenow
from threatlint.servicenow import ServiceNowError

INSTANCE = "https://example.service-now.com"


def test_avit_numbers_are_normalized_and_bounded():
    assert servicenow.parse_avit_numbers(["avit0001234, AVIT0001235", "AVIT0001234"]) == ["AVIT0001234", "AVIT0001235"]
    with pytest.raises(ServiceNowError, match="Not an AVIT"):
        servicenow.parse_avit_numbers("CVE-2024-0001")
    with pytest.raises(ServiceNowError, match="at most"):
        servicenow.parse_avit_numbers([f"AVIT{i:07d}" for i in range(51)])


@pytest.mark.parametrize("bad", ["http://example.service-now.com", "https://u:p@example.service-now.com",
                                 "https://example.service-now.com/x", "https://service-now.com.attacker.example"])
def test_instance_must_be_a_servicenow_https_origin(bad):
    assert servicenow.validate_instance_url("https://Example.service-now.com/") == INSTANCE
    with pytest.raises(ServiceNowError):
        servicenow.validate_instance_url(bad)


def test_parameter_store_uses_the_aws_cli_and_reports_access_help(monkeypatch):
    calls = []
    monkeypatch.setattr(servicenow.shutil, "which", lambda name: "/usr/bin/aws")

    def fake_run(command, **_kwargs):
        calls.append(command)
        payload = {"Parameters": [{"Name": servicenow.CLIENT_ID_PARAMETER, "Value": "id"},
                                  {"Name": servicenow.CLIENT_SECRET_PARAMETER, "Value": "secret"}]}
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    monkeypatch.setattr(servicenow.subprocess, "run", fake_run)
    assert servicenow.read_parameter_store("appsec") == ("id", "secret")
    assert calls[0][-2:] == ["--profile", "appsec"] and "--with-decryption" in calls[0] and "us-west-2" in calls[0]

    monkeypatch.setattr(servicenow.subprocess, "run",
                        lambda command, **_k: subprocess.CompletedProcess(command, 255, "", "Token has expired"))
    with pytest.raises(ServiceNowError, match="Token has expired") as error:
        servicenow.read_parameter_store()
    assert servicenow.SSO_URL in str(error.value)


def test_avits_become_one_untrusted_findings_artifact(monkeypatch):
    def fake_request(url, *, data=None, headers):
        if url.endswith("/oauth_token.do"):
            assert b"grant_type=client_credentials" in data
            return {"access_token": "token"}
        if "sn_vul_app_vulnerable_item" in url:
            assert headers["Authorization"] == "Bearer token"
            return {"result": [
                {"number": {"display_value": "AVIT0000002"}, "description": {"display_value": "a\nb"}},
                {"number": {"display_value": "AVIT0000001"},
                 "vulnerability": {"display_value": "SSRF", "link": f"{INSTANCE}/api/now/table/sn_vul_app_vulnerability_entry/1"}},
                {"number": {"display_value": "AVIT0000003"},
                 "vulnerability": {"display_value": "x", "link": "https://attacker.example/api/now/table/x/1"}},
            ]}
        assert url.startswith(f"{INSTANCE}/api/now/table/sn_vul_app_vulnerability_entry/1")
        return {"result": {"cwe": "CWE-918"}}

    monkeypatch.setattr(servicenow, "_request_json", fake_request)
    numbers = ["AVIT0000001", "AVIT0000002", "AVIT0000003", "AVIT0000004"]
    content, count, missing = servicenow.load_avits(INSTANCE, numbers, "id", "secret")
    assert (count, missing) == (3, ["AVIT0000004"])
    assert content.index("## AVIT0000001") < content.index("## AVIT0000002")
    assert "CWE-918" in content and "~~~text\na\nb\n~~~" in content and "secret" not in content


def test_redirects_are_not_followed():
    assert servicenow._NoRedirect().redirect_request(None, None, 302, "", {}, "https://elsewhere.example") is None


def _run_args(tmp_path, **overrides):
    values = dict(mode="fp-review", provider="lmstudio", base_url="http://localhost:1234/v1", api_key="", model="m",
                  target="", findings=None, deep=False, base=None, head=None, output_dir=str(tmp_path),
                  avit=[], avit_file=None, snow_instance="", aws_profile=None)
    values.update(overrides)
    return argparse.Namespace(**values)


def test_fp_review_requires_semgrep_before_any_model_request(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "_lmstudio_models", lambda _url: ["m"])
    monkeypatch.setattr(cli, "_semgrep_version", lambda: None)
    monkeypatch.setattr(cli, "_run_agent", lambda *a, **k: pytest.fail("model must not be called"))
    assert cli.cmd_run(_run_args(tmp_path)) == 1
    assert "pip install semgrep" in capsys.readouterr().out


def test_fp_review_with_avits_sends_one_artifact(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_lmstudio_models", lambda _url: ["m"])
    monkeypatch.setattr(cli, "_semgrep_version", lambda: "1.99.0")
    monkeypatch.setattr(servicenow, "resolve_credentials", lambda _profile: ("id", "secret"))
    monkeypatch.setattr(servicenow, "load_avits", lambda instance, numbers, *_: ("## AVIT0000001\n", 1, numbers[1:]))
    captured = {}

    def fake_agent(_base, _model, _system, message, _root, api_key=""):
        captured["message"] = message
        return "# Report\n"

    monkeypatch.setattr(cli, "_run_agent", fake_agent)
    monkeypatch.setattr(cli, "_save_report", lambda *a: tmp_path / "r.md")
    args = _run_args(tmp_path, avit=["AVIT0000001,AVIT0000002"], snow_instance=INSTANCE)
    assert cli.cmd_run(args) == 0
    assert "UNTRUSTED EVIDENCE" in captured["message"] and "AVIT0000001" in captured["message"]
    assert "single cohesive report" in captured["message"] and "1.99.0" in captured["message"]


def test_avits_are_rejected_for_other_modes(tmp_path):
    with pytest.raises(ServiceNowError, match="only supported"):
        cli._load_requested_avits(_run_args(tmp_path, mode="threat-model", avit=["AVIT0000001"]), "threat-model")


def test_avit_fetch_writes_a_findings_file(monkeypatch, tmp_path):
    monkeypatch.setattr(servicenow, "resolve_credentials", lambda _profile: ("id", "secret"))
    monkeypatch.setattr(servicenow, "load_avits", lambda instance, numbers, *_: ("# AVITs\n", 1, []))
    output = tmp_path / "avits.md"
    args = cli.build_parser().parse_args(["avit", "fetch", "AVIT0000001", "--snow-instance", INSTANCE, "-o", str(output)])
    assert servicenow.cmd_avit(args) == 0
    assert output.read_text() == "# AVITs\n"
