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
    assert servicenow.parse_avit_numbers(["avit000000000001234, AVIT000000000001235", "AVIT000000000001234"]) == ["AVIT000000000001234", "AVIT000000000001235"]
    with pytest.raises(ServiceNowError, match="Not an AVIT"):
        servicenow.parse_avit_numbers("CVE-2024-0001")
    with pytest.raises(ServiceNowError, match="at most"):
        servicenow.parse_avit_numbers([f"AVIT{i:015d}" for i in range(51)])


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
        if "/sysrule_view" in url:
            return {"result": [{"condition": "u_scm_toolISNOTEMPTY"}]}
        if "/sys_documentation" in url:
            return {"result": []}
        if "u_scm_toolISNOTEMPTY" in url:
            return {"result": [{"number": number} for number in ("AVIT000000000000001", "AVIT000000000000002", "AVIT000000000000003")]}
        if "sn_vul_app_vulnerable_item" in url:
            assert headers["Authorization"] == "Bearer token"
            return {"result": [
                {"number": {"display_value": "AVIT000000000000002"}, "u_security_finding_source": {"display_value": "SCA"}, "description": {"display_value": "a\nb"}},
                {"number": {"display_value": "AVIT000000000000005"}, "u_security_finding_source": {"display_value": "SAST"}},
                {"number": {"display_value": "AVIT000000000000001"},
                 "vulnerability": {"display_value": "SSRF", "link": f"{INSTANCE}/api/now/table/sn_vul_app_vulnerability_entry/1"}},
                {"number": {"display_value": "AVIT000000000000003"}, "scanner": {"display_value": "Semgrep"},
                 "vulnerability": {"display_value": "x", "link": "https://attacker.example/api/now/table/x/1"}},
            ]}
        assert url.startswith(f"{INSTANCE}/api/now/table/sn_vul_app_vulnerability_entry/1")
        return {"result": {"cwe": "CWE-918", "category": "SAST"}}

    monkeypatch.setattr(servicenow, "_request_json", fake_request)
    numbers = ["AVIT000000000000001", "AVIT000000000000002", "AVIT000000000000003", "AVIT000000000000004", "AVIT000000000000005"]
    content, count, missing, excluded = servicenow.load_avits(INSTANCE, numbers, "id", "client-secret-value")
    assert (count, missing, excluded) == (3, ["AVIT000000000000004"], ["AVIT000000000000005"])
    assert "## AVIT000000000000005" not in content and "Excluded (not in the AVR CodeSecurity view): AVIT000000000000005" in content
    assert content.index("## AVIT000000000000001") < content.index("## AVIT000000000000002")
    assert "CWE-918" in content and "~~~text\na\nb\n~~~" in content and "client-secret-value" not in content


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
    monkeypatch.setattr(servicenow, "load_avits", lambda instance, numbers, *_: ("## AVIT000000000000001\n", 1, numbers[1:], []))
    captured = {}

    def fake_agent(_base, _model, _system, message, _root, api_key=""):
        captured["message"] = message
        return "# Report\n"

    monkeypatch.setattr(cli, "_run_agent", fake_agent)
    monkeypatch.setattr(cli, "_save_report", lambda *a: tmp_path / "r.md")
    args = _run_args(tmp_path, avit=["AVIT000000000000001,AVIT000000000000002"], snow_instance=INSTANCE)
    assert cli.cmd_run(args) == 0
    assert "UNTRUSTED EVIDENCE" in captured["message"] and "AVIT000000000000001" in captured["message"]
    assert "single cohesive report" in captured["message"] and "1.99.0" in captured["message"]


def test_avits_are_rejected_for_other_modes(tmp_path):
    with pytest.raises(ServiceNowError, match="only supported"):
        cli._load_requested_avits(_run_args(tmp_path, mode="threat-model", avit=["AVIT000000000000001"]), "threat-model")


def test_avit_fetch_writes_a_findings_file(monkeypatch, tmp_path):
    monkeypatch.setattr(servicenow, "resolve_credentials", lambda _profile: ("id", "secret"))
    monkeypatch.setattr(servicenow, "load_avits", lambda instance, numbers, *_: ("# AVITs\n", 1, [], []))
    output = tmp_path / "avits.md"
    args = cli.build_parser().parse_args(["avit", "fetch", "AVIT000000000000001", "--snow-instance", INSTANCE, "-o", str(output)])
    assert servicenow.cmd_avit(args) == 0
    assert output.read_text() == "# AVITs\n"


def test_scope_is_the_codesecurity_view_not_the_finding_source(monkeypatch):
    rows = [{"number": {"display_value": "AVIT000000000000009"}, "u_security_finding_source": {"display_value": "Secrets"}},
            {"number": {"display_value": "AVIT000000000000008"}, "u_security_finding_source": {"display_value": "SCA"},
             "u_scm_tool": {"display_value": "ADO"}, "u_repository": {"display_value": "askada-frontend"}}]
    def fake_request(url, *, data=None, headers):
        if url.endswith("/oauth_token.do"):
            return {"access_token": "token"}
        if "/sysrule_view" in url or "/sys_documentation" in url:
            return {"result": []}
        return {"result": rows}
    monkeypatch.setattr(servicenow, "_request_json", fake_request)
    # No readable view rule: the CodeSecurity view's SCM fields decide; finding source is irrelevant.
    _content, count, _missing, excluded = servicenow.load_avits(INSTANCE, ["AVIT000000000000008", "AVIT000000000000009"], "id", "secret")
    assert (count, excluded) == (1, ["AVIT000000000000009"])
    rows.pop()
    with pytest.raises(servicenow.ServiceNowError, match="CodeSecurity view"):
        servicenow.load_avits(INSTANCE, ["AVIT000000000000009"], "id", "secret")


def test_saved_workbench_config_supplies_instance_and_keys(monkeypatch, tmp_path):
    import json as _json
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    monkeypatch.delenv(servicenow.CLIENT_ID_ENV, raising=False)
    monkeypatch.delenv(servicenow.CLIENT_SECRET_ENV, raising=False)
    (tmp_path / "servicenow.json").write_text(_json.dumps({"instance": INSTANCE, "clientId": "saved-id", "clientSecret": "saved-secret"}))
    monkeypatch.setattr(servicenow, "read_parameter_store", lambda _p: pytest.fail("saved config should be used first"))
    assert servicenow.resolve_credentials() == ("saved-id", "saved-secret")
    assert servicenow.saved_config()["instance"] == INSTANCE
