import json
import types

import pytest

from threatlint import ado_login, aws_login, org_config, parameter_store, semgrep_platform, servicenow, setup_wizard


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    monkeypatch.setenv("SEMGREP_SETTINGS_FILE", str(tmp_path / "native-semgrep.yml"))
    for name in (*org_config.ENV.values(), *ado_login.ENV_NAMES, "SEMGREP_APP_TOKEN",
                 "THREATLINT_SNOW_CLIENT_ID", "THREATLINT_SNOW_CLIENT_SECRET"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(ado_login, "_keyring", lambda: None)
    monkeypatch.setattr(semgrep_platform, "_keyring", lambda: None)


def _args(**kw):
    return types.SimpleNamespace(**{"aws_profile": "appsec", "check": True, "json": False, **kw})


def test_check_lists_every_missing_credential_with_its_fix(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    for name in (*ado_login.ENV_NAMES, "SEMGREP_APP_TOKEN", "THREATLINT_SNOW_CLIENT_ID", "THREATLINT_SNOW_CLIENT_SECRET"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(ado_login, "_keyring", lambda: None)
    monkeypatch.setattr(semgrep_platform, "parameter_store_token", lambda profile=None: "")
    assert setup_wizard.cmd_setup(_args()) == 1
    out = capsys.readouterr().out
    assert "✗ ServiceNow OAuth client" in out and "threatlint ado login" in out and "threatlint semgrep login" in out


def test_check_passes_and_never_prints_values(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    (tmp_path / "servicenow.json").write_text(json.dumps({"instance": "https://x.service-now.com", "clientId": "id", "clientSecret": "s3cret-value"}), encoding="utf-8")
    monkeypatch.setenv("THREATLINT_ADO_PAT", "p" * 52)
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "t" * 64)
    assert setup_wizard.cmd_setup(types.SimpleNamespace(aws_profile="appsec", check=True, json=True)) == 0
    out = capsys.readouterr().out
    assert all(item["configured"] for item in json.loads(out))
    assert "s3cret" not in out and "p" * 52 not in out and "t" * 64 not in out


def test_failed_aws_signin_stops_before_any_integration_prompts(monkeypatch, capsys):
    monkeypatch.setattr(setup_wizard.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(aws_login, "existing_profile", lambda _profile: None)
    monkeypatch.setattr(setup_wizard, "_yes", lambda _question: True)
    monkeypatch.setattr(aws_login, "cmd_aws", lambda _args: 1)
    monkeypatch.setattr("builtins.input", lambda _prompt: pytest.fail("No dependent prompt after AWS failure"))
    monkeypatch.setattr(setup_wizard, "check", lambda *_: pytest.fail("No credential lookups after AWS failure"))
    assert setup_wizard.cmd_setup(_args(check=False)) == 1
    assert "AWS sign-in failed" in capsys.readouterr().err


def test_failed_shared_settings_lookup_stops_setup(monkeypatch, capsys):
    monkeypatch.setattr(setup_wizard.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(setup_wizard, "step_aws", lambda _profile: True)
    monkeypatch.setattr(org_config, "bootstrap", lambda *a, **k: (_ for _ in ()).throw(
        parameter_store.ParameterStoreError("AccessDeniedException: check access")))
    monkeypatch.setattr("builtins.input", lambda _prompt: pytest.fail("No manual secret fallback"))
    assert setup_wizard.cmd_setup(_args(check=False, org_parameter="/example/setup")) == 1
    assert "AccessDeniedException" in capsys.readouterr().err


def test_invalid_parameter_is_rejected_before_signin(monkeypatch, capsys):
    monkeypatch.setattr(setup_wizard, "step_aws", lambda *_: pytest.fail("Invalid references must not start sign-in"))
    assert setup_wizard.cmd_setup(_args(check=False, org_parameter="--debug")) == 1
    assert "Invalid Parameter Store name" in capsys.readouterr().err


def test_check_honors_explicit_region_without_importing(monkeypatch):
    seen = []
    monkeypatch.setattr(setup_wizard, "cmd_check", lambda _args: seen.append(org_config.aws_region()) or 0)
    assert setup_wizard.cmd_setup(_args(aws_region="eu-west-1")) == 0
    assert seen == ["eu-west-1"]


def test_configured_servicenow_failure_never_prompts_for_secrets(monkeypatch):
    monkeypatch.setenv("THREATLINT_SNOW_CLIENT_ID_PARAMETER", "/example/client-id")
    monkeypatch.setenv("THREATLINT_SNOW_CLIENT_SECRET_PARAMETER", "/example/client-secret")
    monkeypatch.setattr(servicenow, "read_parameter_store", lambda _profile: (_ for _ in ()).throw(
        servicenow.ServiceNowError("AWS SSO session has expired")))
    monkeypatch.setattr("builtins.input", lambda _prompt: pytest.fail("Configured SSM must not fall back to input"))
    monkeypatch.setattr(setup_wizard.getpass, "getpass", lambda _prompt: pytest.fail("No secret prompt"))
    with pytest.raises(servicenow.ServiceNowError, match="expired"):
        setup_wizard.step_servicenow("appsec")


def test_servicenow_uses_environment_url_and_credentials_without_prompting(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("THREATLINT_SNOW_INSTANCE", "https://example.service-now.com")
    monkeypatch.setenv("THREATLINT_SNOW_CLIENT_ID", "synthetic-client")
    monkeypatch.setenv("THREATLINT_SNOW_CLIENT_SECRET", "synthetic-secret")
    calls = []
    monkeypatch.setattr(servicenow, "access_token", lambda *args: calls.append(args) or "token")
    monkeypatch.setattr("builtins.input", lambda _prompt: pytest.fail("Existing configuration needs no prompts"))
    setup_wizard.step_servicenow("appsec")
    assert calls == [("https://example.service-now.com", "synthetic-client", "synthetic-secret")]
    assert json.loads((tmp_path / "servicenow.json").read_text())["instance"] == "https://example.service-now.com"
    out = capsys.readouterr().out
    assert "synthetic-client" not in out and "synthetic-secret" not in out


def test_shared_parameter_bootstraps_fresh_setup_without_credential_prompts(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(setup_wizard.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(setup_wizard, "step_aws", lambda _profile: True)
    monkeypatch.setattr(setup_wizard, "step_github", lambda: None)
    monkeypatch.setattr("builtins.input", lambda _prompt: pytest.fail("Shared settings should supply all required fields"))
    monkeypatch.setattr(setup_wizard.getpass, "getpass", lambda _prompt: pytest.fail("No manual secrets"))
    metadata = {"snowInstance": "https://example.service-now.com", "snowClientIdParameter": "/example/client-id",
                "snowClientSecretParameter": "/example/client-secret", "adoOrganizations": ["example"],
                "adoPatParameter": "/example/ado", "semgrepTokenParameter": "/example/semgrep"}
    lookups = []

    def read(name, profile=None, region=None):
        lookups.append((name, profile, region))
        return {"/example/setup": json.dumps(metadata), "/example/ado": "synthetic-ado-token",
                "/example/semgrep": "synthetic-semgrep-token-12345"}[name]

    monkeypatch.setattr(parameter_store, "read_parameter", read)
    snow_calls = []

    def snow_read(profile):
        assert servicenow.client_parameters() == ("/example/client-id", "/example/client-secret")
        assert profile == "appsec" and org_config.aws_region() == "eu-west-1"
        return "synthetic-client", "synthetic-secret"

    monkeypatch.setattr(servicenow, "read_parameter_store", snow_read)
    monkeypatch.setattr(servicenow, "access_token", lambda *args: snow_calls.append(args) or "token")
    ado_calls = []
    monkeypatch.setattr(ado_login, "validate", lambda *args: ado_calls.append(args))
    monkeypatch.setattr(semgrep_platform, "deployment", lambda *_: {"id": 1, "name": "example"})
    assert setup_wizard.cmd_setup(_args(check=False, org_parameter="/example/setup", aws_region="eu-west-1")) == 0
    assert snow_calls == [("https://example.service-now.com", "synthetic-client", "synthetic-secret")]
    assert ado_calls == [("example", "synthetic-ado-token")]
    assert ado_login.load("example")[0] == "synthetic-ado-token"
    assert semgrep_platform.saved_token()[0] == "synthetic-semgrep-token-12345"
    assert [item[0] for item in lookups] == ["/example/setup", "/example/ado", "/example/semgrep"]
    output = capsys.readouterr()
    assert "Setup complete" in output.out
    for secret in ("synthetic-client", "synthetic-secret", "synthetic-ado-token", "synthetic-semgrep-token-12345"):
        assert secret not in output.out + output.err
        assert secret not in (tmp_path / "org.json").read_text()


def test_setup_check_accepts_configured_ssm_without_saving(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("THREATLINT_SNOW_INSTANCE", "https://example.service-now.com")
    monkeypatch.setenv("THREATLINT_SNOW_CLIENT_ID_PARAMETER", "/example/client-id")
    monkeypatch.setenv("THREATLINT_SNOW_CLIENT_SECRET_PARAMETER", "/example/client-secret")
    monkeypatch.setenv("THREATLINT_ADO_PAT", "synthetic-ado-token")
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "synthetic-semgrep-token")
    monkeypatch.setattr(servicenow, "read_parameter_store", lambda _profile: ("synthetic-client", "synthetic-secret"))
    monkeypatch.setattr(org_config, "bootstrap", lambda *a, **k: pytest.fail("--check must not import or save settings"))
    monkeypatch.setattr("builtins.input", lambda _prompt: pytest.fail("--check must not prompt"))
    assert setup_wizard.cmd_setup(_args(json=True, org_parameter="/example/setup")) == 0
    output = capsys.readouterr().out
    assert "AWS Parameter Store" in output
    assert not (tmp_path / "servicenow.json").exists() and not org_config.path().exists()
    assert "synthetic" not in output


def test_ado_shared_pat_is_validated_for_every_missing_organization(monkeypatch):
    monkeypatch.setenv("THREATLINT_ADO_ORGANIZATIONS", "first,second")
    monkeypatch.setenv("THREATLINT_ADO_PAT_PARAMETER", "/example/ado")
    monkeypatch.setattr(parameter_store, "read_parameter", lambda *a, **k: "synthetic-pat")
    calls = []
    monkeypatch.setattr(ado_login, "validate", lambda organization, _pat: calls.append(("validate", organization)))
    monkeypatch.setattr(ado_login, "save", lambda organization, _pat: calls.append(("save", organization)) or "store")
    setup_wizard.step_ado("appsec")
    assert calls == [("validate", "first"), ("validate", "second"), ("save", "first"), ("save", "second")]


def test_ado_check_does_not_use_an_unrelated_saved_organization(monkeypatch):
    monkeypatch.setenv("THREATLINT_ADO_ORGANIZATIONS", "first,second")
    monkeypatch.setattr(ado_login, "load", lambda organization="": ("synthetic-pat", "store") if organization != "second" else ("", ""))
    assert next(source for name, source, _ in setup_wizard.check("appsec") if name == "Azure DevOps PAT") == ""


def test_semgrep_environment_token_is_passed_to_login(monkeypatch):
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "synthetic-semgrep-token")
    calls = []
    monkeypatch.setattr(semgrep_platform, "login", lambda **kwargs: calls.append(kwargs) or "store")
    setup_wizard.step_semgrep("appsec")
    assert calls == [{"token": "synthetic-semgrep-token", "profile": "appsec"}]


def test_semgrep_configured_parameter_failure_does_not_prompt(monkeypatch):
    monkeypatch.setenv("THREATLINT_SEMGREP_TOKEN_PARAMETER", "/example/semgrep")
    monkeypatch.setattr(semgrep_platform, "parameter_store_token", lambda _profile: (_ for _ in ()).throw(
        semgrep_platform.SemgrepError("AccessDeniedException")))
    monkeypatch.setattr(semgrep_platform, "login", lambda **kwargs: pytest.fail("No prompt fallback after access denied"))
    with pytest.raises(semgrep_platform.SemgrepError, match="AccessDeniedException"):
        setup_wizard.step_semgrep("appsec")
