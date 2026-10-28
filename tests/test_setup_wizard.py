import json
import types

from threatlint import ado_login, semgrep_platform, setup_wizard


def _args(**kw):
    return types.SimpleNamespace(aws_profile="appsec", check=True, json=False, **kw)


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
