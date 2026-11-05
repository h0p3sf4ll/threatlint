"""threatlint ado login: PAT validation, storage, and precedence for AVIT checkouts."""

import io
import json
import os
import stat
import types
import urllib.error

import pytest

from threatlint import ado_login, cli, org_config, parameter_store, servicenow

PAT = "a" * 52


class Response(io.BytesIO):
    def __init__(self, body, status=200):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path / "home"))
    for name in (*ado_login.ENV_NAMES, *org_config.ENV.values()):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(ado_login, "_keyring", lambda: None)


def test_pat_is_validated_against_the_organization():
    seen = {}
    ado_login.validate("contoso", PAT, opener=lambda request, timeout: seen.update(url=request.full_url, auth=request.headers["Authorization"]) or Response(b'{"count":1}'))
    assert seen["url"].startswith("https://dev.azure.com/contoso/_apis/projects")
    with pytest.raises(ado_login.AdoLoginError, match="did not accept"):
        ado_login.validate("contoso", PAT, opener=lambda *_a, **_k: Response(b"<html>sign in</html>", 203))
    def denied(*_a, **_k):
        raise urllib.error.HTTPError("u", 401, "x", {}, None)
    with pytest.raises(ado_login.AdoLoginError, match="invalid or expired"):
        ado_login.validate("contoso", PAT, opener=denied)
    with pytest.raises(ado_login.AdoLoginError, match="not a URL"):
        ado_login.validate("https://dev.azure.com/contoso", PAT)


def test_saved_pat_is_private_and_used_for_ado_clones(monkeypatch):
    where = ado_login.save("contoso", PAT)
    path = ado_login.store_path()
    assert where == str(path)
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert ado_login.load() == (PAT, str(path))
    header, source = servicenow.git_credential("azure-devops")
    assert header.startswith("Basic ") and source == str(path)
    monkeypatch.setenv("THREATLINT_ADO_PAT", "b" * 52)
    assert ado_login.load()[1] == "THREATLINT_ADO_PAT", "the environment wins over the saved PAT"
    monkeypatch.delenv("THREATLINT_ADO_PAT")
    assert ado_login.logout() and ado_login.load() == ("", "")


def test_keyring_is_used_when_available(monkeypatch):
    store = {}
    keyring = type("K", (), {"set_password": staticmethod(lambda s, u, p: store.update({(s, u): p})),
                             "get_password": staticmethod(lambda s, u: store.get((s, u))),
                             "delete_password": staticmethod(lambda s, u: store.pop((s, u)))})
    monkeypatch.setattr(ado_login, "_keyring", lambda: keyring)
    assert ado_login.save("contoso", PAT) == "the OS credential store"
    assert PAT not in ado_login.store_path().read_text(encoding="utf-8")
    assert ado_login.load() == (PAT, "OS credential store")


def test_pat_stdin_for_non_interactive_setup(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(PAT + "\n"))
    monkeypatch.setattr(ado_login, "validate", lambda org, pat: None)
    assert ado_login.prompt_and_save("contoso", pat_from_stdin=True) == str(ado_login.store_path())


def test_a_pat_for_one_organization_is_not_sent_to_another(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    for name in ado_login.ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(ado_login, "_keyring", lambda: None)
    ado_login.save("contoso", PAT)
    monkeypatch.setattr(servicenow, "_run_tool", lambda name, args, timeout=60: "entra-token")
    assert servicenow.git_credential("azure-devops", "contoso")[1] == str(ado_login.store_path())
    assert servicenow.git_credential("azure-devops", "fabrikam") == ("Bearer entra-token", "az login")
    monkeypatch.setattr(servicenow, "_run_tool", lambda name, args, timeout=60: "")
    assert servicenow.git_credential("azure-devops", "fabrikam")[1] == str(ado_login.store_path())


def test_pats_for_several_organizations_are_kept_side_by_side(monkeypatch):
    store = {}
    keyring = type("K", (), {"set_password": staticmethod(lambda s, u, p: store.update({(s, u): p})),
                             "get_password": staticmethod(lambda s, u: store.get((s, u))),
                             "delete_password": staticmethod(lambda s, u: store.pop((s, u)))})
    monkeypatch.setattr(ado_login, "_keyring", lambda: keyring)
    ado_login.save("contoso", PAT)
    ado_login.save("Fabrikam", "f" * 52)
    assert sorted(ado_login.organizations()) == ["Fabrikam", "contoso"]
    assert ado_login.load("contoso")[0] == PAT and ado_login.load("fabrikam")[0] == "f" * 52
    assert ado_login.load("other") == ("", "")
    monkeypatch.setattr(servicenow, "_run_tool", lambda *a, **k: "")
    assert servicenow.git_credential("azure-devops", "Fabrikam")[0].endswith(__import__("base64").b64encode(b":" + b"f" * 52).decode())
    assert ado_login.logout("contoso") and ado_login.organizations() == ["Fabrikam"]


def test_the_single_pat_file_from_earlier_versions_still_loads(monkeypatch):
    store = {(ado_login.KEYRING_SERVICE, "pat"): PAT}
    keyring = type("K", (), {"set_password": staticmethod(lambda s, u, p: store.update({(s, u): p})),
                             "get_password": staticmethod(lambda s, u: store.get((s, u))), "delete_password": staticmethod(lambda s, u: store.pop((s, u)))})
    monkeypatch.setattr(ado_login, "_keyring", lambda: keyring)
    ado_login.store_path().parent.mkdir(parents=True, exist_ok=True)
    ado_login.store_path().write_text('{"organization": "contoso", "storage": "keyring"}', encoding="utf-8")
    assert ado_login.load("contoso") == (PAT, "OS credential store")
    ado_login.save("fabrikam", "f" * 52)
    assert ado_login.load("contoso")[0] == PAT and ado_login.load("fabrikam")[0] == "f" * 52


def test_the_store_stays_readable_by_older_single_pat_versions(monkeypatch):
    ado_login.save("contoso", PAT)
    ado_login.save("fabrikam", "f" * 52)
    data = __import__("json").loads(ado_login.store_path().read_text(encoding="utf-8"))
    assert data["organization"] == "contoso" and data["pat"] == PAT, "old readers still find a PAT at the top level"
    assert set(data["organizations"]) == {"contoso", "fabrikam"}


def test_token_prints_a_saved_pat_only_to_a_pipe(monkeypatch, capsys):
    import types
    from threatlint import ado_login
    monkeypatch.setattr(ado_login, "load", lambda org="": ("p" * 52, "store") if org == "contoso" else ("", ""))
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    assert ado_login.cmd_ado(types.SimpleNamespace(ado_command="token", organization="contoso")) == 0
    assert capsys.readouterr().out == "p" * 52
    assert ado_login.cmd_ado(types.SimpleNamespace(ado_command="token", organization="other")) == 1
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    assert ado_login.cmd_ado(types.SimpleNamespace(ado_command="token", organization="contoso")) == 1
    assert "p" * 20 not in capsys.readouterr().out


def _shared(monkeypatch):
    monkeypatch.setenv("THREATLINT_ADO_PAT_PARAMETER", "/example/service-account/pat")
    monkeypatch.setenv("THREATLINT_ADO_ORGANIZATIONS", "Contoso,Fabrikam")
    monkeypatch.setenv("THREATLINT_AWS_PROFILE", "service-account-reader")
    monkeypatch.setenv("THREATLINT_AWS_REGION", "eu-west-1")


def test_shared_pat_is_authoritative_and_rotation_never_changes_local_secret_storage(monkeypatch):
    ado_login.save("contoso", PAT)
    original = ado_login.store_path().read_bytes()
    monkeypatch.setenv("THREATLINT_ADO_PAT", "e" * 52)
    _shared(monkeypatch)
    values, reads = iter(["s" * 52, "r" * 52]), []

    def read(name, profile=None, region=None):
        reads.append((name, profile, region))
        return next(values)

    monkeypatch.setattr(parameter_store, "read_parameter", read)
    assert ado_login.load("contoso") == ("s" * 52, ado_login.SERVICE_ACCOUNT_SOURCE)
    assert ado_login.load("Fabrikam", profile="explicit-profile") == ("r" * 52, ado_login.SERVICE_ACCOUNT_SOURCE)
    assert reads == [("/example/service-account/pat", "service-account-reader", "eu-west-1"),
                     ("/example/service-account/pat", "explicit-profile", "eu-west-1")]
    assert ado_login.store_path().read_bytes() == original


def test_service_account_uses_aws_default_chain_when_no_profile_is_configured(monkeypatch):
    _shared(monkeypatch)
    monkeypatch.delenv("THREATLINT_AWS_PROFILE")
    monkeypatch.setenv("AWS_PROFILE", "ambient-profile")
    reads = []
    monkeypatch.setattr(parameter_store, "read_parameter", lambda name, **kwargs: reads.append(kwargs) or PAT)
    ado_login.service_account_pat("Contoso")
    assert reads == [{"profile": None, "region": "eu-west-1"}], "None lets the AWS CLI honor its own credential chain"


def test_service_account_refuses_unlisted_organizations_before_any_secret_lookup(monkeypatch):
    ado_login.save("other", PAT)
    monkeypatch.setenv("THREATLINT_ADO_PAT", "e" * 52)
    _shared(monkeypatch)
    monkeypatch.setattr(parameter_store, "read_parameter", lambda *a, **k: pytest.fail("Disallowed organization must not read the service account"))
    monkeypatch.setattr(servicenow, "_run_tool", lambda *a, **k: pytest.fail("Disallowed organization must not fall back to az login"))
    with pytest.raises(ado_login.AdoLoginError, match="not allowed"):
        ado_login.load("other")


def test_service_account_lookup_failure_never_uses_existing_personal_pat(monkeypatch):
    ado_login.save("contoso", PAT)
    monkeypatch.setenv("THREATLINT_ADO_PAT", "e" * 52)
    _shared(monkeypatch)

    def denied(*args, **kwargs):
        raise parameter_store.ParameterStoreError("AccessDeniedException: check permissions")

    monkeypatch.setattr(parameter_store, "read_parameter", denied)
    with pytest.raises(ado_login.AdoLoginError, match="AccessDeniedException"):
        ado_login.load("Contoso")


def test_service_account_helper_requires_ssm_even_when_personal_credentials_exist(monkeypatch):
    monkeypatch.setenv("THREATLINT_ADO_PAT", PAT)
    with pytest.raises(ado_login.AdoLoginError, match="adoPatParameter"):
        ado_login.service_account_pat("contoso")


@pytest.mark.parametrize("organizations", ["", "https://dev.azure.com/contoso", "contoso,invalid/org"])
def test_invalid_service_account_scope_cannot_fall_back_to_personal_credentials(monkeypatch, organizations):
    _shared(monkeypatch)
    monkeypatch.setenv("THREATLINT_ADO_ORGANIZATIONS", organizations)
    monkeypatch.setenv("THREATLINT_ADO_PAT", PAT)
    monkeypatch.setattr(parameter_store, "read_parameter", lambda *a, **k: pytest.fail("Validate scope before reading secrets"))
    assert ado_login.public_status()["hasPat"] is False
    with pytest.raises(ado_login.AdoLoginError, match="adoOrganizations"):
        ado_login.load("contoso")


def test_status_exposes_only_service_account_metadata_without_reading_secrets(monkeypatch, capsys):
    _shared(monkeypatch)
    monkeypatch.setattr(parameter_store, "read_parameter", lambda *a, **k: pytest.fail("Status must not retrieve secrets"))
    monkeypatch.setattr(ado_login, "_read_store", lambda: pytest.fail("Service account status must not inspect personal PATs"))
    assert ado_login.cmd_ado(types.SimpleNamespace(ado_command="status", json=True)) == 0
    status = json.loads(capsys.readouterr().out)
    assert status == {"hasPat": True, "source": ado_login.SERVICE_ACCOUNT_SOURCE,
                      "organizations": [{"name": name, "source": ado_login.SERVICE_ACCOUNT_SOURCE} for name in ("Contoso", "Fabrikam")],
                      "serviceAccount": {"configured": True, "parameter": "/example/service-account/pat",
                                         "organizations": ["Contoso", "Fabrikam"], "profile": "service-account-reader", "region": "eu-west-1"}}
    assert ado_login.organizations() == ["Contoso", "Fabrikam"]
    assert ado_login.cmd_ado(types.SimpleNamespace(ado_command="status", json=False)) == 0
    assert capsys.readouterr().out.splitlines() == [f"Azure DevOps PAT: {ado_login.SERVICE_ACCOUNT_SOURCE} · {name}" for name in ("Contoso", "Fabrikam")]


def test_service_account_command_validates_every_org_and_saves_only_metadata(monkeypatch, capsys):
    org_config.path().parent.mkdir(parents=True)
    org_config.path().write_text(json.dumps({"snowInstance": "https://example.service-now.com", "semgrepDeployment": "retained"}))
    calls = []
    monkeypatch.setattr(parameter_store, "read_parameter", lambda name, **kwargs: calls.append(("read", name, kwargs)) or PAT)
    monkeypatch.setattr(ado_login, "validate", lambda org, pat: calls.append(("validate", org, pat)))
    monkeypatch.setattr(ado_login, "save", lambda *a, **k: pytest.fail("Service account PAT must not be saved"))
    args = cli.build_parser().parse_args(["ado", "service-account", "--parameter", "/example/pat",
                                         "--organization", "first", "--organization", "Second", "--organization", "first",
                                         "--aws-profile", "appsec", "--region", "eu-central-1"])
    assert ado_login.cmd_ado(args) == 0
    assert calls == [("read", "/example/pat", {"profile": "appsec", "region": "eu-central-1"}),
                     ("validate", "first", PAT), ("validate", "Second", PAT)]
    saved = org_config.path().read_text()
    assert json.loads(saved) == {"snowInstance": "https://example.service-now.com", "semgrepDeployment": "retained",
                                "adoPatParameter": "/example/pat", "adoOrganizations": ["first", "Second"],
                                "awsProfile": "appsec", "awsRegion": "eu-central-1"}
    assert not ado_login.store_path().exists()
    output = capsys.readouterr()
    assert PAT not in saved + output.out + output.err


def test_failed_service_account_validation_preserves_existing_configuration(monkeypatch):
    org_config.path().parent.mkdir(parents=True)
    original = '{"adoPatParameter":"/previous/pat","adoOrganizations":["previous"]}'
    org_config.path().write_text(original)
    monkeypatch.setattr(parameter_store, "read_parameter", lambda *a, **k: PAT)

    def validate(org, pat):
        if org == "second":
            raise ado_login.AdoLoginError("Azure DevOps rejected the PAT")

    monkeypatch.setattr(ado_login, "validate", validate)
    with pytest.raises(ado_login.AdoLoginError, match="rejected"):
        ado_login.configure_service_account("/new/pat", ["first", "second"])
    assert org_config.path().read_text() == original


def test_invalid_ssm_pat_is_not_echoed(monkeypatch):
    _shared(monkeypatch)
    bad = "sensitive value with spaces"
    monkeypatch.setattr(parameter_store, "read_parameter", lambda *a, **k: bad)
    with pytest.raises(ado_login.AdoLoginError, match="valid PAT") as caught:
        ado_login.load("contoso")
    assert bad not in str(caught.value)
