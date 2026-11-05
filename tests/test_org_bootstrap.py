"""Organization bootstrap imports metadata atomically, without credential values."""

import json
import os
import stat

import pytest

from threatlint import org_config, parameter_store


@pytest.fixture(autouse=True)
def isolated_org(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    for variable in org_config.ENV.values():
        monkeypatch.delenv(variable, raising=False)


def _parameter(monkeypatch, payload):
    monkeypatch.setattr(parameter_store, "read_parameter", lambda *_args, **_kwargs:
                        payload if isinstance(payload, str) else json.dumps(payload))


def test_fresh_bootstrap_persists_only_metadata_and_selected_reference(monkeypatch):
    calls = []
    payload = {"snowInstance": "https://example.service-now.com", "snowClientIdParameter": "/example/snow/id",
               "snowClientSecretParameter": "/example/snow/secret", "adoOrganizations": ["example"],
               "adoPatParameter": "/example/ado/pat", "semgrepTokenParameter": "/example/semgrep/token"}

    def read(name, profile=None, region=None):
        calls.append((name, profile, region))
        return json.dumps(payload)

    monkeypatch.setattr(parameter_store, "read_parameter", read)
    destination = org_config.bootstrap("/example/org", "appsec", "eu-central-1")
    assert calls == [("/example/org", "appsec", "eu-central-1")]
    assert json.loads(destination.read_text()) == {**payload, "orgParameter": "/example/org", "awsRegion": "eu-central-1"}
    if os.name != "nt":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_saved_settings_and_environment_keep_precedence(monkeypatch):
    org_config.path().write_text(json.dumps({"snowInstance": "https://local.service-now.com", "semgrepDeployment": "",
                                             "repoStore": "local-repositories", "orgParameter": "/previous/org"}))
    monkeypatch.setenv("THREATLINT_SNOW_INSTANCE", "https://environment.service-now.com")
    _parameter(monkeypatch, {"snowInstance": "https://imported.service-now.com", "semgrepDeployment": "imported-deployment",
                             "repoStore": "imported-repositories"})
    org_config.bootstrap("/example/org")
    saved = json.loads(org_config.path().read_text())
    assert saved["snowInstance"] == "https://local.service-now.com"
    assert saved["semgrepDeployment"] == "imported-deployment"
    assert saved["repoStore"] == "local-repositories"
    assert saved["orgParameter"] == "/example/org"
    assert org_config.value("snowInstance") == "https://environment.service-now.com"


def test_region_uses_app_environment_then_saved_then_legacy_default(monkeypatch):
    assert org_config.aws_region() == "us-west-2"
    org_config.path().write_text('{"awsRegion":"eu-west-1"}')
    assert org_config.aws_region() == "eu-west-1"
    monkeypatch.setenv("THREATLINT_AWS_REGION", "ap-south-1")
    assert org_config.aws_region() == "ap-south-1"


@pytest.mark.parametrize("payload", [
    {"clientSecret": "synthetic-secret"}, {"unsupported": "synthetic-secret"}, [],
    {"snowInstance": ["https://example.service-now.com"]}, {"adoOrganizations": [7]},
    {"adoOrganizations": "example"}, {"semgrepTokenParameter": False},
    {"snowInstance": "http://example.service-now.com"},
    {"snowInstance": "https://user:synthetic-secret@example.service-now.com"},
    {"snowInstance": "https://example.service-now.com/#fragment"}, {"awsRegion": "--debug"},
    {"snowInstance": "https://example.service-now.com:invalid"}, {"ssoUrl": "https://exa mple.com"},
    {"snowClientSecretParameter": "--debug"},
    "malformed-synthetic-secret",
])
def test_invalid_metadata_is_never_saved_or_echoed(monkeypatch, payload):
    _parameter(monkeypatch, payload)
    with pytest.raises(parameter_store.ParameterStoreError) as caught:
        org_config.bootstrap("/example/org")
    assert not org_config.path().exists()
    assert "synthetic-secret" not in str(caught.value)


def test_access_failure_preserves_existing_config(monkeypatch):
    original = '{"snowInstance":"https://saved.service-now.com"}'
    org_config.path().write_text(original)

    def fail(*_args, **_kwargs):
        raise parameter_store.ParameterStoreError("AccessDeniedException")

    monkeypatch.setattr(parameter_store, "read_parameter", fail)
    with pytest.raises(parameter_store.ParameterStoreError, match="AccessDeniedException"):
        org_config.bootstrap("/example/org")
    assert org_config.path().read_text() == original


@pytest.mark.parametrize("original", ["malformed", "[]"])
def test_invalid_existing_config_is_preserved(monkeypatch, original):
    org_config.path().write_text(original)
    _parameter(monkeypatch, {"semgrepDeployment": "example"})
    with pytest.raises(parameter_store.ParameterStoreError, match="existing org.json"):
        org_config.bootstrap("/example/org")
    assert org_config.path().read_text() == original


def test_atomic_write_failure_preserves_config_and_removes_temporary_file(monkeypatch):
    original = '{"semgrepDeployment":"existing"}'
    org_config.path().write_text(original)
    _parameter(monkeypatch, {"semgrepDeployment": "imported"})

    def fail_replace(*_args):
        raise OSError("synthetic-private-path")

    monkeypatch.setattr(org_config.os, "replace", fail_replace)
    with pytest.raises(parameter_store.ParameterStoreError) as caught:
        org_config.bootstrap("/example/org")
    assert "synthetic-private-path" not in str(caught.value)
    assert org_config.path().read_text() == original
    assert list(org_config.path().parent.glob(".org-*.tmp")) == []
