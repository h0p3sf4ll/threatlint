"""Regression coverage for cohesive TLS and organization configuration modules."""

import json
import types
from pathlib import Path

import pytest

from threatlint import org_config, tls


def test_tls_tool_env_preserves_explicit_values_without_mutating_base(monkeypatch):
    monkeypatch.setattr(tls, "ca_bundle", lambda: "/synthetic/bundle.pem")
    base = {"AWS_CA_BUNDLE": "/synthetic/user.pem", "OTHER": "unchanged"}
    result = tls.tool_env(base)
    assert result == {**base, "GIT_SSL_CAINFO": "/synthetic/bundle.pem"}
    assert base == {"AWS_CA_BUNDLE": "/synthetic/user.pem", "OTHER": "unchanged"}


def test_tls_bundle_combines_only_synthetic_roots_and_is_cached(monkeypatch, tmp_path):
    root = "-----BEGIN CERTIFICATE-----\nsynthetic-root\n-----END CERTIFICATE-----"
    default = tmp_path / "default.pem"
    default.write_text("synthetic-default")
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(tls, "_built", False)
    monkeypatch.setattr(tls, "_bundle", None)
    monkeypatch.setattr(tls, "_os_roots", lambda: ["invalid", root])
    monkeypatch.setattr(tls.ssl, "get_default_verify_paths", lambda: types.SimpleNamespace(cafile=str(default)))
    path = tls.ca_bundle()
    assert path == str(tmp_path / "home" / "ca-bundle.pem")
    assert Path(path).read_text() == root + "\nsynthetic-default"
    monkeypatch.setattr(tls, "_os_roots", lambda: pytest.fail("A cached bundle must not reread OS roots"))
    assert tls.ca_bundle() == path


def test_tls_explicit_ssl_cert_file_avoids_generated_bundle(monkeypatch):
    calls = []
    context = types.SimpleNamespace(load_verify_locations=lambda **kwargs: pytest.fail("Explicit trust must not be extended"))
    monkeypatch.setenv("SSL_CERT_FILE", "/synthetic/user.pem")
    monkeypatch.setattr(tls.ssl, "create_default_context", lambda **kwargs: calls.append(kwargs) or context)
    monkeypatch.setattr(tls, "ca_bundle", lambda: pytest.fail("Explicit trust must not export OS roots"))
    assert tls.ssl_context() is context
    assert calls == [{"cafile": "/synthetic/user.pem"}]


@pytest.mark.parametrize("payload", [[], "malformed-json", None])
def test_org_settings_invalid_payloads_are_empty(monkeypatch, tmp_path, payload):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    monkeypatch.delenv(org_config.ENV["ssoUrl"], raising=False)
    monkeypatch.delenv(org_config.ENV["adoOrganizations"], raising=False)
    org_config.path().write_text(payload if isinstance(payload, str) else json.dumps(payload))
    assert org_config.value("ssoUrl") == ""
    assert org_config.values("adoOrganizations") == []


def test_org_settings_env_precedence_and_list_normalization(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    org_config.path().write_text(json.dumps({"ssoUrl": " saved-url ", "adoOrganizations": [" first ", "", 2]}))
    monkeypatch.delenv(org_config.ENV["ssoUrl"], raising=False)
    monkeypatch.delenv(org_config.ENV["adoOrganizations"], raising=False)
    assert org_config.value("ssoUrl") == "saved-url"
    assert org_config.values("adoOrganizations") == ["first", "2"]
    monkeypatch.setenv(org_config.ENV["ssoUrl"], " env-url ")
    monkeypatch.setenv(org_config.ENV["adoOrganizations"], " env-one, , env-two ")
    assert org_config.value("ssoUrl") == "env-url"
    assert org_config.values("adoOrganizations") == ["env-one", "env-two"]
