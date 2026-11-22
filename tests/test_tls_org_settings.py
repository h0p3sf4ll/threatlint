"""Regression coverage for cohesive TLS and organization configuration modules."""

import json
import os
import subprocess
import sys
import time
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
    shared = tmp_path / "home" / "ca-bundle.pem"
    shared.parent.mkdir()
    shared.write_text("existing shared bundle", encoding="utf-8")
    cleanup = []
    monkeypatch.setattr(tls.atexit, "register", lambda callback, path: cleanup.append((callback, path)))
    path = tls.ca_bundle()
    assert Path(path).parent == shared.parent
    assert Path(path).name.startswith(f"ca-bundle-{os.getpid()}-")
    assert Path(path).suffix == ".pem"
    assert Path(path) != shared
    assert Path(path).read_text() == root + "\nsynthetic-default"
    if os.name == "posix":
        assert Path(path).stat().st_mode & 0o777 == 0o600
    monkeypatch.setattr(tls, "_os_roots", lambda: pytest.fail("A cached bundle must not reread OS roots"))
    assert tls.ca_bundle() == path
    assert len(cleanup) == 1
    cleanup[0][0](cleanup[0][1])
    assert not Path(path).exists()
    assert shared.read_text() == "existing shared bundle"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows concurrent certificate bundle reader regression")
def test_tls_concurrent_windows_child_imports_load_private_bundles(tmp_path):
    """Real SSL readers must not share a path another process can replace."""
    shared_home = tmp_path / "shared-home"
    environment = dict(os.environ)
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "AWS_CA_BUNDLE", "GIT_SSL_CAINFO"):
        environment.pop(name, None)
    environment["THREATLINT_HOME"] = str(shared_home)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    program = """
import pathlib, sys, time
from threatlint import tls
directory, number = pathlib.Path(sys.argv[1]), sys.argv[2]
def wait_for(name):
    deadline = time.monotonic() + 30
    while not (directory / name).exists():
        if time.monotonic() > deadline:
            raise RuntimeError('TLS test barrier timed out')
        time.sleep(0.01)
(directory / (number + '.ready')).touch()
wait_for('release')
from threatlint import servicenow
for _ in range(5):
    tls.ssl_context()
bundle = tls.ca_bundle()
assert bundle and servicenow._OPENER
(directory / (number + '.loaded')).write_text(bundle, encoding='utf-8')
wait_for('finish')
"""
    children = []
    bundles = []
    try:
        for number in range(3):
            children.append(subprocess.Popen([sys.executable, "-c", program, str(tmp_path), str(number)],
                                             env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        for phase in ("ready", "loaded"):
            deadline = time.monotonic() + 30
            while not all((tmp_path / f"{number}.{phase}").exists() for number in range(3)):
                for child in children:
                    if child.poll() is not None:
                        _, error = child.communicate()
                        pytest.fail(f"TLS child exited before {phase}: {error[-8192:]}")
                assert time.monotonic() < deadline, f"TLS children did not reach {phase}"
                time.sleep(0.01)
            if phase == "ready":
                (tmp_path / "release").touch()
        bundles = [Path((tmp_path / f"{number}.loaded").read_text(encoding="utf-8")) for number in range(3)]
        assert len(set(bundles)) == 3
        assert all(bundle.parent == shared_home and bundle.is_file() for bundle in bundles)
    finally:
        (tmp_path / "release").touch()
        (tmp_path / "finish").touch()
        failures = []
        for child in children:
            try:
                _, error = child.communicate(timeout=10)
            except (OSError, subprocess.TimeoutExpired) as failure:
                failures.append(f"TLS child communication failed: {type(failure).__name__}")
                try:
                    child.kill()
                except OSError as error:
                    failures.append(f"TLS child kill failed: {type(error).__name__}")
                try:
                    _, error = child.communicate(timeout=10)
                except (OSError, subprocess.TimeoutExpired) as error:
                    failures.append(f"TLS child drain failed: {type(error).__name__}")
                    continue
            if child.returncode != 0:
                failures.append(error[-8192:] or f"TLS child exited {child.returncode}")
        assert not failures, "\n".join(failures)
    assert all(not bundle.exists() for bundle in bundles)


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
