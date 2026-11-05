"""Parameter reads preserve TLS configuration and keep AWS output out of errors."""

import json
import subprocess
import types

import pytest

from threatlint import org_config, parameter_store


@pytest.fixture(autouse=True)
def isolated_parameter_store(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    monkeypatch.delenv("THREATLINT_AWS_REGION", raising=False)
    monkeypatch.setattr(parameter_store.shutil, "which", lambda name: "C:/Program Files/AWS/aws.exe")
    monkeypatch.setattr(parameter_store.tls, "tool_env", lambda: {"AWS_CA_BUNDLE": "synthetic-ca.pem"})


def test_read_parameter_uses_profile_dynamic_region_and_trusted_tool_environment(monkeypatch):
    monkeypatch.setenv("THREATLINT_AWS_REGION", "eu-west-1")
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return types.SimpleNamespace(returncode=0, stdout=json.dumps({"Parameter": {"Value": "synthetic-secret"}}))

    monkeypatch.setattr(parameter_store.subprocess, "run", run)
    assert parameter_store.read_parameter("/example/token", "appsec") == "synthetic-secret"
    command, kwargs = calls[0]
    assert command == ["C:/Program Files/AWS/aws.exe", "ssm", "get-parameter", "--name", "/example/token",
                       "--with-decryption", "--region", "eu-west-1", "--output", "json", "--profile", "appsec"]
    assert kwargs == {"shell": False, "capture_output": True, "text": True, "timeout": 60,
                      "check": False, "env": {"AWS_CA_BUNDLE": "synthetic-ca.pem"}}


def test_explicit_region_overrides_saved_and_environment_regions(monkeypatch):
    org_config.path().write_text(json.dumps({"awsRegion": "us-east-1"}))
    monkeypatch.setenv("THREATLINT_AWS_REGION", "us-west-1")
    calls = []
    monkeypatch.setattr(parameter_store.subprocess, "run", lambda command, **_: calls.append(command) or
                        types.SimpleNamespace(returncode=0, stdout='{"Parameter":{"Value":"value"}}'))
    parameter_store.read_parameter("/example/config", region="ap-south-1")
    assert calls[0][calls[0].index("--region") + 1] == "ap-south-1"


@pytest.mark.parametrize("name, profile, region", [
    ("--debug", None, None), ("/path with spaces", None, None), ("", None, None),
    (None, None, None), ("a" * 2049, None, None), ("/valid", "--debug", None),
    ("/valid", None, "--endpoint-url"), ("/valid", None, "not-a-region"),
])
def test_invalid_references_fail_before_cli_execution(monkeypatch, name, profile, region):
    monkeypatch.setattr(parameter_store.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("Invalid input must not reach AWS"))
    with pytest.raises(parameter_store.ParameterStoreError):
        parameter_store.read_parameter(name, profile, region)


def test_parameter_arn_is_accepted():
    parameter_store.validate_reference("arn:aws:ssm:us-east-1:111122223333:parameter/example/config", "appsec", "us-east-1")


def test_missing_cli_is_actionable(monkeypatch):
    monkeypatch.setattr(parameter_store.shutil, "which", lambda name: None)
    with pytest.raises(parameter_store.ParameterStoreError, match="not found on PATH"):
        parameter_store.read_parameter("/example/token")


@pytest.mark.parametrize("stderr, expected", [
    ("An error occurred (AccessDeniedException): synthetic-secret", "AccessDeniedException"),
    ("An error occurred (ParameterNotFound): synthetic-secret", "ParameterNotFound"),
    ("Token has expired: synthetic-secret", "Token has expired"),
    ("Unable to locate credentials synthetic-secret", "credentials are unavailable"),
    ("[SSL: CERTIFICATE_VERIFY_FAILED] synthetic-secret", "certificate validation failed"),
    ("unexpected arbitrary synthetic-secret", "AWS could not read the parameter"),
])
def test_failed_cli_returns_only_safe_diagnostics(monkeypatch, stderr, expected):
    monkeypatch.setattr(parameter_store.subprocess, "run", lambda *_args, **_kwargs:
                        types.SimpleNamespace(returncode=1, stdout="synthetic-secret", stderr=stderr))
    with pytest.raises(parameter_store.ParameterStoreError) as caught:
        parameter_store.read_parameter("/example/token")
    assert expected in str(caught.value)
    assert "synthetic-secret" not in str(caught.value)


@pytest.mark.parametrize("stdout", ["synthetic-secret", "[]", '{"Parameter":{}}',
                                     '{"Parameter":{"Value":[]}}', '{"Parameter":{"Value":""}}'])
def test_invalid_response_does_not_echo_payload(monkeypatch, stdout):
    monkeypatch.setattr(parameter_store.subprocess, "run", lambda *_args, **_kwargs:
                        types.SimpleNamespace(returncode=0, stdout=stdout))
    with pytest.raises(parameter_store.ParameterStoreError) as caught:
        parameter_store.read_parameter("/example/token")
    assert "synthetic-secret" not in str(caught.value)


def test_timeout_is_reported_without_raw_exception(monkeypatch):
    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("synthetic-secret", 60)

    monkeypatch.setattr(parameter_store.subprocess, "run", timeout)
    with pytest.raises(parameter_store.ParameterStoreError, match="timed out") as caught:
        parameter_store.read_parameter("/example/token")
    assert "synthetic-secret" not in str(caught.value)
