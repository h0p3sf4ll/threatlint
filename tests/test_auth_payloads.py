"""Synthetic, offline regression coverage for extracted auth transformations."""

import base64
import copy
import json
import types

import pytest

from threatlint import (
    ado_login, ado_payloads, aws_login, aws_profiles,
    github_app, github_app_cli, github_app_config, github_app_payloads,
)


def test_ado_request_validates_before_any_http_call():
    request = ado_payloads.validation_request("Synthetic-Org", "p" * 52)
    assert request.full_url == "https://dev.azure.com/Synthetic-Org/_apis/projects?$top=1&api-version=7.1"
    assert request.get_method() == "GET"
    assert request.get_header("Authorization") == "Basic " + base64.b64encode((":" + "p" * 52).encode()).decode()
    assert request.get_header("Accept") == "application/json"


@pytest.mark.parametrize("organization,pat", [
    ("https://attacker.invalid", "p" * 52),
    ("org/another", "p" * 52),
    ("", "p" * 52),
    ("synthetic", "bad\npat"),
])
def test_ado_rejects_bad_inputs_without_calling_opener(organization, pat):
    def forbidden(*args, **kwargs):
        pytest.fail("Invalid local input must not reach an opener")

    with pytest.raises(ado_login.AdoLoginError):
        ado_login.validate(organization, pat, opener=forbidden)
    assert ado_login.AdoLoginError is ado_payloads.AdoLoginError


@pytest.mark.parametrize("data", [None, [], "bad", 1, {}, {"organizations": []}])
def test_ado_malformed_store_payloads_are_empty(data):
    assert ado_payloads.store_records(data) == {}


def test_ado_legacy_and_multi_org_store_round_trip_without_mutation():
    legacy = {"organization": "Synthetic", "storage": "keyring"}
    records = ado_payloads.store_records(legacy)
    assert records == {"synthetic": {**legacy, "keyring_user": "pat"}}
    records["other"] = {"organization": "Other", "storage": "file", "pat": "p" * 52}
    before = copy.deepcopy(records)
    payload = ado_payloads.store_payload(records)
    assert payload["organization"] == "Synthetic" and "pat" not in payload
    assert ado_payloads.store_records(payload) == records == before
    assert legacy == {"organization": "Synthetic", "storage": "keyring"}
    assert ado_payloads.store_records({"organizations": {**records, "bad": []}}) == records


def test_ado_empty_store_payload_retains_new_schema():
    assert ado_payloads.store_payload({}) == {"organizations": {}}


def test_aws_profiles_preserve_unrelated_sections_and_raw_percent_values(tmp_path):
    path = tmp_path / "aws-config"
    path.write_text("[default]\nregion = synthetic-region\n[profile unrelated]\nrole_arn = value%raw\n")
    args = (path, "synthetic", "https://synthetic.awsapps.com/start", "us-east-1", "000000000000",
            "Role%Name", "synthetic-session", "us-west-2")
    assert aws_profiles.write_profile(*args) is True
    saved = path.read_bytes()
    assert aws_profiles.write_profile(*args) is False
    assert path.read_bytes() == saved
    assert aws_profiles.read_section(path, "profile unrelated") == {"role_arn": "value%raw"}
    assert aws_profiles.read_section(path, "profile synthetic")["sso_role_name"] == "Role%Name"
    assert aws_profiles.read_section(path, "missing") is None


def test_aws_frontend_resolves_profile_path_at_call_time(monkeypatch, tmp_path):
    path = tmp_path / "isolated" / "config"
    monkeypatch.setattr(aws_login, "aws_config_path", lambda: path)
    assert aws_login.ensure_profile("synthetic", "https://synthetic.awsapps.com/start", "us-east-1",
                                    "000000000000", "ReadOnly")
    assert aws_login.existing_profile("synthetic")["sso_session"] == aws_login.DEFAULT_SESSION
    assert aws_login.existing_session(aws_login.DEFAULT_SESSION)["sso_region"] == "us-east-1"
    assert aws_login.existing_session("") == {}
    assert aws_login.existing_session("missing") == {}
    assert aws_login.existing_profile("missing") is None
    path.write_text("[default]\nregion = synthetic\n")
    assert aws_login.existing_profile("default") == {"region": "synthetic"}


def _decode(part):
    return json.loads(base64.urlsafe_b64decode(part + b"=" * (-len(part) % 4)))


def test_github_jwt_payload_is_deterministic_without_signing():
    signing_input = github_app_payloads.jwt_signing_input("Iv1.synthetic", 1000, 60, 540)
    header, claims = signing_input.split(b".")
    assert _decode(header) == {"alg": "RS256", "typ": "JWT"}
    assert _decode(claims) == {"iss": "Iv1.synthetic", "iat": 940, "exp": 1540}
    assert b"=" not in signing_input


def test_github_frontend_keeps_signing_and_clock_policy_seams(monkeypatch):
    calls = []
    monkeypatch.setattr(github_app, "_sign", lambda data, config: calls.append((data, config)) or b"synthetic-signature")
    monkeypatch.setattr(github_app, "JWT_BACKDATE_S", 12)
    monkeypatch.setattr(github_app, "JWT_LIFETIME_S", 34)
    config = {"appId": "123", "installationId": "456"}
    token = github_app.app_jwt(config, now=1000.9)
    assert calls == [(github_app_payloads.jwt_signing_input("123", 1000, 12, 34), config)]
    assert token.rsplit(".", 1)[1] == github_app._b64url(b"synthetic-signature")
    assert github_app.GitHubAppError is github_app_payloads.GitHubAppError
    assert github_app.validate_api_url is github_app_payloads.validate_api_url


@pytest.mark.parametrize("app_id,installation", [("bad/id", "1"), ("1", "-1"), ("", "1")])
def test_github_invalid_ids_fail_before_signing(monkeypatch, app_id, installation):
    monkeypatch.setattr(github_app, "_sign", lambda *args: pytest.fail("Invalid IDs must not be signed"))
    with pytest.raises(github_app.GitHubAppError):
        github_app.app_jwt({"appId": app_id, "installationId": installation}, now=1000)


def test_enterprise_api_path_is_preserved_and_normalized():
    assert github_app_payloads.validate_api_url(" https://github.synthetic/api/v3/// ") == "https://github.synthetic/api/v3"


def test_github_cli_resolves_public_client_dependencies_at_call_time(monkeypatch, tmp_path, capsys):
    calls = []
    monkeypatch.setattr(github_app, "login", lambda *args: calls.append(args) or (tmp_path / "settings.json", 2, "synthetic"))
    args = types.SimpleNamespace(github_command="login", app_id="1", installation_id="2", private_key_file="synthetic.pem", api_url="https://synthetic.invalid")
    assert github_app_cli.cmd_github(args) == 0
    assert calls == [("1", "2", "synthetic.pem", "https://synthetic.invalid")]
    assert "2 repositories visible" in capsys.readouterr().out
    assert github_app.cmd_github is github_app_cli.cmd_github
    assert github_app.load_config is github_app_config.load_config


def test_github_save_keeps_cache_invalidation_and_path_seams(monkeypatch, tmp_path):
    path = tmp_path / "synthetic-settings.json"
    key = tmp_path / "synthetic.pem"
    key.write_text("synthetic-key-not-read")
    monkeypatch.setattr(github_app, "config_path", lambda: path)
    github_app._cache[("synthetic", "1", "2")] = ("synthetic-token", 1000)
    assert github_app.save_config("1", "2", str(key)) == path
    assert github_app._cache == {}
    assert json.loads(path.read_text())["privateKeyFile"] == str(key)
    assert "synthetic-key-not-read" not in path.read_text()
