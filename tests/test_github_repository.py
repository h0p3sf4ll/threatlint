"""AVIT GitHub operations use a trusted host and credentials scoped to it."""

import base64
import json
import types

import pytest

from threatlint import github_app, github_repository as gh, servicenow as sn

_REAL_GH_CLI_TOKEN = gh._gh_cli_token


@pytest.fixture(autouse=True)
def no_real_credentials(monkeypatch):
    for name in gh._TOKEN_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(gh, "_gh_cli_token", lambda hostname: "")


def saved_app(tmp_path, monkeypatch, api="https://api.github.com", **changes):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    data = {"appId": "123", "installationId": "456", "privateKeyFile": "/synthetic/app.pem", "apiUrl": api, **changes}
    (tmp_path / "github-app.json").write_text(json.dumps(data))


@pytest.mark.parametrize("api,web,canonical", [
    ("https://api.github.com", "https://github.com", "https://api.github.com"),
    ("https://API.GITHUB.COM:443/", "https://github.com", "https://api.github.com"),
    ("https://git.example.test/api/v3", "https://git.example.test", "https://git.example.test/api/v3"),
    ("https://git.example.test/api/v3/", "https://git.example.test", "https://git.example.test/api/v3"),
    ("https://api.acme.ghe.com/", "https://acme.ghe.com", "https://api.acme.ghe.com"),
])
def test_configured_api_maps_to_web_host(monkeypatch, api, web, canonical):
    monkeypatch.setenv("THREATLINT_GITHUB_API_URL", api)
    assert gh.endpoints() == {"api_url": canonical, "web_url": web, "hostname": web.removeprefix("https://")}


def test_default_saved_and_environment_endpoint_precedence(tmp_path, monkeypatch):
    assert gh.endpoints()["hostname"] == "github.com"
    saved_app(tmp_path, monkeypatch, "https://git.example.test/api/v3")
    assert gh.endpoints()["hostname"] == "git.example.test"
    monkeypatch.setenv("THREATLINT_GITHUB_API_URL", "https://api.acme.ghe.com")
    assert gh.endpoints()["hostname"] == "acme.ghe.com"


@pytest.mark.parametrize("api", [
    "http://git.example.test/api/v3", "https://user:secret@git.example.test/api/v3",
    "https://git.example.test/api/v3?token=secret", "https://git.example.test/api/v3#secret",
    "https://git.example.test/api/v3?", "https://git.example.test/api/v3#",
    "https://git.example.test", "https://git.example.test/redirect/api/v3", "https://git.example.test/api/v3//",
    "https://api.github.com/api/v3", "https://github.com/api/v3", "https://api.github.com//",
    "https://git.example.test:8443/api/v3", "https://git.example.test:/api/v3",
    "https://git.example.test%2f.attacker.test/api/v3", "https://git.example.test\\@attacker.test/api/v3",
    "https://git.example.test/\napi/v3", "https://api.acme.ghe.com/api/v3", "https://acme.ghe.com/api/v3",
])
def test_rejects_unsafe_or_unrecognized_api_url(monkeypatch, api):
    monkeypatch.setenv("THREATLINT_GITHUB_API_URL", api)
    with pytest.raises(gh.GitHubAppError, match="valid GitHub HTTPS API URL") as error:
        gh.endpoints()
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("api,names", [
    ("https://api.github.com", ("GH_TOKEN", "GITHUB_TOKEN")),
    ("https://git.example.test/api/v3", ("GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")),
    ("https://api.acme.ghe.com", ("GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")),
])
def test_only_host_specific_environment_tokens_are_used(monkeypatch, api, names):
    monkeypatch.setenv("THREATLINT_GITHUB_API_URL", api)
    for name in gh._TOKEN_ENV:
        if name not in names:
            monkeypatch.setenv(name, "other-host-token")
    assert gh.token() == ("", "")
    monkeypatch.setenv(names[1], "second-token")
    assert gh.token() == ("second-token", names[1])
    monkeypatch.setenv(names[0], "first-token")
    assert gh.token() == ("first-token", names[0])


def test_app_token_wins_and_is_minted_for_configured_host(tmp_path, monkeypatch):
    saved_app(tmp_path, monkeypatch, "https://git.example.test/api/v3/")
    monkeypatch.setenv("GH_ENTERPRISE_TOKEN", "personal-token")
    seen = []
    monkeypatch.setattr(github_app, "installation_token", lambda config: seen.append(config) or "installation-token")
    assert gh.token() == ("installation-token", "GitHub App")
    assert seen[0]["apiUrl"] == "https://git.example.test/api/v3"


def test_configured_app_failure_never_falls_back_or_echoes_error(tmp_path, monkeypatch):
    saved_app(tmp_path, monkeypatch)
    monkeypatch.setenv("GH_TOKEN", "personal-token")
    monkeypatch.setattr(gh, "_gh_cli_token", lambda _host: pytest.fail("must not fall back to CLI"))
    def failure(_config):
        raise gh.GitHubAppError("synthetic-sensitive-value")
    monkeypatch.setattr(github_app, "installation_token", failure)
    with pytest.raises(gh.GitHubAppError, match="GitHub App authentication failed") as error:
        gh.token()
    assert "synthetic-sensitive-value" not in str(error.value)


def test_incomplete_app_fails_closed(tmp_path, monkeypatch):
    saved_app(tmp_path, monkeypatch, installationId="")
    monkeypatch.setenv("GH_TOKEN", "personal-token")
    with pytest.raises(gh.GitHubAppError, match="incomplete"):
        gh.token()


def test_parameter_store_key_configuration_is_reused(tmp_path, monkeypatch):
    saved_app(tmp_path, monkeypatch, privateKeyFile="")
    (tmp_path / "org.json").write_text(json.dumps({"githubAppPrivateKeyParameter": "/example/github-key"}))
    seen = []
    monkeypatch.setattr(github_app, "installation_token", lambda config: seen.append(config) or "app-token")
    assert gh.token() == ("app-token", "GitHub App")
    assert seen[0]["privateKeyParameter"] == "/example/github-key"


def test_cli_lookup_is_host_scoped_and_cannot_inherit_token_environment(monkeypatch):
    seen = {}
    for name in gh._TOKEN_ENV:
        monkeypatch.setenv(name, "unrelated-token")
    monkeypatch.setattr(gh.shutil, "which", lambda _name: "/synthetic/gh")
    monkeypatch.setattr(gh.tls, "tool_env", lambda base: base)
    monkeypatch.setattr(gh.subprocess, "run", lambda command, **kw: seen.update(command=command, env=kw["env"]) or types.SimpleNamespace(returncode=0, stdout="stored-token\n"))
    assert _REAL_GH_CLI_TOKEN("acme.ghe.com") == "stored-token"
    assert seen["command"] == ["/synthetic/gh", "auth", "token", "--hostname", "acme.ghe.com"]
    assert not set(gh._TOKEN_ENV) & seen["env"].keys()


@pytest.mark.parametrize("tool", ["GitHub", "GH", "GitHub Enterprise", "GitHub Enterprise Server", "GHES", "GitHub Enterprise Cloud", "GHEC"])
def test_avits_use_configured_host_not_record_urls(monkeypatch, tool):
    monkeypatch.setenv("THREATLINT_GITHUB_API_URL", "https://git.example.test/api/v3")
    target = sn.repository_target({"scm_tool": tool, "organization": "acme", "repository": "app", "branch": "refs/heads/release/one",
                                   "api_url": "https://attacker.test/api/v3", "clone_url": "https://attacker.test/acme/app.git"})
    assert target["clone_url"] == "https://git.example.test/acme/app.git"
    assert target["web_url"] == "https://git.example.test/acme/app"
    assert target["branch"] == "release/one"


def test_checkout_headers_scope_enterprise_credential_to_configured_host(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLINT_GITHUB_API_URL", "https://git.example.test/api/v3")
    monkeypatch.setenv("GH_ENTERPRISE_TOKEN", "enterprise-token")
    monkeypatch.setenv("GH_TOKEN", "public-token")
    seen = {}
    monkeypatch.setattr(sn.shutil, "which", lambda name: f"/synthetic/{name}")
    monkeypatch.setattr(sn.subprocess, "run", lambda command, **kw: seen.update(command=command, env=kw["env"]) or types.SimpleNamespace(returncode=0, stderr=""))
    target = sn.repository_target({"scm_tool": "GHES", "organization": "acme", "repository": "app", "branch": "main"})
    sn.checkout_repository(target, str(tmp_path / "checkout"))
    assert seen["command"][-2] == target["clone_url"]
    assert seen["env"]["GIT_CONFIG_KEY_0"] == "http.https://git.example.test/.extraHeader"
    credential = base64.b64encode(b"x-access-token:enterprise-token").decode()
    assert seen["env"]["GIT_CONFIG_VALUE_0"] == f"Authorization: Basic {credential}"
    assert "enterprise-token" not in " ".join(seen["command"])


def test_configuration_errors_are_servicenow_errors(monkeypatch):
    monkeypatch.setenv("THREATLINT_GITHUB_API_URL", "https://git.example.test/unexpected")
    with pytest.raises(sn.ServiceNowError):
        sn.repository_target({"scm_tool": "GHES", "organization": "acme", "repository": "app"})
    with pytest.raises(sn.ServiceNowError):
        sn.git_credential("github")
    with pytest.raises(sn.ServiceNowError):
        sn._git_auth_env("github")
