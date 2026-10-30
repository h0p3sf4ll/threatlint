"""GitHub App authentication: JWT, installation-token cache, precedence, CLI, and no secret output.

Every key here is a throwaway RSA key generated in the test's tmp dir; every ID is synthetic; HTTP is mocked.
"""

import base64
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import types
from pathlib import Path

import pytest

from threatlint import github_app, servicenow, setup_wizard

ROOT = Path(__file__).resolve().parents[1]
APP_ID, INSTALLATION_ID = "1000001", "2000002"
TOKEN = "ghs_" + "T" * 36


@pytest.fixture(scope="session")
def rsa_key(tmp_path_factory):
    directory = tmp_path_factory.mktemp("github-app-key")
    key, public = directory / "throwaway-app.pem", directory / "throwaway-app.pub"
    subprocess.run(["openssl", "genrsa", "-out", str(key), "2048"], check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", str(key), "-pubout", "-out", str(public)], check=True, capture_output=True)
    return key, public


def _config(key, api="https://api.github.test"):
    return {"appId": APP_ID, "installationId": INSTALLATION_ID, "privateKeyFile": str(key), "apiUrl": api, "privateKeyParameter": ""}


def _b64decode(part):
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeGitHub:
    """Records requests; answers the access-token and repository-list endpoints."""

    def __init__(self, expires_at="2099-01-01T00:00:00Z", tokens=None):
        self.requests, self.expires_at, self.tokens = [], expires_at, list(tokens or [TOKEN])

    def open(self, request, timeout=None):
        self.requests.append(request)
        if request.full_url.endswith("/access_tokens"):
            assert request.get_method() == "POST"
            token = self.tokens.pop(0) if len(self.tokens) > 1 else self.tokens[0]
            return _Response(json.dumps({"token": token, "expires_at": self.expires_at}).encode())
        if "/installation/repositories" in request.full_url:
            return _Response(json.dumps({"total_count": 3, "repositories": [{"owner": {"login": "example-org"}}]}).encode())
        raise AssertionError(request.full_url)


def _save(tmp_path, key, api="https://api.github.test"):
    (tmp_path / "github-app.json").write_text(json.dumps({"appId": APP_ID, "installationId": INSTALLATION_ID, "privateKeyFile": str(key), "apiUrl": api}))


# ── JWT ──────────────────────────────────────────────────────────────────────

def test_app_jwt_header_claims_and_signature(rsa_key, tmp_path):
    key, public = rsa_key
    now = 1_700_000_000
    token = github_app.app_jwt(_config(key), now)
    header, payload, signature = token.split(".")
    assert json.loads(_b64decode(header)) == {"alg": "RS256", "typ": "JWT"}
    claims = json.loads(_b64decode(payload))
    assert claims["iss"] == APP_ID and claims["iat"] == now - 60
    assert now < claims["exp"] <= now + 600 and claims["exp"] - claims["iat"] <= 660
    assert "=" not in token
    (tmp_path / "sig").write_bytes(_b64decode(signature))
    verify = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public), "-signature", str(tmp_path / "sig")],
                            input=f"{header}.{payload}".encode(), capture_output=True)
    assert verify.returncode == 0, verify.stdout + verify.stderr


def test_signing_never_puts_key_contents_on_argv(rsa_key, monkeypatch):
    key, _ = rsa_key
    seen = []
    real = subprocess.run

    def spy(command, **kwargs):
        seen.append(command)
        return real(command, **kwargs)

    monkeypatch.setattr(github_app.subprocess, "run", spy)
    github_app.app_jwt(_config(key))
    pem = key.read_text()
    assert seen and all("PRIVATE KEY" not in arg and pem not in arg for arg in seen[0])


def test_parameter_store_key_is_passed_over_a_pipe(rsa_key, monkeypatch):
    key, _ = rsa_key
    monkeypatch.setattr(github_app, "_read_parameter", lambda name: key.read_text())
    config = {**_config(key), "privateKeyFile": "", "privateKeyParameter": "/example/github-app-key"}
    assert github_app.app_jwt(config).count(".") == 2


def test_unreadable_key_error_does_not_reveal_the_path(tmp_path):
    with pytest.raises(github_app.GitHubAppError) as error:
        github_app.app_jwt(_config(tmp_path / "missing-secret-name.pem"))
    assert "missing-secret-name" not in str(error.value)


@pytest.mark.parametrize("url", ["http://api.github.com", "https://user:pw@api.github.com", "https://api.github.com?x=1", "ftp://x", ""])
def test_api_url_must_be_plain_https(url):
    with pytest.raises(github_app.GitHubAppError):
        github_app.validate_api_url(url)


def test_redirects_are_refused():
    with pytest.raises(github_app.GitHubAppError, match="redirect"):
        github_app._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://evil.example/")


# ── Token exchange and cache ─────────────────────────────────────────────────

def test_installation_token_exchange_and_cache(rsa_key):
    key, _ = rsa_key
    fake = FakeGitHub()
    assert github_app.installation_token(_config(key), opener=fake) == TOKEN
    assert github_app.installation_token(_config(key), opener=fake) == TOKEN
    assert len(fake.requests) == 1
    request = fake.requests[0]
    assert request.full_url == f"https://api.github.test/app/installations/{INSTALLATION_ID}/access_tokens"
    assert request.get_header("Authorization").startswith("Bearer ey")


def test_token_refreshes_five_minutes_before_expiry(rsa_key):
    key, _ = rsa_key
    expires = 1_700_003_600  # 2023-11-14T22:13:20Z
    fake = FakeGitHub(expires_at="2023-11-14T23:13:20Z", tokens=["ghs_first" + "a" * 30, "ghs_second" + "b" * 30])
    clock = [expires - 3600]
    get = lambda: github_app.installation_token(_config(key), opener=fake, now=lambda: clock[0])
    first = get()
    clock[0] = expires - 301
    assert get() == first and len(fake.requests) == 1
    clock[0] = expires - 299
    assert get() != first and len(fake.requests) == 2


def test_rejected_credentials_give_a_safe_error(rsa_key):
    key, _ = rsa_key
    import urllib.error

    class Rejecting:
        def open(self, request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, io.BytesIO(b"{}"))

    with pytest.raises(github_app.GitHubAppError) as error:
        github_app.installation_token(_config(key), opener=Rejecting())
    assert "401" in str(error.value) and APP_ID not in str(error.value) and INSTALLATION_ID not in str(error.value)


# ── Configuration and precedence ─────────────────────────────────────────────

def test_environment_overrides_saved_config(rsa_key, tmp_path, monkeypatch):
    key, _ = rsa_key
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    assert github_app.load_config() is None
    _save(tmp_path, key)
    assert github_app.load_config()["apiUrl"] == "https://api.github.test"
    monkeypatch.setenv("THREATLINT_GITHUB_APP_INSTALLATION_ID", "3000003")
    assert github_app.load_config()["installationId"] == "3000003"


def test_environment_only_config(rsa_key, tmp_path, monkeypatch):
    key, _ = rsa_key
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    monkeypatch.setenv("THREATLINT_GITHUB_APP_ID", APP_ID)
    monkeypatch.setenv("THREATLINT_GITHUB_APP_INSTALLATION_ID", INSTALLATION_ID)
    monkeypatch.setenv("THREATLINT_GITHUB_APP_PRIVATE_KEY_FILE", str(key))
    config = github_app.load_config()
    assert config["source"] == "environment" and config["apiUrl"] == github_app.DEFAULT_API_URL


def test_key_parameter_from_org_json(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    (tmp_path / "org.json").write_text(json.dumps({"githubAppPrivateKeyParameter": "/example/github-app-key"}))
    (tmp_path / "github-app.json").write_text(json.dumps({"appId": APP_ID, "installationId": INSTALLATION_ID}))
    assert github_app.load_config()["privateKeyParameter"] == "/example/github-app-key"


def test_precedence_app_then_env_then_gh(rsa_key, tmp_path, monkeypatch):
    key, _ = rsa_key
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    for name in github_app.TOKEN_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    gh = lambda: "gho_cli_token"
    assert github_app.github_token(gh_cli=gh) == ("gho_cli_token", "gh auth token")
    monkeypatch.setenv("GITHUB_TOKEN", "env-token")
    assert github_app.github_token(gh_cli=gh) == ("env-token", "GITHUB_TOKEN")
    monkeypatch.setenv("GH_TOKEN", "gh-env-token")
    assert github_app.github_token(gh_cli=gh) == ("gh-env-token", "GH_TOKEN")
    _save(tmp_path, key)
    monkeypatch.setattr(github_app, "installation_token", lambda *a, **k: TOKEN)
    assert github_app.github_token(gh_cli=gh) == (TOKEN, "GitHub App")
    assert github_app.source() == "GitHub App"


def test_failing_app_falls_back_without_leaking(rsa_key, tmp_path, monkeypatch, capsys):
    key, _ = rsa_key
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    _save(tmp_path, key)
    monkeypatch.setenv("GH_TOKEN", "env-token")

    def broken(*a, **k):
        raise github_app.GitHubAppError("GitHub API request failed: HTTP 401")

    monkeypatch.setattr(github_app, "installation_token", broken)
    assert github_app.github_token() == ("env-token", "GH_TOKEN")
    err = capsys.readouterr().err
    assert "falling back" in err and APP_ID not in err and str(key) not in err


def test_git_credential_uses_the_app_token(rsa_key, tmp_path, monkeypatch):
    key, _ = rsa_key
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    monkeypatch.setenv("GH_TOKEN", "env-token")
    _save(tmp_path, key)
    monkeypatch.setattr(github_app, "installation_token", lambda *a, **k: TOKEN)
    header, source = servicenow.git_credential("github", "example-org")
    assert source == "GitHub App"
    assert header == "Basic " + base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()
    env = servicenow._git_auth_env("github")
    assert env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraHeader" and env["GIT_TERMINAL_PROMPT"] == "0"


def test_no_app_keeps_existing_behaviour(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "env-token")
    assert servicenow.git_credential("github")[1] == "GH_TOKEN"
    for name in github_app.TOKEN_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(servicenow, "_run_tool", lambda *a, **k: "")
    assert servicenow.git_credential("github") == ("", "")


# ── CLI ──────────────────────────────────────────────────────────────────────

def _args(command, **kw):
    return types.SimpleNamespace(github_command=command, **{"app_id": "", "installation_id": "", "private_key_file": "", "api_url": "", **kw})


def test_login_validates_saves_0600_and_prints_no_secrets(rsa_key, tmp_path, monkeypatch, capsys):
    key, _ = rsa_key
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    fake = FakeGitHub()
    real_request = github_app._request
    monkeypatch.setattr(github_app, "_request", lambda method, url, auth, opener=None: real_request(method, url, auth, fake))
    assert github_app.cmd_github(_args("login", app_id=APP_ID, installation_id=INSTALLATION_ID, private_key_file=str(key),
                                       api_url="https://api.github.test")) == 0
    saved = tmp_path / "github-app.json"
    assert stat.S_IMODE(saved.stat().st_mode) == 0o600
    data = json.loads(saved.read_text())
    assert data == {"appId": APP_ID, "installationId": INSTALLATION_ID, "privateKeyFile": str(key), "apiUrl": "https://api.github.test"}
    assert "PRIVATE KEY" not in saved.read_text()
    assert [request.full_url.rsplit("/", 2)[-1] for request in fake.requests] == ["access_tokens", "repositories?per_page=1"]
    assert fake.requests[1].get_header("Authorization") == f"Bearer {TOKEN}"
    out, err = capsys.readouterr()
    assert "3 repositories" in out and "example-org" in out
    for secret in (APP_ID, INSTALLATION_ID, str(key), TOKEN, "PRIVATE KEY"):
        assert secret not in out + err

    assert github_app.cmd_github(_args("status")) == 0
    out, err = capsys.readouterr()
    assert "GitHub App" in out
    for secret in (APP_ID, INSTALLATION_ID, str(key), TOKEN):
        assert secret not in out + err

    assert github_app.cmd_github(_args("logout")) == 0 and not saved.exists()
    assert key.exists()


def test_login_failure_saves_nothing(rsa_key, tmp_path, monkeypatch, capsys):
    key, _ = rsa_key
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))

    def rejected(*a, **k):
        raise github_app.GitHubAppError("GitHub API request failed: HTTP 401")

    monkeypatch.setattr(github_app, "installation_repositories", rejected)
    assert github_app.cmd_github(_args("login", app_id=APP_ID, installation_id=INSTALLATION_ID, private_key_file=str(key))) == 1
    assert not (tmp_path / "github-app.json").exists()


def test_status_without_app(monkeypatch, capsys):
    monkeypatch.setenv("GH_TOKEN", "env-token-value")
    assert github_app.cmd_github(_args("status")) == 0
    out = capsys.readouterr().out
    assert "GH_TOKEN" in out and "env-token-value" not in out


def test_cli_registers_github_commands():
    from threatlint.cli import build_parser
    args = build_parser().parse_args(["github", "login", "--app-id", APP_ID, "--installation-id", INSTALLATION_ID, "--private-key-file", "k.pem"])
    assert (args.command, args.github_command, args.app_id) == ("github", "login", APP_ID)


def test_setup_check_reports_github_as_optional(monkeypatch, capsys):
    monkeypatch.setattr(github_app, "source", lambda: "")
    setup_wizard.cmd_check(types.SimpleNamespace(aws_profile="appsec", json=False))
    assert "GitHub credential (optional)" in capsys.readouterr().out


# ── CI scripts ───────────────────────────────────────────────────────────────

def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("script", ["post_pr_comment.py", "create_issues.py"])
def test_scripts_prefer_env_then_app_then_gh(script, monkeypatch, tmp_path, rsa_key):
    key, _ = rsa_key
    module = _load(script[:-3], ROOT / ".github/scripts" / script)
    monkeypatch.setenv("GH_TOKEN", "env-token")
    assert module.github_token() == "env-token"
    for name in github_app.TOKEN_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    _save(tmp_path, key)
    monkeypatch.setattr(github_app, "installation_token", lambda *a, **k: TOKEN)
    assert module.github_token() == TOKEN
    (tmp_path / "github-app.json").unlink()
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="gho_cli\n"))
    assert module.github_token() == "gho_cli"


def test_post_comment_passes_the_app_token_to_gh_only_by_env(monkeypatch, tmp_path, rsa_key, capsys):
    key, _ = rsa_key
    module = _load("post_pr_comment", ROOT / ".github/scripts/post_pr_comment.py")
    for name in github_app.TOKEN_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    _save(tmp_path, key)
    monkeypatch.setattr(github_app, "installation_token", lambda *a, **k: TOKEN)
    calls = []
    monkeypatch.setattr(module.subprocess, "run", lambda command, **k: calls.append((command, k.get("env"))) or types.SimpleNamespace(returncode=0, stderr=""))
    module.post_comment(7, "body")
    command, env = calls[0]
    assert command[:3] == ["gh", "pr", "comment"] and TOKEN not in command and env["GH_TOKEN"] == TOKEN
    assert TOKEN not in capsys.readouterr().out


def test_chat_uses_app_token_when_env_has_none(monkeypatch, tmp_path, rsa_key):
    key, _ = rsa_key
    chat = _load("threatlint_chat_app", ROOT / ".github/scripts/threatlint_chat.py")
    assert chat.github_token({"GH_TOKEN": "env-token"}) == "env-token"
    assert chat.github_token({}) == ""
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    _save(tmp_path, key)
    monkeypatch.setattr(github_app, "installation_token", lambda *a, **k: TOKEN)
    assert chat.github_token({}) == TOKEN
