"""threatlint ado login: PAT validation, storage, and precedence for AVIT checkouts."""

import io
import os
import stat
import urllib.error

import pytest

from threatlint import ado_login, servicenow

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
    for name in ado_login.ENV_NAMES:
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
    assert PAT not in ado_login.store_path().read_text()
    assert ado_login.load() == (PAT, "OS credential store")


def test_pat_stdin_for_non_interactive_setup(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(PAT + "\n"))
    monkeypatch.setattr(ado_login, "validate", lambda org, pat: None)
    assert ado_login.prompt_and_save("contoso", pat_from_stdin=True) == str(ado_login.store_path())
