"""Keep every test away from the developer's real ~/.threatlint settings and GitHub credentials."""

import pytest

_GITHUB_ENV = ("THREATLINT_GITHUB_APP_ID", "THREATLINT_GITHUB_APP_INSTALLATION_ID", "THREATLINT_GITHUB_APP_PRIVATE_KEY_FILE",
               "THREATLINT_GITHUB_API_URL", "THREATLINT_GITHUB_APP_PRIVATE_KEY_PARAMETER")


@pytest.fixture(autouse=True)
def _isolated_threatlint_home(monkeypatch, tmp_path_factory):
    """A private THREATLINT_HOME (tests that need their own set it again), no GitHub App env, and an empty token cache."""
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path_factory.mktemp("threatlint-home")))
    for name in _GITHUB_ENV:
        monkeypatch.delenv(name, raising=False)
    from threatlint import github_app
    github_app.clear_cache()
    yield
    github_app.clear_cache()
