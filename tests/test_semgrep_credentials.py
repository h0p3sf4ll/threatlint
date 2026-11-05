import json

import pytest

from threatlint import semgrep_credentials as credentials, semgrep_platform as sp


@pytest.fixture
def native_file(monkeypatch, tmp_path):
    path = tmp_path / "native.yml"
    monkeypatch.setenv("SEMGREP_SETTINGS_FILE", str(path))
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path / "threatlint"))
    monkeypatch.delenv("SEMGREP_APP_TOKEN", raising=False)
    monkeypatch.setattr(sp, "_keyring", lambda: None)
    return path


@pytest.mark.parametrize("value", ["synthetic-native-token-123456", "'synthetic-native-token-123456'", '"synthetic-native-token-123456" # login'])
def test_native_login_scalar(native_file, value):
    native_file.write_text(f"api_token: {value}\nanonymous_user_id: example\n")
    assert credentials.native_token() == ("synthetic-native-token-123456", str(native_file))


@pytest.mark.parametrize("contents", ["api_token: null\n", "api_token: *anchor\n", "api_token: !!str secret\n",
                                        "other:\n  api_token: synthetic-native-token-123456\n",
                                        "api_token: synthetic-native-token-123456\napi_token: synthetic-other-token-123456\n"])
def test_native_login_rejects_non_scalar_or_duplicate_keys(native_file, contents):
    native_file.write_text(contents)
    assert credentials.native_token() == ("", "")


def test_token_precedence_and_no_copy(native_file, monkeypatch):
    native_file.write_text("api_token: synthetic-native-token-123456\n")
    monkeypatch.setattr(sp, "parameter_store_token", lambda *_: pytest.fail("native login precedes SSM"))
    assert sp.resolve_token() == ("synthetic-native-token-123456", str(native_file))
    assert not sp.store_path().exists()
    sp.save_token("synthetic-saved-token-123456")
    assert sp.resolve_token()[0] == "synthetic-native-token-123456"
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "synthetic-env-token-123456")
    assert sp.resolve_token()[0] == "synthetic-env-token-123456"


def test_native_xdg_and_explicit_path_precedence(monkeypatch, tmp_path):
    monkeypatch.delenv("SEMGREP_SETTINGS_FILE", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    expected = tmp_path / ".semgrep" / "settings.yml"
    expected.parent.mkdir()
    expected.write_text("api_token: synthetic-native-token-123456\n")
    assert credentials.settings_path() == expected
    monkeypatch.setenv("SEMGREP_SETTINGS_FILE", str(tmp_path / "override.yml"))
    assert credentials.settings_path() == tmp_path / "override.yml"
