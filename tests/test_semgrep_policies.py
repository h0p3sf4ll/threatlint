"""Policy operations use injected API calls and retain their original compatibility seams."""

import urllib.parse

from threatlint import semgrep_platform as sp


def test_rule_pagination_uses_the_original_api_seam(monkeypatch):
    calls = []

    def call(path, token):
        calls.append(path)
        if len(calls) == 1:
            return {"rules": [{"path": "r"}], "cursor": "synthetic cursor"}
        return {"rules": [{"path": "r.tuned"}]}

    monkeypatch.setattr(sp, "call", call)
    assert sp._policy_rules("7", "8", "synthetic") == [{"path": "r"}, {"path": "r.tuned"}]
    assert urllib.parse.parse_qs(urllib.parse.urlsplit(calls[1]).query)["cursor"] == ["synthetic cursor"]


def test_replacement_uses_the_original_policy_operation_seam(monkeypatch):
    monkeypatch.setattr(sp, "call", lambda *args: {"policies": [
        {"id": 8, "productType": "PRODUCT_TYPE_SAST"},
    ]})
    seen = []
    monkeypatch.setattr(sp, "_replace_in", lambda *args: seen.append(args) or [{"synthetic": True}])
    assert sp.replace_in_policies("synthetic", {"id": 7}, "sast", "r", "r.tuned") == [{"synthetic": True}]
    assert seen[0][2] == [{"id": 8, "productType": "PRODUCT_TYPE_SAST"}]


def test_disable_original_requires_an_enabled_tuned_rule_in_the_same_policy(monkeypatch):
    writes = []

    def call(path, token, **kwargs):
        if kwargs:
            writes.append((path, kwargs))
            return {}
        return {"policies": [{"id": 8, "productType": "PRODUCT_TYPE_SAST"}]}

    monkeypatch.setattr(sp, "call", call)
    monkeypatch.setattr(sp, "_policy_rules", lambda *args: [
        {"path": "r", "policyMode": "MODE_BLOCK"},
        {"path": "r.tuned", "policyMode": "MODE_DISABLED"},
    ])
    assert sp.disable_originals("synthetic", {"id": 7}, "sast", "r") == []
    assert writes == []
