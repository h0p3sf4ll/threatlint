"""Semgrep token setup and rule tuning: nothing is published unless the tuned rule is proven."""

import os
import types

import pytest

from threatlint import semgrep_platform as sp

REPORT = """#### [FP-001] — safe
**Original finding**: AVIT000000041277488; js.rule; Semgrep Code; a.js:10
**Disposition**: FALSE POSITIVE

**Tuned rule**:

```yaml
rules:
  - id: js.rule.tuned
    languages: [javascript]
    severity: WARNING
    message: m
    pattern: eval($X)
```
"""


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    monkeypatch.delenv("SEMGREP_APP_TOKEN", raising=False)
    monkeypatch.setattr(sp, "_keyring", lambda: None)
    monkeypatch.setattr(sp, "existing_tuning", lambda *a: [])


def test_token_is_saved_privately_and_resolved_first(monkeypatch):
    sp.save_token("t" * 64, "example_org")
    assert sp.resolve_token() == ("t" * 64, str(sp.store_path()))
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "env-token-value-123456")
    assert sp.resolve_token()[1] == "SEMGREP_APP_TOKEN"


def test_the_tuned_rule_block_is_read_from_the_report():
    assert sp.tuned_rule_from_report(REPORT).startswith("rules:\n  - id: js.rule.tuned")
    assert sp.tuned_rule_from_report("no rule") == ""


FIXTURES = "**Tuned rule fixtures**:\n\n```javascript\n// ruleid: js.rule.tuned\neval(req.body.x)\n// ok: js.rule.tuned\neval('1')\n```\n"


def test_nothing_is_published_when_the_tuned_rule_still_matches(monkeypatch, tmp_path):
    monkeypatch.setattr(sp, "_semgrep", lambda args, **kw: types.SimpleNamespace(returncode=0, stdout="All tests passed", stderr=""))
    monkeypatch.setattr(sp, "original_rule_yaml", lambda rule, token: "rules:\n  - id: js.rule\n")
    (tmp_path / "a.js").write_text("x")
    monkeypatch.setattr(sp, "_matches", lambda config, target, line, exact=False: [2, 4] if target.endswith("tuned.js") else [10])
    published = []
    monkeypatch.setattr(sp, "publish", lambda *a: published.append(a))
    with pytest.raises(sp.SemgrepError, match="still reports the false-positive location"):
        sp.tune_rule(REPORT + FIXTURES, "sast", "js.rule", str(tmp_path / "a.js"), 10, "t", {"id": 1})
    assert published == []


def test_tuned_rule_replaces_the_original_in_its_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(sp, "_semgrep", lambda args, **kw: types.SimpleNamespace(returncode=0, stdout="All tests passed", stderr=""))
    monkeypatch.setattr(sp, "original_rule_yaml", lambda rule, token: "rules:\n  - id: js.rule\n")
    (tmp_path / "a.js").write_text("x")
    monkeypatch.setattr(sp, "_matches", lambda config, target, line, exact=False: [2, 4] if target.endswith("tuned.js") else ([] if config.endswith("tuned.yaml") else [10]))
    monkeypatch.setattr(sp, "publish", lambda path, token: "org.js.rule.tuned")
    puts = []
    def call(path, token, *, method="GET", body=None):
        if method == "PUT":
            puts.append((path.rsplit("/", 1)[-1], body["policyMode"]))
            return {}
        if path.endswith("/1"):
            return {"policies": [{"id": "5", "name": "Global Policy", "productType": "PRODUCT_TYPE_SAST"},
                                 {"id": "6", "name": "Secrets", "productType": "PRODUCT_TYPE_SECRETS"}]}
        return {"rules": [{"path": "js.rule", "policyMode": "MODE_BLOCK"}, {"path": "other", "policyMode": "MODE_BLOCK"}]}
    monkeypatch.setattr(sp, "call", call)
    changes = sp.tune_rule(REPORT + FIXTURES, "sast", "js.rule", str(tmp_path / "a.js"), 10, "t", {"id": 1}, out=open(os.devnull, "w"))
    assert puts == [("org.js.rule.tuned", "MODE_BLOCK"), ("js.rule", "MODE_DISABLED")]
    assert changes[0]["policy"] == "Global Policy"


def test_tuning_is_rejected_when_the_fixtures_do_not_model_the_original(monkeypatch, tmp_path):
    monkeypatch.setattr(sp, "_semgrep", lambda args, **kw: types.SimpleNamespace(returncode=0, stdout="All tests passed", stderr=""))
    monkeypatch.setattr(sp, "original_rule_yaml", lambda rule, token: "rules:\n  - id: js.rule\n")
    monkeypatch.setattr(sp, "_matches", lambda config, target, line, exact=False: [2])  # original misses the ok line
    monkeypatch.setattr(sp, "publish", lambda *a: pytest.fail("must not publish an unproven tuning"))
    with pytest.raises(sp.SemgrepError, match="do not model this false positive"):
        sp.tune_rule(REPORT + FIXTURES, "sast", "js.rule", str(tmp_path / "a.js"), 10, "t", {"id": 1})


def test_tuning_requires_fixtures(monkeypatch, tmp_path):
    monkeypatch.setattr(sp, "_semgrep", lambda args, **kw: types.SimpleNamespace(returncode=0, stdout="", stderr=""))
    with pytest.raises(sp.SemgrepError, match="fixtures"):
        sp.tune_rule(REPORT, "sast", "js.rule", str(tmp_path / "a.js"), 10, "t", {"id": 1})

def test_a_rule_already_tuned_is_not_tuned_again(monkeypatch, tmp_path):
    monkeypatch.undo()
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    def call(path, token, *, method="GET", body=None):
        assert method == "GET", "nothing may change"
        if path.endswith("/1"):
            return {"policies": [{"id": "5", "name": "Global Policy", "productType": "PRODUCT_TYPE_SAST"}]}
        return {"rules": [{"path": "example_org.js.rule.tuned", "policyMode": "MODE_COMMENT"}, {"path": "js.rule", "policyMode": "MODE_DISABLED"}]}
    monkeypatch.setattr(sp, "call", call)
    monkeypatch.setattr(sp, "validate_tuned_rule", lambda *a: pytest.fail("must not re-validate or publish"))
    assert sp.tune_rule(REPORT, "sast", "js.rule", str(tmp_path / "a.js"), 10, "t", {"id": 1}, out=open(os.devnull, "w")) == []
