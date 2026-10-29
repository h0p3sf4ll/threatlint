"""Semgrep token setup and rule tuning: nothing is published unless the tuned rule is proven."""

import contextlib
import os
from pathlib import Path
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
    (tmp_path / "a.js").write_text("x", encoding="utf-8")
    monkeypatch.setattr(sp, "_matches", lambda config, target, line, exact=False: [2, 4] if target.endswith("tuned.js") else [10])
    published = []
    monkeypatch.setattr(sp, "publish", lambda *a: published.append(a))
    with pytest.raises(sp.SemgrepError, match="still reports the false-positive location"):
        sp.tune_rule(REPORT + FIXTURES, "sast", "js.rule", str(tmp_path / "a.js"), 10, "t", {"id": 1})
    assert published == []


def test_tuned_rule_replaces_the_original_in_its_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(sp, "_semgrep", lambda args, **kw: types.SimpleNamespace(returncode=0, stdout="All tests passed", stderr=""))
    monkeypatch.setattr(sp, "original_rule_yaml", lambda rule, token: "rules:\n  - id: js.rule\n")
    (tmp_path / "a.js").write_text("x", encoding="utf-8")
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
    changes = sp.tune_rule(REPORT + FIXTURES, "sast", "js.rule", str(tmp_path / "a.js"), 10, "t", {"id": 1}, out=open(os.devnull, "w", encoding="utf-8"))
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

def test_a_rule_whose_live_tuning_covers_the_line_is_not_tuned_again(monkeypatch, tmp_path):
    monkeypatch.undo()
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    def call(path, token, *, method="GET", body=None):
        assert method == "GET", "nothing may change"
        if path.endswith("/1"):
            return {"policies": [{"id": "5", "name": "Global Policy", "productType": "PRODUCT_TYPE_SAST"}]}
        return {"rules": [{"path": "example_org.js.rule.tuned", "policyMode": "MODE_COMMENT"}, {"path": "js.rule", "policyMode": "MODE_DISABLED"}]}
    monkeypatch.setattr(sp, "call", call)
    monkeypatch.setattr(sp, "original_rule_yaml", lambda rule, token: "rules:\n  - id: example_org.js.rule.tuned\n")
    monkeypatch.setattr(sp, "_matches", lambda *a, **k: [])
    monkeypatch.setattr(sp, "validate_tuned_rule", lambda *a: pytest.fail("must not re-validate or publish"))
    assert sp.tune_rule(REPORT, "sast", "js.rule", str(tmp_path / "a.js"), 10, "t", {"id": 1}, out=open(os.devnull, "w", encoding="utf-8")) == []


def test_an_already_tuned_rule_that_still_reports_the_line_is_extended_not_skipped(monkeypatch, tmp_path):
    (tmp_path / "a.js").write_text("x", encoding="utf-8")
    proposal = sp.tuned_rule_from_report(REPORT)
    original = proposal.replace("js.rule.tuned", "js.rule")
    # The live tuned rule gained an exclusion the proposal lacks: appended as its own top-level key.
    live = original.replace("js.rule", "example_org.js.rule.tuned") + "    pattern-sanitizers:\n      - pattern: clean(...)\n"
    monkeypatch.setattr(sp, "existing_tuning", lambda *a: [{"policy": "Global", "tuned": "example_org.js.rule.tuned", "mode": "MODE_COMMENT"}])
    monkeypatch.setattr(sp, "original_rule_yaml", lambda rule, token: original if rule == "js.rule" else live)
    monkeypatch.setattr(sp, "_matches", lambda config, target, line, exact=False: [10])
    monkeypatch.setattr(sp, "replace_in_policies", lambda *a: pytest.fail("an extended rule keeps its policy entries"))
    seen = {}
    class Stop(Exception):
        pass
    def validate(rule, *a, **k):
        seen["rule"] = rule
        raise Stop
    monkeypatch.setattr(sp, "validate_tuned_rule", validate)
    with pytest.raises(Stop):
        sp.tune_rule(REPORT + FIXTURES, "sast", "js.rule", str(tmp_path / "a.js"), 10, "t", {"id": 1}, out=open(os.devnull, "w", encoding="utf-8"))
    assert "pattern: clean(...)" in seen["rule"] and seen["rule"].startswith("rules:\n  - id: js.rule.tuned"), "the live rule's change is merged in before the proof gate"


def test_an_already_tuned_rule_that_no_longer_reports_the_line_needs_no_change(monkeypatch, tmp_path):
    (tmp_path / "a.js").write_text("x", encoding="utf-8")
    monkeypatch.setattr(sp, "existing_tuning", lambda *a: [{"policy": "Global", "tuned": "example_org.js.rule.tuned", "mode": "MODE_COMMENT"}])
    monkeypatch.setattr(sp, "original_rule_yaml", lambda rule, token: "rules:\n  - id: x\n")
    monkeypatch.setattr(sp, "_matches", lambda *a, **k: [])
    monkeypatch.setattr(sp, "publish", lambda *a: pytest.fail("nothing to publish"))
    monkeypatch.setattr(sp, "disable_originals", lambda *a: [])
    assert sp.tune_rule("no block", "sast", "js.rule", str(tmp_path / "a.js"), 10, "t", {"id": 1}, out=open(os.devnull, "w", encoding="utf-8")) == []


def test_an_original_left_enabled_beside_its_tuned_rule_is_disabled(monkeypatch, tmp_path):
    monkeypatch.undo()
    monkeypatch.setenv("THREATLINT_HOME", str(tmp_path))
    (tmp_path / "a.js").write_text("x", encoding="utf-8")
    puts = []
    def call(path, token, *, method="GET", body=None):
        if method == "PUT":
            puts.append((path, body))
            return {}
        if path.endswith("/1"):
            return {"policies": [{"id": "5", "name": "Global Policy", "productType": "PRODUCT_TYPE_SAST"}]}
        return {"rules": [{"path": "example_org.js.rule.tuned", "policyMode": "MODE_MONITOR"}, {"path": "js.rule", "policyMode": "MODE_MONITOR"},
                          {"path": "other.js.rule2", "policyMode": "MODE_MONITOR"}]}
    monkeypatch.setattr(sp, "call", call)
    monkeypatch.setattr(sp, "original_rule_yaml", lambda rule, token: "rules:\n  - id: example_org.js.rule.tuned\n")
    monkeypatch.setattr(sp, "_matches", lambda *a, **k: [])
    assert sp.tune_rule("no block", "sast", "js.rule", str(tmp_path / "a.js"), 10, "t", {"id": 1}, out=open(os.devnull, "w", encoding="utf-8")) == []
    assert puts == [("/api/policies/v1/deployments/1/5/rules/js.rule", {"policyMode": "MODE_DISABLED"})], "only the original is disabled, the tuned rule and others are untouched"


def test_concurrent_extensions_of_one_live_rule_are_merged():
    base = "rules:\n- id: r\n  pattern-sinks:\n  - patterns:\n    - pattern: q($X)\n  pattern-sanitizers:\n  - pattern: clean(...)\n  message: m\n"
    live = base.replace("- id: r", "- id: org.r.tuned").replace("    - pattern: q($X)\n", "    - pattern: q($X)\n    - metavariable-regex:\n        metavariable: $X\n        regex: ^LIVE$\n")
    proposed = base.replace("- id: r", "- id: r.tuned").replace("  - pattern: clean(...)\n", "  - pattern: clean(...)\n  - patterns:\n    - pattern: mine(...)\n")
    merged = sp.merge_exclusions(proposed, live, base)
    assert merged.startswith("rules:\n- id: r.tuned\n") and "regex: ^LIVE$" in merged and "mine(...)" in merged, merged
    clash = live.replace("^LIVE$", "^MINE$")
    assert sp.merge_exclusions(clash.replace("org.r.tuned", "r.tuned"), live.replace("^LIVE$", "^OTHER$"), live.replace("org.r.tuned", "r")) is None
    assert sp.merge_exclusions(proposed, live) is None, "no common ancestor, no merge"


def test_fixture_markers_on_the_line_before_or_at_the_end_of_the_line():
    fixtures = "// ruleid: r.tuned\nclass A {\nclass B { // ok: r.tuned\n# ok: r.tuned\nclass C {\n"
    assert sp._fixture_lines(fixtures, "r.tuned") == ([2], [3, 5])


def test_fixture_markers_inside_xml_and_block_comments():
    fixtures = "<!-- ruleid: r.tuned -->\n<key>A</key>\n<!-- ok: r.tuned -->\n<key>B</key>\n/* ok: r.tuned */\nx\n"
    assert sp._fixture_lines(fixtures, "r.tuned") == ([2], [4, 6])


def test_a_yaml_fixture_does_not_overwrite_the_rule_file(monkeypatch, tmp_path):
    seen = {}
    def semgrep(args, **kw):
        if "--test" in args:
            seen.update({p.name: p.read_text(encoding="utf-8") for p in Path(args[-1]).iterdir() if p.is_file()})
        return types.SimpleNamespace(returncode=0, stdout="All tests passed", stderr="")
    monkeypatch.setattr(sp, "_semgrep", semgrep)
    monkeypatch.setattr(sp, "_matches", lambda config, target, line, exact=False: [])
    rule = "rules:\n  - id: yaml.rule.tuned\n    languages: [yaml]\n"
    fixtures = "# ruleid: yaml.rule.tuned\nkey: x\n"
    with contextlib.suppress(sp.SemgrepError):
        sp.validate_tuned_rule(rule, "", str(tmp_path / "values.yaml"), 2, fixtures)
    assert seen == {"yaml.rule.tuned.yaml": rule, "yaml.rule.tuned.test.yaml": fixtures}


def test_a_code_rule_behind_a_secrets_avit_is_replaced_in_the_code_policy(monkeypatch):
    puts = []
    def call(path, token, *, method="GET", body=None):
        if method == "PUT":
            puts.append(path.rsplit("/", 2)[-2:])
            return {}
        if path.endswith("/1"):
            return {"policies": [{"id": "5", "name": "Global Policy", "productType": "PRODUCT_TYPE_SAST"},
                                 {"id": "6", "name": "Secrets", "productType": "PRODUCT_TYPE_SECRETS"}]}
        return {"rules": [{"path": "yaml.rule", "policyMode": "MODE_MONITOR"}] if "/5/" in path else []}
    monkeypatch.setattr(sp, "call", call)
    changes = sp.replace_in_policies("t", {"id": 1}, "secrets", "yaml.rule", "org.yaml.rule.tuned")
    assert [c["policy"] for c in changes] == ["Global Policy"] and puts == [["rules", "org.yaml.rule.tuned"], ["rules", "yaml.rule"]]
