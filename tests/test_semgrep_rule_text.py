"""Rule-text handling is testable without running or contacting Semgrep."""

import pytest

from threatlint import semgrep_platform as sp
from threatlint import semgrep_rule_text as text


@pytest.mark.parametrize("language", ["yaml", "yml"])
def test_rule_blocks_are_trimmed_but_fixtures_keep_their_whitespace(language):
    report = (
        f"**Tuned rule**:\n\n```{language}\n\nrules: []\n\n```\n"
        "**Tuned rule fixtures**:\n\n```python\n  x = 1  \n```\n"
    )
    assert text.tuned_rule_from_report(report) == "rules: []\n"
    assert text.fixtures_from_report(report) == "  x = 1  \n"
    assert text.tuned_rule_from_report("none") == ""
    assert text.fixtures_from_report("none") == ""


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("src/a.py", "r.tuned.py"),
        ("config.yaml", "r.tuned.test.yaml"),
        ("config.YML", "r.tuned.test.YML"),
        ("Dockerfile", "r.tuned.dockerfile"),
        ("README", "r.tuned.txt"),
        ("", "r.tuned.txt"),
    ],
)
def test_fixture_names_never_overwrite_the_rule(target, expected):
    assert text.fixture_name("r.tuned", target) == expected


@pytest.mark.parametrize(
    ("rule", "target", "expected"),
    [("", "Dockerfile", True), ("", "src/a.py", False), ("", "", False),
     ("paths:\n  include:\n    - Info.plist\n", "Info.plist", True),
     ("paths:\n  include:\n    - '*.py'\n", "a.py", False)],
)
def test_only_name_sensitive_fixtures_need_a_target_named_copy(rule, target, expected):
    assert text.needs_named_fixture(rule, target) is expected


def test_markers_distinguish_own_lines_next_lines_and_other_rule_ids():
    fixtures = "// ruleid: r.tuned, other\nbad()\nsafe() // ok: r.tuned\n// ok: unrelated\n"
    assert text.fixture_lines(fixtures, "r.tuned") == ([2], [3])
    assert sp._fixture_lines is text.fixture_lines


def test_merge_normalization_only_removes_registry_metadata_and_rule_id():
    rule = (
        "rules:\n  - id: org.rule.tuned\n    metadata:\n"
        "      semgrep.dev:\n        origin: registry\n\n"
        "      source: registry\n      shortlink: link\n      rule-origin-note: note\n"
        "      category: security\n    pattern: source($X)\n"
        "    patterns:\n      - pattern-not: ignored($X)\n"
    )
    normalized = text.normalize_for_merge(rule)
    assert "- id: RULE_ID" in normalized
    assert "registry" not in normalized and "shortlink" not in normalized
    assert "category: security" in normalized
    assert "pattern: source($X)" in normalized
    assert "- pattern-not: ignored($X)" in normalized
    assert normalized.endswith("\n")


def test_exclusions_preserve_exact_payloads_but_ignore_indentation():
    rule = "patterns:\n  - pattern: $X\n  - pattern-not: safe($X)\n    regex: ^safe$\n"
    assert text.exclusions(rule) == ["- pattern-not: safe($X)", "regex: ^safe$"]
    assert sp._exclusions(rule) == text.exclusions(rule)
