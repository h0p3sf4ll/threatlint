"""Deterministic rendering and original ServiceNow formatter seams."""

import pytest

from threatlint import servicenow as sn
from threatlint import servicenow_markdown as markdown


def test_fields_are_ordered_escaped_and_fenced_without_reinterpreting_evidence():
    lines = markdown.field_lines({
        "z": "last", "number": "AVIT0042599", "a": "x|y", "long": "first\n~~~\nlast",
    })
    assert lines == [
        "| Field | Value |", "|---|---|", "| number | AVIT0042599 |",
        "| a | x\\|y |", "| z | last |", "", "**long**", "", "~~~text",
        "first\n~ ~ ~\nlast", "~~~",
    ]


def test_inline_length_boundary():
    assert "| a | " + "x" * 160 + " |" in markdown.field_lines({"a": "x" * 160})
    assert "~~~text" in markdown.field_lines({"a": "x" * 161})


def test_artifact_has_an_explicit_timestamp_and_preserves_reference_sections():
    result = markdown.avits_markdown(
        "https://example.service-now.com",
        [{"fields": {"number": "AVIT0042599", "short_description": "Synthetic"},
          "references": {"vulnerability": {"rule": "synthetic"}}}],
        ["AVIT0042599"], [], None, retrieved="2026-01-02 03:04 UTC", table="test_table",
        render_context=lambda item: ["review target"],
    )
    assert "- Source: https://example.service-now.com table `test_table`" in result
    assert "- Retrieved: 2026-01-02 03:04 UTC" in result
    assert "- Not found or not readable: none" in result
    assert "## AVIT0042599 — Synthetic\n\nreview target" in result
    assert "### Referenced vulnerability\n\n| Field | Value |\n|---|---|\n| rule | synthetic |\n" in result


@pytest.mark.parametrize(
    ("view", "expected"),
    [("CodeSecurity", "unavailable: missing"), ("Other", "none on this AVIT (missing)")],
)
def test_repository_errors_are_rendered_according_to_the_view(view, expected):
    def missing(context):
        raise sn.ServiceNowError("missing")

    lines = markdown.context_lines(
        {"fields": {}, "view": view}, finding_kind=lambda item: "sast",
        repository_target=missing, error_type=sn.ServiceNowError,
    )
    assert f"| Repository | {expected} |" in lines


def test_original_formatter_resolves_dependencies_at_call_time(monkeypatch):
    monkeypatch.setattr(sn, "repository_target", lambda context: {"web_url": "synthetic", "branch": "test"})
    monkeypatch.setattr(sn, "finding_kind", lambda item: "sca")
    lines = sn._context_lines({"fields": {}})
    assert "| Repository | synthetic |" in lines
    assert "| Finding type | SCA (Semgrep Supply Chain) |" in lines
    monkeypatch.setattr(sn, "_context_lines", lambda item: ["custom context"])
    monkeypatch.setattr(sn, "_field_lines", lambda fields: ["custom fields"])
    rendered = sn.avits_markdown("instance", [{"fields": {}, "references": {}}], [], [])
    assert "custom context" in rendered and "custom fields" in rendered
