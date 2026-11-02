"""Pure AVIT record decoding, without credentials or network access."""

import pytest

from threatlint import servicenow as sn
from threatlint import servicenow_records as records


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, ""), (0, "0"), (" x ", "x"),
        ({"display_value": "Shown", "value": "stored"}, "Shown"),
        ({"display_value": "", "value": "stored"}, "stored"),
        ({}, ""),
    ],
)
def test_display_values_are_preferred_and_trimmed(raw, expected):
    assert records.field_value(raw) == expected


def test_values_are_bounded_and_system_metadata_is_not_exposed():
    assert records.field_value("x" * 5000) == "x" * 4000
    assert records.flatten({
        "sys_id": "id", "sys_created_on": "created", "sys_updated_on": "updated",
        "sys_secret": "hidden", "sys_tags": "ignored", "number": "AVIT0042599",
        "empty": None,
    }) == {
        "sys_id": "id", "sys_created_on": "created", "sys_updated_on": "updated",
        "number": "AVIT0042599",
    }


def test_form_labels_override_aliases_and_empty_labels_fall_back():
    fields = {"u_repo": "alias", "u_custom": " label ", "u_SCM_Tool": "GitHub", "u_Start_Line": "42"}
    assert records.avit_context(fields, {"repository": "u_custom"}) == {
        "repository": "label", "scm_tool": "GitHub", "line": "42",
    }
    assert records.avit_context(fields, {"repository": "empty"})["repository"] == "alias"


@pytest.mark.parametrize(
    ("source", "kind"),
    [("SCA", "sca"), ("Open Source", "sca"), ("Supply Chain", "sca"),
     ("Secret", "secrets"), ("SAST", "sast"), ("", "sast")],
)
def test_finding_source_selects_the_product(source, kind):
    assert records.finding_kind({"context": {"finding_source": source}}) == kind


def test_explicit_view_membership_takes_precedence_over_scm_presence():
    context = {"scm_tool": "GitHub", "repository": "repo"}
    assert records.in_code_security_view({"context": context})
    assert not records.in_code_security_view({"context": context, "in_view": False})
    assert records.in_code_security_view({"in_view": True})
    assert not records.in_code_security_view({})


def test_original_facade_passes_its_field_and_normalization_seams(monkeypatch):
    monkeypatch.setattr(sn, "_field_value", lambda raw: f"value:{raw}")
    assert sn._flatten({"number": "123"}) == {"number": "value:123"}
    monkeypatch.setattr(sn, "_normalized", lambda name: "repository")
    assert sn.avit_context({"custom": "repo"}) == {"repository": "repo"}
