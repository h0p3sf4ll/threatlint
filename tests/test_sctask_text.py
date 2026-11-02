"""Pure journal interpretation and comments preserve catalog-task decisions."""

import pytest

from threatlint import sctask
from threatlint import sctask_text as text

COMMENTS = (("false note", "FALSE POSITIVE"), ("true note", "TRUE POSITIVE"), ("ambiguous note", "AMBIGUOUS"))


@pytest.mark.parametrize(
    ("notes", "expected"),
    [("true note\nfalse note", "TRUE POSITIVE"),
     ("ambiguous note\ntrue note", "AMBIGUOUS"),
     ("false note\nambiguous note", "FALSE POSITIVE"),
     ("unrelated", "NOT REVIEWED")],
)
def test_newest_matching_journal_entry_wins(notes, expected):
    assert text.journal_disposition(notes, COMMENTS) == expected


def test_task_numbers_are_case_insensitive_ordered_and_deduplicated():
    assert text.parse_sctask_numbers("sctask1234567 SCTASK7654321 SCTASK1234567") == [
        "SCTASK1234567", "SCTASK7654321",
    ]
    assert sctask.parse_sctask_numbers is text.parse_sctask_numbers


@pytest.mark.parametrize("pending", ["AMBIGUOUS", "NOT REVIEWED", "NOT FOUND"])
def test_unresolved_outcomes_prevent_a_complete_decision(pending):
    outcomes = [{"avit": "AVIT0042599", "disposition": pending}]
    assert not text.all_decided(outcomes)
    comment = text.closing_comment(outcomes, leave_open=True)
    assert "so this task can be closed" not in comment
    assert "left open for AppSec follow-up" in comment


def test_true_positive_comment_keeps_remediation_on_the_avit():
    comment = text.closing_comment([
        {"avit": "AVIT0042599", "disposition": "TRUE POSITIVE"},
        {"avit": "AVIT0042600", "disposition": "FALSE POSITIVE"},
    ])
    assert "AVIT0042599 is a confirmed finding" in comment
    assert "must be fixed in the AVIT itself" in comment
    assert sctask.closing_comment is text.closing_comment
