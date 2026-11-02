"""Pure catalog-task number parsing, journal interpretation, and developer comments."""

from __future__ import annotations

import re

_SCTASK = re.compile(r"SCTASK\d{7,10}")


def parse_sctask_numbers(text: str) -> list[str]:
    return list(dict.fromkeys(_SCTASK.findall(str(text or "").upper())))


def avits_in(text: str, pattern: re.Pattern) -> list[str]:
    """AVIT numbers in free text, in order of appearance, without duplicates."""
    return list(dict.fromkeys(pattern.findall(str(text or "").upper())))


def journal_disposition(notes: str, comments: tuple[tuple[str, str], ...]) -> str:
    """The journal is newest-first, so its first matching work note wins."""
    found = sorted((notes.find(text), label) for text, label in comments if text in notes)
    return found[0][1] if found else "NOT REVIEWED"


def all_decided(outcomes: list[dict]) -> bool:
    return all(item["disposition"] in ("TRUE POSITIVE", "FALSE POSITIVE") for item in outcomes)


def closing_comment(outcomes: list[dict], leave_open: bool = False) -> str:
    """The comment developers see on the task: one line per AVIT, then where to go next."""
    decided = all_decided(outcomes)
    opening = ("Reviewed by Threatlint. Every AVIT below has a decision, so this task can be closed." if leave_open and decided
               else "Reviewed by Threatlint." if leave_open else "Closed by Threatlint.")
    lines = [f"{opening} Each AVIT below was reviewed against its repository and branch, and its report is attached to this task.", ""]
    for item in outcomes:
        lines.append({
            "FALSE POSITIVE": f"- {item['avit']}: false positive, closed by Threatlint.",
            "TRUE POSITIVE": f"- {item['avit']}: true positive, still open. Please remediate it in {item['avit']}.",
            "AMBIGUOUS": f"- {item['avit']}: could not be decided from the code; left open for AppSec follow-up (see its report).",
        }.get(item["disposition"], f"- {item['avit']}: not reviewed ({item['disposition'].lower()}); left open for AppSec follow-up."))
    true_positives = [item["avit"] for item in outcomes if item["disposition"] == "TRUE POSITIVE"]
    lines.append("")
    if true_positives:
        lines.append(f"Developers: {', '.join(true_positives)} {'is a confirmed finding' if len(true_positives) == 1 else 'are confirmed findings'} "
                     "and must be fixed in the AVIT itself. Each attached report gives the evidence, the proposed fix and the acceptance criteria.")
    lines.append("If you have questions about any decision, review the attached report for that AVIT first, then contact Application Security.")
    return "\n".join(lines)
