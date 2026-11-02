"""Pure parsing of reviewer dispositions and source locations from AVIT reports."""

from __future__ import annotations

import re

_DISPOSITION = re.compile(r"TRUE POSITIVE|FALSE POSITIVE|AMBIGUOUS", re.IGNORECASE)


class ResolveError(RuntimeError):
    """A user-actionable resolution failure; messages never contain credentials."""


def _field(body: str, name: str) -> str:
    match = re.search(rf"(?im)^\**(?:{name})\**\s*:\s*(.+)$", body)
    return match.group(1).replace("*", "").strip() if match else ""


def _verdict(body: str, identifier: str, title: str) -> dict[str, str]:
    disposition = _DISPOSITION.search(_field(body, "Disposition|Verdict"))
    confidence = _field(body, "Confidence").split()
    return {
        "id": identifier,
        "title": title,
        "disposition": disposition.group(0).upper() if disposition else "",
        "confidence": confidence[0] if confidence else "",
    }


def verdict_for(report: str, avit: str) -> dict[str, str]:
    """Find this AVIT's verdict, rejecting absent or conflicting dispositions."""
    sections = re.split(r"(?m)^#{2,6}\s+(?=\[?[A-Z][A-Z0-9]*-\d+\b)", report)
    matches = []
    for section in sections[1:]:
        header, _, body = section.partition("\n")
        original = re.search(r"(?im)^\**Original finding\**\s*:\s*(.+)$", body)
        if avit not in (original.group(1) if original else header).upper():
            continue
        identifier = re.match(r"\[?([A-Z][A-Z0-9]*-\d+)\]?", header)
        title = re.sub(r"^\[?[A-Z][A-Z0-9]*-\d+\]?\s*[—–:-]?\s*", "", header).strip()
        matches.append(_verdict(body, identifier.group(1) if identifier else "", title))
    if not matches:
        # A plain single-finding heading has no FP identifier; its original-finding line decides.
        originals = [
            match for match in re.finditer(r"(?im)^\**Original finding\**\s*:\s*(.+)$", report)
            if avit in match.group(1).upper()
        ]
        if len(originals) == 1 and len(re.findall(r"(?im)^\**Original finding\**\s*:", report)) == 1:
            title = re.search(r"(?m)^#\s+(.+)$", report)
            matches.append(_verdict(
                report[originals[0].start():], "", title.group(1).strip() if title else avit,
            ))
    if not matches:
        raise ResolveError(f"The report has no finding whose Original finding is {avit}")
    if len({match["disposition"] for match in matches}) > 1:
        raise ResolveError(f"The report gives {avit} conflicting dispositions; resolve it manually")
    if not matches[0]["disposition"]:
        raise ResolveError(f"{matches[0]['id'] or avit} has no TRUE POSITIVE / FALSE POSITIVE / AMBIGUOUS disposition")
    return matches[0]


def report_line(report: str, avit: str) -> int | None:
    match = re.search(rf"Original finding\W*:\s*{avit};[^\n]*:(\d+)\s*$", report, re.M)
    return int(match.group(1)) if match else None
