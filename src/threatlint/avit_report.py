"""Pure parsing of reviewer dispositions and source locations from AVIT reports."""

from __future__ import annotations

import re

_DISPOSITION = re.compile(r"TRUE POSITIVE|FALSE POSITIVE|AMBIGUOUS", re.IGNORECASE)
_AVIT_TOKEN = re.compile(r"(?<![A-Z0-9])AVIT\d{7,15}(?![A-Z0-9])", re.IGNORECASE)


class ResolveError(RuntimeError):
    """A user-actionable resolution failure; messages never contain credentials."""


def _field(body: str, name: str) -> str:
    match = re.search(rf"(?im)^\**(?:{name})\**\s*:\s*(.+)$", body)
    return match.group(1).replace("*", "").strip() if match else ""


def _verdict(body: str, identifier: str, title: str) -> dict[str, str]:
    stated = re.findall(r"(?im)^\**(?:Disposition|Verdict)\**\s*:\s*(.+)$", body)
    dispositions = [match.group(0).upper() if (match := _DISPOSITION.search(value)) else "" for value in stated]
    if len(set(dispositions)) > 1:
        raise ResolveError(f"{identifier or title} has conflicting dispositions; resolve it manually")
    confidence = _field(body, "Confidence").split()
    return {
        "id": identifier,
        "title": title,
        "disposition": dispositions[0] if dispositions else "",
        "confidence": confidence[0] if confidence else "",
    }


def _mentions_avit(text: str, avit: str) -> bool:
    """Match a complete AVIT number, never a prefix of another record number."""
    return any(match.group(0).upper() == avit.upper() for match in _AVIT_TOKEN.finditer(text))


def verdict_for(report: str, avit: str) -> dict[str, str]:
    """Find this AVIT's verdict, rejecting absent or conflicting dispositions."""
    sections = re.split(r"(?m)^#{2,6}\s+(?=\[?[A-Z][A-Z0-9]*-\d+\b)", report)
    matches = []
    for section in sections[1:]:
        header, _, body = section.partition("\n")
        original = re.search(r"(?im)^\**Original finding\**\s*:\s*(.+)$", body)
        if not _mentions_avit(original.group(1) if original else header, avit):
            continue
        identifier = re.match(r"\[?([A-Z][A-Z0-9]*-\d+)\]?", header)
        title = re.sub(r"^\[?[A-Z][A-Z0-9]*-\d+\]?\s*[—–:-]?\s*", "", header).strip()
        matches.append(_verdict(body, identifier.group(1) if identifier else "", title))
    if not matches:
        # A plain single-finding heading has no FP identifier; its original-finding line decides.
        originals = [
            match for match in re.finditer(r"(?im)^\**Original finding\**\s*:\s*(.+)$", report)
            if _mentions_avit(match.group(1), avit)
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
