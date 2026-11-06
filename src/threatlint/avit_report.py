"""Pure parsing of reviewer dispositions and source locations from AVIT reports."""

from __future__ import annotations

import re

from threatlint.finding_review import (
    FindingReviewError, _field_pattern, _structure, normalize_verdict, report_fields,
)

_DISPOSITION = re.compile(r"TRUE POSITIVE|FALSE POSITIVE|AMBIGUOUS", re.IGNORECASE)
_AVIT_TOKEN = re.compile(r"(?<![A-Z0-9])AVIT\d{7,15}(?![A-Z0-9])", re.IGNORECASE)


class ResolveError(RuntimeError):
    """A user-actionable resolution failure; messages never contain credentials."""


def _field(body: str, name: str) -> str:
    values = report_fields(body, name)
    return values[0] if values else ""


def _verdict(body: str, identifier: str, title: str) -> dict[str, str]:
    stated = report_fields(body, "Disposition") + report_fields(body, "Verdict")
    try:
        normalized = [normalize_verdict({"disposition": value}) for value in stated]
    except FindingReviewError as exc:
        raise ResolveError(str(exc)) from None
    dispositions = [item["disposition"] for item in normalized]
    if len(set(dispositions)) > 1:
        raise ResolveError(f"{identifier or title} has conflicting dispositions; resolve it manually")
    confidence = _field(body, "Confidence").split()
    verdict = {
        "id": identifier,
        "title": title,
        "disposition": dispositions[0] if dispositions else "",
        "confidence": confidence[0] if confidence else "",
    }
    legacy = any(item.get("decision_basis") for item in normalized)
    if legacy:
        verdict["disposition"] = "AMBIGUOUS"
    return normalize_verdict(verdict, body=body)


def _mentions_avit(text: str, avit: str) -> bool:
    """Match a complete AVIT number, never a prefix of another record number."""
    return any(match.group(0).upper() == avit.upper() for match in _AVIT_TOKEN.finditer(text))


def verdict_for(report: str, avit: str) -> dict[str, str]:
    """Find this AVIT's verdict, rejecting absent or conflicting dispositions."""
    structural = _structure(report)
    boundaries = list(re.finditer(r"(?m)^#{2,6}[ \t]+(?=\[?[A-Z][A-Z0-9]*-\d+\b)", structural))
    matches = []
    for index, boundary in enumerate(boundaries):
        end = boundaries[index + 1].start() if index + 1 < len(boundaries) else len(report)
        section = report[boundary.end():end]
        header, _, body = section.partition("\n")
        original = _field(body, "Original finding")
        if not _mentions_avit(original or header, avit):
            continue
        identifier = re.match(r"\[?([A-Z][A-Z0-9]*-\d+)\]?", header)
        title = re.sub(r"^\[?[A-Z][A-Z0-9]*-\d+\]?\s*[—–:-]?\s*", "", header).strip()
        matches.append(_verdict(body, identifier.group(1) if identifier else "", title))
    if not matches:
        # A plain single-finding heading has no FP identifier; its original-finding line decides.
        all_originals = list(_field_pattern("Original finding").finditer(structural))
        originals = [
            match for match in all_originals if _mentions_avit(match.group(2), avit)
        ]
        if len(originals) == 1 and len(all_originals) == 1:
            title = re.search(r"(?m)^#[ \t]+(.+)$", structural)
            matches.append(_verdict(
                report[originals[0].start():], "", title.group(1).strip() if title else avit,
            ))
    if not matches:
        raise ResolveError(f"The report has no finding whose Original finding is {avit}")
    if len({match["disposition"] for match in matches}) > 1:
        raise ResolveError(f"The report gives {avit} conflicting dispositions; resolve it manually")
    if not matches[0]["disposition"]:
        raise ResolveError(f"{matches[0]['id'] or avit} has no TRUE POSITIVE / FALSE POSITIVE disposition")
    return matches[0]


def report_line(report: str, avit: str, expected_path: str = "") -> int | None:
    """Read only this AVIT's explicit original location, never nearby evidence citations."""
    if not _AVIT_TOKEN.fullmatch(avit):
        return None

    def unquote(value: str) -> str:
        value = value.strip()
        return value[1:-1] if value.startswith("`") and value.endswith("`") else value

    def normalized_path(value: str) -> str:
        return value.replace("\\", "/").removeprefix("./").lstrip("/")

    locations = set()
    for field in report_fields(report, "Original finding"):
        parts = field.split(";")
        if unquote(parts[0]).upper() != avit.upper():
            continue
        if len(parts) < 2:
            return None
        # Reports commonly format the location as inline code or finish the
        # sentence with a period. Neither changes the scanner's source location.
        location = unquote(parts[-1].strip().removesuffix(".").rstrip())
        match = re.fullmatch(r"([^`;\n]+):([0-9]+)(?:[-–]([0-9]+))?", location)
        if not match:
            return None
        path = normalized_path(match.group(1).strip())
        start = int(match.group(2))
        end = int(match.group(3)) if match.group(3) else start
        if not path or start < 1 or end < start:
            return None
        if expected_path and path != normalized_path(expected_path):
            return None
        locations.add((path, start, end))
    return next(iter(locations))[1] if len(locations) == 1 else None
