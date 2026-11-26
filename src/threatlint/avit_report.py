"""Pure parsing of reviewer dispositions and source locations from AVIT reports."""

from __future__ import annotations

import re

from threatlint.finding_review import (
    FindingReviewError, _field_pattern, _structure, is_conservative, normalize_verdict, report_fields,
)

_DISPOSITION = re.compile(r"TRUE POSITIVE|FALSE POSITIVE|AMBIGUOUS", re.IGNORECASE)
_AVIT_TOKEN = re.compile(r"(?<![A-Z0-9])AVIT\d{7,15}(?![A-Z0-9])", re.IGNORECASE)


class ResolveError(RuntimeError):
    """A user-actionable resolution failure; messages never contain credentials."""


class RuleNotTuned(ResolveError):
    """The AVIT closed with its report but rule tuning did not complete."""

    def __init__(self, reason: str, triage_reason: str = ""):
        super().__init__(reason)
        self.triage_reason = triage_reason


class ClosedAvitSemgrepError(ResolveError):
    """An operational Semgrep failure after ServiceNow confirmed the attachment and closure."""


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
    # The first word alone, without trailing punctuation: "CONFIRMED." and "CONFIRMED (static path only)" are CONFIRMED.
    confidence = re.match(r"[^A-Za-z]*([A-Za-z]+)", _field(body, "Confidence"))
    verdict = {
        "id": identifier,
        "title": title,
        "disposition": dispositions[0] if dispositions else "",
        "confidence": confidence.group(1) if confidence else "",
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


def needs_confirmation(verdict: dict, report: str) -> bool:
    """A true-positive disposition can remain unverified for automated remediation."""
    return verdict.get("disposition") == "TRUE POSITIVE" and (
        is_conservative(verdict) or verdict.get("confidence", "").upper() != "CONFIRMED"
        or any(re.match(r"UNVERIFIED\b", value, re.I) for value in report_fields(report, "Validation status"))
    )


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


def safe_error(exc: Exception) -> str:
    """Keep actionable diagnostics without echoing likely credential values."""
    message = str(exc).replace("\n", " ")[:500]
    message = re.sub(r"(?i)\b(password|passwd|client[_-]?secret|api[_-]?key|access[_-]?token|authorization)\b\s*[:=]\s*\S+",
                     r"\1=[REDACTED]", message)
    message = re.sub(r"\b(?:sk-|ghp_|github_pat_)[A-Za-z0-9_-]+", "[REDACTED]", message)
    return message or type(exc).__name__
