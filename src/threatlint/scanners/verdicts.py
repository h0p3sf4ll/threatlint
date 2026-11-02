"""Pure FP-report syntax parsing; reference selection and actionable errors live in base."""

from __future__ import annotations

import re

_DISPOSITION = re.compile(r"TRUE POSITIVE|FALSE POSITIVE|AMBIGUOUS", re.IGNORECASE)


def mentions(text: str, reference: str) -> bool:
    """Match whole references, so DOJO-12 cannot select DOJO-123."""
    return re.search(rf"(?<![\w-]){re.escape(reference)}(?![\w-])", text or "", re.IGNORECASE) is not None


def candidates(report: str, *, disposition_pattern: re.Pattern[str] = _DISPOSITION) -> list[tuple[str, dict[str, str]]]:
    """Return each finding's original reference text (or heading) and parsed verdict fields."""
    sections = re.split(r"(?m)^#{2,6}\s+(?=\[[A-Z][A-Z0-9]*-\d+\])", report)
    parsed = []
    for section in sections[1:]:
        header, _, body = section.partition("\n")
        original = re.search(r"(?im)^\**Original finding\**\s*:\s*(.+)$", body)

        def field(name: str) -> str:
            match = re.search(rf"(?im)^\**(?:{name})\**\s*:\s*(.+)$", body)
            return match.group(1).replace("*", "").strip() if match else ""

        disposition = disposition_pattern.search(field("Disposition|Verdict"))
        identifier = re.match(r"\[([A-Z][A-Z0-9]*-\d+)\]", header)
        verdict = {
            "id": identifier.group(1) if identifier else "",
            "title": re.sub(r"^\[[^\]]+\]\s*[—–:-]?\s*", "", header).strip(),
            "disposition": disposition.group(0).upper() if disposition else "",
            "confidence": field("Confidence").split()[0] if field("Confidence") else "",
        }
        parsed.append((original.group(1) if original else header, verdict))
    return parsed


def report_line(report: str, reference: str) -> int | None:
    """The Original finding's trailing path:line when the scanner record has no line."""
    match = re.search(rf"Original finding\W*:\s*{re.escape(reference)};[^\n]*:(\d+)\s*$", report, re.M | re.I)
    return int(match.group(1)) if match else None
