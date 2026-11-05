"""Pure FP-report syntax parsing; reference selection and actionable errors live in base."""

from __future__ import annotations

import re

from threatlint.finding_review import FindingReviewError, normalize_verdict

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

        stated = re.findall(r"(?im)^\**(?:Disposition|Verdict)\**\s*:\s*(.+)$", body)
        values = [value if disposition_pattern.search(value) else "" for value in stated]
        normalized = [normalize_verdict({"disposition": value}) for value in values]
        if len({item["disposition"] for item in normalized}) > 1:
            raise FindingReviewError("The finding has conflicting dispositions; resolve it manually")
        identifier = re.match(r"\[([A-Z][A-Z0-9]*-\d+)\]", header)
        verdict = {
            "id": identifier.group(1) if identifier else "",
            "title": re.sub(r"^\[[^\]]+\]\s*[—–:-]?\s*", "", header).strip(),
            "disposition": "AMBIGUOUS" if any(item.get("decision_basis") for item in normalized)
                           else normalized[0]["disposition"] if normalized else "",
            "confidence": field("Confidence").split()[0] if field("Confidence") else "",
        }
        parsed.append((original.group(1) if original else header, normalize_verdict(verdict, body=body)))
    return parsed


def report_line(report: str, reference: str) -> int | None:
    """The Original finding's trailing path:line when the scanner record has no line."""
    match = re.search(rf"Original finding\W*:\s*{re.escape(reference)};[^\n]*:(\d+)\s*$", report, re.M | re.I)
    return int(match.group(1)) if match else None
