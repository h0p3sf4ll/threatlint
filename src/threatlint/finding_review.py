"""Binary finding-review decisions and compatible normalization of legacy reports."""

from __future__ import annotations

import re

TITLE = "Finding Review"
DISPOSITIONS = ("TRUE POSITIVE", "FALSE POSITIVE")
_LABEL = re.compile(r"\b(?:TRUE POSITIVE|FALSE POSITIVE|AMBIGUOUS)\b", re.IGNORECASE)
_FIELD_START = r" {0,3}(?:[-*+][ \t]+)?"


def _field_pattern(names: str) -> re.Pattern:
    """Match a labeled metadata line, preserving its prefix and value separately."""
    return re.compile(
        rf"(?im)^({_FIELD_START}(?:\*\*(?:{names})(?:[ \t]*:[ \t]*\*\*|\*\*[ \t]*:)"
        rf"|(?:{names})[ \t]*:)[ \t]*)([^\r\n]+)\r?$"
    )


_DECLARATION = _field_pattern("Disposition|Verdict")
CONSERVATIVE_BASIS = "CONSERVATIVE DEFAULT"
CONSERVATIVE_REASON = (
    "False positive was not proven beyond reasonable doubt, so the finding is treated as TRUE POSITIVE. "
    "The original uncertainty, confidence, evidence gaps, and validation limits still apply; "
    "this decision does not establish exploit reproduction or independent verification."
)


class FindingReviewError(ValueError):
    """A report declares an invalid or conflicting finding decision."""


def normalize_disposition(value: str) -> str:
    """Return a binary label, preserving an absent/unknown label for caller validation."""
    labels = {"TRUE POSITIVE" if match.group(0).upper() == "AMBIGUOUS" else match.group(0).upper()
              for match in _LABEL.finditer(value or "")}
    if len(labels) > 1:
        raise FindingReviewError("The finding has conflicting dispositions; resolve it manually")
    return next(iter(labels), "")


def is_conservative(verdict: dict) -> bool:
    """A default triage decision is separate from an evidence-backed confirmation."""
    return (verdict.get("unverified") is True
            or str(verdict.get("disposition", "")).upper() == "AMBIGUOUS"
            or str(verdict.get("decision_basis", "")).upper() == CONSERVATIVE_BASIS)


def _structure(body: str) -> str:
    """Mask fenced examples while retaining character offsets into the original report."""
    fence, lines = None, []
    for line in body.splitlines(keepends=True):
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        masked = fence is not None or marker is not None
        if marker:
            if fence is None:
                fence = marker.group(1)
            elif marker.group(1).startswith(fence):
                fence = None
        lines.append(re.sub(r"[^\r\n]", " ", line) if masked else line)
    return "".join(lines)


def report_fields(body: str, name: str) -> list[str]:
    """Read actual metadata declarations without treating fenced examples as decisions."""
    return [match.group(2).replace("*", "").strip()
            for match in _field_pattern(re.escape(name)).finditer(_structure(body))]


def report_section(body: str, aliases: tuple[str, ...]) -> str:
    """Read a Markdown field or heading, retaining quoted code inside its section."""
    structural = _structure(body)
    names = "|".join(re.escape(name) for name in aliases)
    ending = r"(?:[ \t]*:[ \t]*\*\*|\*\*[ \t]*:|\*\*(?=[ \t]*\r?$))"
    match = re.search(
        rf"(?im)^{_FIELD_START}(?:\*\*(?:{names}){ending}"
        rf"|#{{2,6}}[ \t]+(?:{names})[ \t]*:?[ \t]*(?:#+[ \t]*)?\r?$)", structural,
    )
    if not match:
        return ""
    next_field = re.search(
        rf"(?m)^{_FIELD_START}(?:\*\*[^*\r\n]+?{ending}|#{{1,6}}[ \t])",
        structural[match.end():],
    )
    end = match.end() + next_field.start() if next_field else len(body)
    return body[match.end():end].strip()


def _proof_section(body: str, name: str) -> str:
    """Require substantive report sections; semantic adjudication remains the reviewer's job."""
    value = report_section(body, (name,))
    return "" if re.fullmatch(r"(?:none|n/a|unknown|not available|not inspected|unverified|tbd)[.!]?", value, re.I) else value


def has_fp_evidence(body: str) -> bool:
    """A labeled FP without both inspected evidence and its safe semantics is not proven."""
    return bool(_proof_section(body, "Evidence") and _proof_section(body, "Verified Safe Behavior"))


def normalize_verdict(verdict: dict, *, body: str | None = None) -> dict:
    """Keep finding metadata and add explicit reasoning when converting a legacy label."""
    result = dict(verdict)
    raw = str(result.get("disposition", ""))
    result["disposition"] = normalize_disposition(raw)
    bases = report_fields(body or "", "Decision basis")
    unsupported_fp = result["disposition"] == "FALSE POSITIVE" and body is not None and not has_fp_evidence(body)
    conservative = (bool(re.search(r"\bAMBIGUOUS\b", raw, re.IGNORECASE))
                    or any(basis.upper().startswith(CONSERVATIVE_BASIS) for basis in bases)
                    or is_conservative(result) or unsupported_fp)
    if conservative:
        result["disposition"] = "TRUE POSITIVE"
        result["unverified"] = True
        result["decision_basis"] = CONSERVATIVE_BASIS
        result["decision_rationale"] = CONSERVATIVE_REASON
    return result


def normalize_report(markdown: str) -> str:
    """Relabel a finding report and normalize declared legacy outcomes without inventing evidence."""
    heading = re.compile(r"(?im)^(#\s+)(?:false[ -]+positive review|fp review|findings? review)\b")
    actual = {match.start() for match in heading.finditer(_structure(markdown))}
    output = heading.sub(lambda match: match.group(1) + TITLE if match.start() in actual else match.group(0), markdown)
    renamed = bool(actual)
    if not renamed:
        output = f"# {TITLE}\n\n{output}"

    def declaration(match: re.Match, body: str) -> str:
        raw = match.group(2)
        normalized = normalize_disposition(raw)
        if not normalized:
            raise FindingReviewError("A finding review has an unsupported disposition; use TRUE POSITIVE or FALSE POSITIVE")
        if not re.search(r"\bAMBIGUOUS\b", raw, re.IGNORECASE) and not (
            normalized == "FALSE POSITIVE" and not has_fp_evidence(body)
        ):
            return match.group(0)
        # Preserve the report's confidence and all surrounding evidence/limitations verbatim.
        converted = re.sub(r"\b(?:AMBIGUOUS|FALSE POSITIVE)\b", "TRUE POSITIVE", raw, flags=re.IGNORECASE)
        return (f"{match.group(1)}{converted}\n"
                f"**Decision basis**: {CONSERVATIVE_BASIS}\n"
                f"**Decision rationale**: {CONSERVATIVE_REASON}")

    # Scope proof to the finding, so another finding's evidence cannot authorize closure.
    boundaries = [0] + [match.start() for match in re.finditer(r"(?m)^#{2,6}\s+\[?[A-Z][A-Z0-9]*-\d+\b", _structure(output))] + [len(output)]
    converted = []
    for start, end in zip(boundaries, boundaries[1:]):
        section = output[start:end]
        allowed = {match.start() for match in _DECLARATION.finditer(_structure(section))}
        converted.append(_DECLARATION.sub(lambda match: declaration(match, section) if match.start() in allowed else match.group(0), section))
    return "".join(converted)
