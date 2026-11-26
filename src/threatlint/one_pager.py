"""One-page PDF summary of a Finding Review verdict, attached beside the Word report.

The page leads with the verdict and a one-sentence bottom line, then the facts an owner needs:
for a TRUE POSITIVE, the risk, the code reviewed, the proposed fix and its acceptance criteria;
for a FALSE POSITIVE, why the finding is not exploitable and what any scanner change requires.

The PDF is written directly with the standard Helvetica and Courier fonts, so no PDF library is
needed. Content that does not fit is shrunk and then shortened; the result is always one page.

    python -m threatlint.one_pager REPORT.md OUT.pdf [--avit AVIT] [--finding FP-001]
"""
from __future__ import annotations

import argparse
import re
import sys
import zlib
from datetime import date
from pathlib import Path

PREFIX = "[ONE PAGER SUMMARY] "
CONTENT_TYPE = "application/pdf"


class OnePagerError(ValueError):
    """The requested finding cannot be summarized."""


class NoFindings(OnePagerError):
    """The report has no structured finding at all (for example a narrative-only review)."""


def attachment_name(word_name: str) -> str:
    """`[ONE PAGER SUMMARY] <Word report name>.pdf`, so the two attachments sort and read as a pair."""
    stem = Path(word_name).name
    return f"{PREFIX}{stem[:-5] if stem.lower().endswith('.docx') else stem}.pdf"


# ── Report parsing ───────────────────────────────────────────────────────────

_FINDING = re.compile(r"(?m)^#{3,4}[ \t]+\[([A-Z][A-Z0-9]*-\d+)\][ \t]*[—–-]+[ \t]*(.+?)[ \t]*$")
_LABEL_END = r"(?=^[ \t]*(?:[-*+][ \t]+)?\*\*[A-Z][^*\n]{2,60}\*\*:|^#{2,6}[ \t]|\Z)"


def _field(body: str, *names: str) -> str:
    for name in names:
        match = re.search(rf"^[ \t]*(?:[-*+][ \t]+)?\*\*{re.escape(name)}\*\*:[ \t]*(.*)$", body, re.M | re.I)
        if match and match.group(1).strip():
            return match.group(1).strip()
    return ""


def _section(body: str, *names: str) -> str:
    """Text after a bold label or heading, up to the next one. Uses the readiness parser first, which accepts
    qualified labels (**Proposed Fix** (direction only):) and labelled lists, then the plain label form."""
    from threatlint.finding_review import report_section  # noqa: PLC0415 - finding_review imports nothing from here
    for name in names:
        found = report_section(body, (name,))
        if found:
            return found
    for name in names:
        pattern = (rf"^(?:#{{2,6}}[ \t]+{re.escape(name)}[ \t]*$|[ \t]*(?:[-*+][ \t]+)?\*\*{re.escape(name)}\*\*:?[ \t]*)"
                   rf"(.*?){_LABEL_END}")
        match = re.search(pattern, body, re.M | re.S | re.I)
        if match and match.group(1).strip():
            return match.group(1).strip()
    return ""


def _code_blocks(text: str) -> list[tuple[str, str]]:
    return [(lang.strip().lower(), code.rstrip("\n"))
            for lang, code in re.findall(r"^[ \t]*```([^\n]*)\n(.*?)^[ \t]*```", text, re.M | re.S)]


_ITEM = re.compile(r"[ \t]*(?:[-*+\u2022]|(\d{1,2})[.)])[ \t]+(.*)")


def _cut(text: str, limit: int) -> str:
    """`text` shortened to `limit` characters at a sentence or word boundary, never ending on a list number."""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    end = cut.rfind(". ")
    cut = cut[: end + 1] if end > limit * 0.25 else cut.rsplit(" ", 1)[0].rstrip(",;:") + "\u2026"
    return re.sub(r"\s+\(?\d{1,2}[.)]$", "", cut).strip()


# Ordinary words that may open a section in lower case; identifiers such as "market" are left as written.
_COMMON_STARTS = "all|any|both|each|every|no|none|the|a|an|when|if|once|after|before|this|these|it|there|only|tests?|we"


def _prose(text: str, limit: int = 420) -> str:
    """Plain prose without code, tables, links, or emphasis. List items stay one per line; long text is cut
    at an item, sentence, or word boundary."""
    text = re.sub(r"^[ \t]*```.*?^[ \t]*```", "", text, flags=re.M | re.S)
    text = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("|"))
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    # A marker that opens the text is a label. Inside a sentence it is part of the wording, so it stays as words.
    marker = r"\*\*(PROPOSED[ \t]*[\u2014\u2013-][ \t]*NOT APPLIED|NOT RUN)\*\*"
    text = re.sub(r"(?m)^[ \t]*(?:-{3,}|\*{3,}|_{3,})[ \t]*$", "", text)  # Markdown dividers carry no words.
    text = re.sub(rf"^\s*[\u2014\u2013-]*[ \t]*\(?{marker}\)?[,.:;]?[ \t]*", "", text)
    text = re.sub(marker, lambda match: "proposed, not applied" if match.group(1).startswith("PROPOSED") else "not run", text)
    # Remove emphasis and code marks only where they wrap text; identifiers keep their own underscores and asterisks.
    text = text.replace("`", "")
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"__(.+?)__", r"\1", text)
    text = re.sub(r"(?<![\w*])\*(?=\S)(.+?)(?<=\S)\*(?![\w*])", r"\1", text)
    text = re.sub(r"(?<![\w_])_(?=\S)(.+?)(?<=\S)_(?![\w_])", r"\1", text)
    lines: list[str] = []
    item_open = False
    for raw in text.splitlines():
        item = _ITEM.match(raw)
        line = re.sub(r"\s+", " ", item.group(2) if item else raw).strip()
        if not line or (not item and line.endswith(":") and (len(line.split()) <= 12 or re.search(r"(?i)\b(?:before|after)\b[^:]*:$", line))):
            continue  # A caption such as "Before (vulnerable):" or "`src/a.cs:87` (Index). Before:" whose code was removed.
        if item:
            lines.append(("\u2022 " if not item.group(1) else f"{item.group(1)}. ") + line)
            item_open = True
        elif lines and (raw[:1].isspace() if item_open else True):
            lines[-1] += " " + line          # An indented continuation of an item, or the rest of a paragraph.
        else:
            lines.append(line)               # A paragraph after a list.
            item_open = False
    out: list[str] = []
    used = 0
    for line in lines:
        if used + len(line) <= limit:
            out.append(line)
            used += len(line) + 1
            continue
        room = limit - used
        partial = _cut(line, room if out else limit)
        # Keep whole items: after the first line, a partial item is shown only when it ends on a full sentence.
        if not out or (room >= 80 and not partial.endswith("\u2026")):
            out.append(partial)
        break
    if out and re.match(rf"(?:{_COMMON_STARTS})\b", out[0]):
        out[0] = out[0][:1].upper() + out[0][1:]
    text = re.sub(r";$", ".", "\n".join(out).strip())
    # A lone caption such as "Excerpt from `path:1-2`:" carries no finding detail.
    return "" if text.endswith(":") and len(text) < 90 else text


def _first_sentence(text: str, limit: int = 240) -> str:
    text = _prose(text, 700)
    match = re.match(r"(.+?[.!?])(?:\s|$)", text)
    sentence = match.group(1) if match else text
    return sentence if len(sentence) <= limit else sentence[:limit].rsplit(" ", 1)[0] + "…"


_NON_CODE = ("http", "text", "shell", "bash", "console", "log", "yaml", "json")


def _sentences(text: str) -> list[str]:
    flat = re.sub(r"\s+", " ", text.replace("\u2022 ", " ")).strip()
    return [part.strip() for part in re.split(r"(?<=[.!?])\s+(?=[A-Z\"'(\[])", flat) if part.strip()]


def _subsection(text: str, name: str) -> str:
    """The text after a bold lead-in such as **Impact.**, **Impact:** or - **Impact:**, up to the next lead-in or heading."""
    lead = r"\*\*[A-Z][^*\n]{1,60}?[.:]?\*\*[.:]?"
    bullet = r"(?:[-*+][ \t]+)?"
    match = re.search(rf"(?ims)^[ \t]*{bullet}\*\*{re.escape(name)}[.:]?\*\*[.:]?[ \t]*(.*?)"
                      rf"(?=^[ \t]*{bullet}{lead}(?:[ \t]|$)|^#{{1,6}}[ \t]|\Z)", text)
    return match.group(1).strip() if match else ""


_LABELLED = re.compile(r"[A-Z][\w-]*(?: [\w-]+){0,3}: ")


def _unlabelled(text: str) -> str:
    """`text` without its labelled sub-points ("- Entry point: ...", "- **Path to SQL**: ..."), which describe structure."""
    kept = []
    for line in text.splitlines():
        content = re.sub(r"^[ \t]*(?:[-*+]|\d{1,2}[.)])[ \t]+", "", line).replace("**", "")
        if not _LABELLED.match(content):
            kept.append(line)
    return "\n".join(kept)


def _plain_sentence(text: str, min_words: int = 8, limit: int = 200) -> str:
    """The first complete sentence of `text` with at least `min_words` words, without line references or connectives."""
    for sentence in _sentences(_prose(text, 2000)):
        if len(sentence.split()) < min_words or sentence.endswith(":") or _LABELLED.match(sentence):
            continue  # A labelled sub-point ("Entry point: ...") describes structure, not the finding's impact.
        sentence = re.sub(r"\s*\([^()]*\b(?:lines?|values? not|not inspected|see )[^()]*\)", "", sentence)
        sentence = re.sub(r"^(?:From there|As a result|Therefore|Thus|In turn|This means(?: that)?|So),?\s+", "", sentence)
        return _cut(sentence[:1].upper() + sentence[1:], limit)
    return ""


def _lower_first(text: str) -> str:
    """Lower-case a leading ordinary word ("Use" -> "use") but keep acronyms and identifiers ("SQL", "OrderService")."""
    return text[:1].lower() + text[1:] if re.match(r"[A-Z][a-z]+\b(?![A-Z])", text) else text


def _fix_code(fix: str, line: str = "") -> tuple[str, list[str]]:
    """("diff", lines) for a unified diff, ("code", lines) for proposed code blocks, or ("", []) when the fix is prose only.

    Blocks introduced as the current code ("Before:") are skipped: the page already shows the code reviewed. Each kept
    block is labelled with its caption ("\u2014 :93-94 (Index, the flagged sink)"). The block for the flagged `line`
    comes first, then a new file or helper, then the rest, so the clipped page keeps the code that matters most."""
    diff = next((code for lang, code in _code_blocks(fix) if lang in ("diff", "patch")), "")
    if diff:
        return "diff", [row for row in diff.splitlines() if not row.startswith(("--- ", "+++ ", "diff --git", "index "))]
    blocks = []
    caption = ""
    for match in re.finditer(r"^[ \t]*```([^\n]*)\n(.*?)^[ \t]*```", fix, re.M | re.S):
        before = [row.strip() for row in fix[: match.start()].splitlines() if row.strip()]
        label = before[-1] if before else ""
        context = re.sub(r"(?i)\b(?:before|after)\b\s*(?:\([^)]*\))?\s*:?\s*$", "", label).strip(" .:")
        if context and not re.fullmatch(r"```.*", context):
            caption = re.sub(r"[`*]", "", context)
        if match.group(1).strip().lower() in _NON_CODE:
            continue
        if re.search(r"(?i)\b(?:before|current|vulnerable|existing|original)\b", label) and not re.search(r"(?i)\bafter\b", label):
            continue
        flagged = bool(line) and re.search(rf"(?<!\d){re.escape(line)}(?!\d)|\bflagged\b", caption)
        rank = 0 if flagged else 1 if re.search(r"(?i)\bnew file\b|\bhelper\b", caption) else 2
        blocks.append((rank, caption, match.group(2).rstrip("\n")))
    lines: list[str] = []
    for _rank, caption, code in sorted(blocks, key=lambda item: item[0])[:4]:
        lines += ([""] if lines else []) + ([f"\u2014 {_cut(caption, 70)}"] if caption else []) + code.splitlines()
    return ("code", lines) if lines else ("", [])


# What an attacker can do ranks above what is merely exposed or reachable.
_STRONG = re.compile(
    r"(?i)\b(?:attackers?|adversar(?:y|ies)|can (?:read|write|modify|delete|drop|execute|run|exfiltrate|dump|bypass|access|"
    r"inject|tamper|alter|add|append|change|impersonate|escalate|take over)|reads?|writes?|steal|exfiltrat|compromis|arbitrary)")
_WEAK = re.compile(r"(?i)\b(?:allows?|lets|exposes?|leads? to|results? in|unauthenticated|reachable)")
_RULE_MATCH = re.compile(r"(?i)\b(?:the rule|rule's|pattern|derives from|imports?|matches the|meets every condition)\b")


def _consequences(*texts: str, count: int = 3) -> list[str]:
    """Sentences that say what an attacker can do (strongest first), never the scanner's matching conditions."""
    candidates: list[tuple[int, int, str]] = []
    for text in texts:
        for sentence in _sentences(_prose(text, 3000)):
            sentence = re.sub(r"(?i)\b(can|could|may|will) then\b", r"\1", sentence)
            sentence = re.sub(r"^(?:[A-Z][\w-]*)(?: [\w-]+){0,2}: (?=[A-Z])", "", sentence)  # "Attack: The attacker..." -> "The attacker..."
            if (_RULE_MATCH.search(sentence) or len(sentence.split()) < 6 or any(sentence == item[2] for item in candidates)
                    or re.search(r"\s\d{1,2}\.\s|\u2192|->", sentence)):  # Not a flattened list of steps.
                continue
            strength = 0 if _STRONG.search(sentence) else 1 if _WEAK.search(sentence) else None
            if strength is not None:
                candidates.append((strength, len(candidates), sentence))
    ranked = sorted(candidates)
    best = [item for item in ranked if item[0] == 0] or ranked  # Weaker sentences only when nothing stronger exists.
    return [sentence for _strength, _order, sentence in best[:count]]


def _basis_chip(basis: str) -> str:
    if re.search(r"\bNOT (?:A )?CONSERVATIVE\b", basis) or re.search(r"EVIDENCE|SUPPORTED|INSPECTED", basis):
        return "Evidence-supported"
    if "CONSERVATIVE" in basis:
        return "Conservative default"
    return _cut(basis.capitalize(), 32) if basis else ""


def _findings(report: str) -> list[dict]:
    matches = list(_FINDING.finditer(report))
    found = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(report)
        body = re.split(r"(?m)^##[ \t]+TIER 3\b", report[match.end():end], maxsplit=1)[0]
        found.append({"id": match.group(1), "title": match.group(2).strip(), "body": body})
    return found


def _select(report: str, findings: list[dict], avit: str, finding_id: str) -> dict:
    if finding_id:
        chosen = next((item for item in findings if item["id"] == finding_id), None)
        if not chosen:
            raise OnePagerError(f"The report has no finding {finding_id}")
        return chosen
    if avit:
        from threatlint.avit_report import verdict_for  # noqa: PLC0415
        try:
            wanted = verdict_for(report, avit)["id"]
        except Exception:  # noqa: BLE001 - fall back to the finding that names the AVIT
            wanted = ""
        chosen = next((item for item in findings if item["id"] == wanted), None) or next(
            (item for item in findings if avit in _field(item["body"], "Original finding")), None)
        if chosen:
            return chosen
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return sorted(findings, key=lambda item: (_field(item["body"], "Disposition").upper().startswith("FALSE"),
                                               rank.get(_field(item["body"], "Severity").upper(), 5)))[0]


def _clip_code(code: str, lines: int) -> list[str]:
    rows = code.expandtabs(4).splitlines()
    while rows and not rows[0].strip():
        rows.pop(0)
    clipped = rows[:lines]
    if len(rows) > lines:
        clipped.append(f"... {len(rows) - lines} more line(s) in the Word report")
    return clipped


_BOTTOM_LINES = 6  # Room for the verdict, the consequence and the fix without cutting a sentence.


def _bottom_lines(text: str) -> list[bytes]:
    """The bottom line as drawn: at most _BOTTOM_LINES lines, the last ending in an ellipsis if anything was left out."""
    lines = _wrap(text, "R", 10.2, _WIDTH - 30)
    if len(lines) <= _BOTTOM_LINES:
        return lines
    last = lines[_BOTTOM_LINES - 1]
    while last and _width(last + _encode(" \u2026"), "R", 10.2) > _WIDTH - 30:
        last = last.rsplit(b" ", 1)[0] if b" " in last else last[:-1]
    return lines[: _BOTTOM_LINES - 1] + [last.rstrip(b" ,;:") + _encode("\u2026")]


def _base_verb(word: str) -> str:
    """moves -> move, binds -> bind, replaces -> replace, passes -> pass, fixes -> fix; other words are unchanged."""
    lower = word.lower()
    if re.search(r"(?:ss|sh|ch|x|z)es$", lower):
        return lower[:-2]
    if lower.endswith("s") and not lower.endswith("ss"):
        return lower[:-1]
    return lower


def _fix_sentence(text: str, limit: int = 170) -> str:
    """The first sentence that says what to change. A sentence that opens with a pronoun ("It holds constant SQL...")
    is joined to the short sentence it refers to ("New helper Data/Queries.cs: it holds constant SQL...")."""
    sentences = _sentences(_prose(text, 1200))
    for index, sentence in enumerate(sentences):
        if len(sentence.split()) < 4:
            continue
        subject = re.match(r"(?i)(?:the|this) (?:fix|patch|change|proposed fix|proposal) (\w+)\b", sentence)
        if subject:  # "The fix moves the SQL..." -> "Move the SQL..."
            sentence = _base_verb(subject.group(1)).capitalize() + sentence[subject.end():]
        elif index and re.match(r"(?:It|This|These|They|That)\b", sentence):
            sentence = f"{sentences[index - 1].rstrip('.')}: {_lower_first(sentence)}"
        return _cut(sentence, limit)
    return _cut(sentences[0], limit) if sentences else ""


def _bottom_line(page: dict, title: str, location: str, risk: str, fix_prose: str, has_code: bool) -> str:
    """Verdict, severity and place; what an attacker can do; and the fix. Each part comes from the report's own fields."""
    if page["basis"] == "CONSERVATIVE DEFAULT":
        state = "Unconfirmed"
    elif page["confidence"] == "CONFIRMED":
        state = "Confirmed"
    else:
        state = "Likely"
    severity = f"{page['severity'].lower()}-severity " if page["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else ""
    subject = _prose(title, 150).rstrip(".")
    head = subject.split(": ", 1)[0]
    subject = head if len(head) >= 12 else subject
    place = Path(location).name if location else ""
    first = f"{state} {severity}finding{f' at {place}' if place else ''}: {_lower_first(subject)}."
    consequence = _plain_sentence(risk, 8, 190)
    action = _fix_sentence(fix_prose)
    note = " (code below)." if has_code and action else ""

    def fix_text() -> str:
        if action:
            return f"Fix: {_lower_first(action)}".rstrip(".") + (note or ".")
        return "Fix: apply the proposed code change on this page." if has_code else ""

    def compose() -> str:
        return " ".join(part for part in (first, consequence, fix_text()) if part)

    # The box holds _BOTTOM_LINES lines: shorten the longer of the consequence and the fix action until all three parts fit.
    while len(_wrap(compose(), "R", 10.2, _WIDTH - 30)) > _BOTTOM_LINES and max(len(consequence), len(action)) > 60:
        if len(consequence) >= len(action):
            consequence = _cut(consequence, len(consequence) - 25)
        else:
            action = _cut(action, len(action) - 25).rstrip("\u2026").rstrip(" ,;:") + "\u2026"
    return compose() or "The inspected code supports the reported finding."


def summary(report: str, avit: str = "", finding_id: str = "") -> dict:
    """The page model for one finding: what the one-pager says, independent of layout."""
    findings = _findings(report)
    if not findings:
        raise NoFindings("The report has no structured finding to summarize")
    finding = _select(report, findings, avit, finding_id)
    body = finding["body"]
    head = report[: report.find("\n## ")] if "\n## " in report else report[:2000]
    repository = re.search(r"^# [^:\n]+:\s*(.+)$", report, re.M)
    disposition = _field(body, "Disposition").upper()
    false_positive = disposition.startswith("FALSE")
    original = [part.strip().strip("`") for part in _field(body, "Original finding").split(";") if part.strip()]
    avit = avit or next((part for part in original if re.fullmatch(r"AVIT\d+", part.upper())), "")
    rule = next((part for part in original if re.fullmatch(r"[\w.-]+\.[\w.-]+", part) and not re.fullmatch(r"AVIT\d+", part.upper())
                 and not re.search(r"\.\w{1,5}:\d", part) and not re.match(r"(?i)semgrep\b|\d", part)), "")
    rule = rule or _field(body, "Semgrep rule").strip("`")
    evidence = _section(body, "Evidence")
    location = next((part for part in original if re.search(r"\.\w{1,6}:\d", part)), "")
    cited = re.search(r"`([\w./\\@-]+\.\w{1,6}:\d+(?:-\d+)?)`", evidence)
    location = location or (cited.group(1) if cited else _field(body, "Location").strip("`"))
    snippet = next((code for lang, code in _code_blocks(evidence)
                    if lang not in ("diff", "patch", "http", "text", "shell", "bash", "console", "log")), "")
    page = {
        "false_positive": false_positive, "disposition": disposition or "REPORTED FINDING", "id": finding["id"],
        "title": _prose(finding["title"], 150) or finding["id"], "avit": avit,
        "severity": (re.findall(r"[A-Za-z]+", _field(body, "Severity")) or ["UNSPECIFIED"])[0].upper(),
        "confidence": (re.findall(r"[A-Za-z]+", _field(body, "Confidence")) or [""])[0].upper(),
        "basis": _field(body, "Decision basis").upper(),
        "owner": _prose(re.sub(r"\s*\(suggested\)", "", _field(body, "Owner")), 180),
        "effort": _prose(_field(body, "Effort"), 180),
        "repository": _prose(repository.group(1), 80) if repository else "",
        "location": location, "rule": rule,
        "reviewed": _field(head, "Date") or date.today().isoformat(),
        "code": _clip_code(snippet, 12) if snippet else [],
    }
    if false_positive:
        safe = _section(body, "Verified Safe Behavior")
        where = f" at {Path(location).name}" if location else ""
        reason = _plain_sentence(safe, 6, 230)
        page["bottom_line"] = (f"False positive{where}: {_lower_first(reason)} No code change is needed." if reason
                               else _first_sentence(safe) or "The inspected code does not support the scanner's claim.")
        page["left"] = [("Why it is not exploitable", _prose(safe, 520)),
                        ("Decisive evidence", _prose(_section(body, "Assessment and alternative interpretation"), 360))]
        page["fix"] = []
        page["right"] = [("Scanner follow-up", _prose(_section(body, "Tuning Status") or _section(body, "Proposed Tuning"), 360)),
                         ("Blast radius of any suppression", _prose(_section(body, "Coverage and Blast Radius"), 320)),
                         ("Before a rule change", _prose(_section(body, "Approval and Rollback"), 260))]
        page["footer"] = "No vulnerability was confirmed. Any scanner suppression requires validated fixtures and scanner-owner approval."
    else:
        impact = _section(body, "Finding and impact")
        # **Impact.** may be its own line, which ends the Finding and impact section, so search the whole finding.
        subsection = _subsection(impact, "Impact") or _subsection(body, "Impact")
        exploit = _section(body, "Exploit path")
        consequences = _consequences(subsection, impact, exploit, _field(head, "Risk and decision"))
        if not consequences and not _prose(impact):  # No impact text at all: look anywhere in the finding.
            consequences = _consequences(body)
        risk = subsection or ("\n".join(f"- {sentence}" for sentence in consequences) if consequences else impact)
        fix = _section(body, "Proposed fix patch") + "\n" + _section(body, "Proposed Fix")
        fix_kind, fix_lines = _fix_code(fix, location.rsplit(":", 1)[-1].split("-")[0] if ":" in location else "")
        fix_prose = re.sub(r"^\s*\([^()]*\)\.?\s*", "", _prose(fix, 600))
        page["bottom_line"] = _bottom_line(page, finding["title"], location,
                                           consequences[0] if consequences else subsection or _unlabelled(impact),
                                           fix_prose, bool(fix_lines))
        page["left"] = [("What is at risk", _prose(risk, 460)),
                        ("Why this is a true positive", _prose(_section(body, "Assessment and alternative interpretation"), 340))]
        page["fix"] = _clip_code("\n".join(fix_lines), 16) if fix_lines else []
        page["fix_kind"] = fix_kind
        page["right"] = [("How to apply the fix" if fix_lines else "Proposed fix (not applied)", _prose(fix_prose, 220 if fix_lines else 320)),
                         ("Done when", _prose(_section(body, "Acceptance Criteria"), 320)),
                         ("Tests to add (not run)", _prose(_section(body, "Regression Tests"), 260))]
        if page["basis"] == "CONSERVATIVE DEFAULT":
            page["right"].insert(0, ("Evidence still needed", _prose(_section(body, "Blocking Evidence"), 280)))
        page["footer"] = "Analysis only: no code was changed and the proposed tests were not run."
    return page


# ── PDF rendering ────────────────────────────────────────────────────────────
# Glyph widths (per 1000 em) of the standard Helvetica fonts for WinAnsi codes 32-255.
_HELVETICA = (
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556,
    556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556,
    833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500,
    556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500,
    334, 260, 334, 584, 761, 556, 0, 222, 556, 333, 1000, 556, 556, 333, 1000, 667, 333, 1000, 0, 611, 0, 0, 222, 222,
    333, 333, 350, 556, 1000, 333, 1000, 500, 333, 944, 0, 500, 667, 278, 333, 556, 556, 556, 556, 260, 556, 333, 737,
    370, 556, 584, 333, 737, 333, 400, 584, 333, 333, 333, 556, 537, 278, 333, 333, 365, 556, 834, 834, 834, 611, 667,
    667, 667, 667, 667, 667, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278, 722, 722, 778, 778, 778, 778, 778,
    584, 778, 722, 722, 722, 722, 667, 667, 611, 556, 556, 556, 556, 556, 556, 889, 500, 556, 556, 556, 556, 278, 278,
    278, 278, 556, 556, 556, 556, 556, 556, 556, 584, 611, 556, 556, 556, 556, 500, 556, 500,
)
_HELVETICA_BOLD = (
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556,
    556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833,
    722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611,
    556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389,
    280, 389, 584, 761, 556, 0, 278, 556, 500, 1000, 556, 556, 333, 1000, 667, 333, 1000, 0, 611, 0, 0, 278, 278, 500,
    500, 350, 556, 1000, 333, 1000, 556, 333, 944, 0, 500, 667, 278, 333, 556, 556, 556, 556, 280, 556, 333, 737, 370,
    556, 584, 333, 737, 333, 400, 584, 333, 333, 333, 611, 556, 278, 333, 333, 365, 556, 834, 834, 834, 611, 722, 722,
    722, 722, 722, 722, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278, 722, 722, 778, 778, 778, 778, 778, 584,
    778, 722, 722, 722, 722, 667, 667, 611, 556, 556, 556, 556, 556, 556, 889, 556, 556, 556, 556, 556, 278, 278, 278,
    278, 611, 611, 611, 611, 611, 611, 611, 584, 611, 611, 611, 611, 611, 556, 611, 556,
)

_PAGE_W, _PAGE_H = 612.0, 792.0          # US Letter
_LEFT, _RIGHT, _TOP, _BOTTOM = 40.0, 40.0, 38.0, 34.0
_WIDTH = _PAGE_W - _LEFT - _RIGHT
_GUTTER = 18.0
_INK, _MUTED, _FAINT, _RULE = (0.11, 0.15, 0.13), (0.33, 0.40, 0.36), (0.42, 0.48, 0.44), (0.84, 0.87, 0.85)
_RED, _RED_TINT = (0.70, 0.15, 0.12), (0.984, 0.937, 0.933)
_GREEN, _GREEN_TINT = (0.12, 0.48, 0.33), (0.933, 0.965, 0.949)
_CODE_BG, _ADD_BG, _DEL_BG = (0.953, 0.961, 0.957), (0.890, 0.953, 0.918), (0.984, 0.902, 0.894)
_ADD_INK, _DEL_INK = (0.08, 0.39, 0.26), (0.60, 0.13, 0.10)
_REPLACE = {"\u2192": "->", "\u2190": "<-", "\u21d2": "=>", "\u2264": "<=", "\u2265": ">=", "\u2260": "!=", "\u2713": "v",
            "\u2714": "v", "\u2717": "x", "\u2718": "x", "\u00a0": " ", "\u2009": " ", "\u202f": " ", "\u2011": "-",
            "\u2212": "-", "\u2502": "|", "\u251c": "+", "\u2514": "+", "\u2500": "-"}


def _encode(text: str) -> bytes:
    text = "".join(_REPLACE.get(char, char) for char in str(text))
    return text.encode("cp1252", errors="replace")


def _width(data: bytes, font: str, size: float) -> float:
    if font == "C":
        return len(data) * 0.6 * size
    table = _HELVETICA_BOLD if font == "B" else _HELVETICA
    return sum(table[byte - 32] if 32 <= byte <= 255 else 500 for byte in data) * size / 1000.0


def _wrap(text: str, font: str, size: float, width: float) -> list[bytes]:
    lines: list[bytes] = []
    for paragraph in str(text).split("\n"):
        current = b""
        for word in _encode(paragraph).split(b" "):
            candidate = current + b" " + word if current else word
            if _width(candidate, font, size) <= width:
                current = candidate
                continue
            if current:
                lines.append(current)
            while _width(word, font, size) > width:  # Long identifiers and paths break mid-token.
                cut = max(1, int(len(word) * width / _width(word, font, size)))
                while cut > 1 and _width(word[:cut], font, size) > width:  # Wide capitals: measure, never estimate.
                    cut -= 1
                slash = word.rfind(b"/", 0, cut)
                if slash >= cut // 3:  # Break a path after a folder rather than inside a name.
                    cut = slash + 1
                lines.append(word[:cut])
                word = word[cut:]
            current = word
        lines.append(current)
    return lines


def _wrap_code(lines: list[str], size: float, width: float) -> list[bytes]:
    columns = max(10, int(width / (0.6 * size)))
    wrapped: list[bytes] = []
    for line in lines:
        data = _encode(line)
        if not data:
            wrapped.append(b"")
        while data:
            cut = columns
            if len(data) > columns:  # Prefer a break after a space or punctuation in the last third of the line.
                breaks = [index + 1 for index in range(columns * 2 // 3, columns) if data[index:index + 1] in b" ,;(."]
                cut = breaks[-1] if breaks else columns
            wrapped.append(data[:cut].rstrip())
            data = data[cut:]
            if data:
                data = b"  " + data.lstrip()
    return wrapped


def _literal(data: bytes) -> bytes:
    return b"(" + data.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)").replace(b"\r", b"") + b")"


class _Canvas:
    """Top-left coordinates, converted to PDF space when drawn."""

    _FONTS = {"R": b"/F1", "B": b"/F2", "C": b"/F3"}

    def __init__(self) -> None:
        self.ops: list[bytes] = []

    def text(self, x: float, top: float, data: bytes, font: str = "R", size: float = 9.0,
             color=_INK, spacing: float = 0.0) -> None:
        y = _PAGE_H - top - size * 0.8
        self.ops.append(b"BT %s %.2f Tf %.3f %.3f %.3f rg %.2f Tc %.2f %.2f Td %s Tj ET" % (
            self._FONTS[font], size, *color, spacing, x, y, _literal(data)))

    def rect(self, x: float, top: float, width: float, height: float, fill=None, stroke=None, line: float = 0.6) -> None:
        y = _PAGE_H - top - height
        if fill:
            self.ops.append(b"%.3f %.3f %.3f rg %.2f %.2f %.2f %.2f re f" % (*fill, x, y, width, height))
        if stroke:
            self.ops.append(b"%.3f %.3f %.3f RG %.2f w %.2f %.2f %.2f %.2f re S" % (*stroke, line, x, y, width, height))

    def rule(self, top: float, x: float = _LEFT, width: float = _WIDTH) -> None:
        self.rect(x, top, width, 0.6, fill=_RULE)


def _spaced_width(data: bytes, font: str, size: float, spacing: float) -> float:
    return _width(data, font, size) + spacing * max(0, len(data) - 1)


_FACT_LINES = {"Suggested owner": 4, "Effort": 4}  # Sentences get room to finish; identifiers stay compact.


def _fact_lines(name: str, value: str, width: float) -> list[bytes]:
    """Two lines (four for owner and effort). A long path loses leading folders, never its file name and line;
    other text that still does not fit ends with an ellipsis."""
    limit = _FACT_LINES.get(name, 2)
    lines = _wrap(value or "\u2014", "B", 8.3, width)
    if len(lines) <= limit:
        return lines
    if name == "Location" and "/" in value:
        parts = value.split("/")
        name_and_line = _encode(parts[-1])
        for start in range(1, len(parts)):
            shorter = _wrap("\u2026/" + "/".join(parts[start:]), "B", 8.3, width)
            # Accept only a shortening that keeps the file name and line whole on one line.
            if len(shorter) <= limit and any(name_and_line in line for line in shorter):
                return shorter
    last = lines[limit - 1]
    while last and _width(last + _encode("\u2026"), "B", 8.3) > width:
        last = last[:-1]
    return lines[: limit - 1] + [last.rstrip() + _encode("\u2026")]


def _header(canvas: _Canvas, page: dict) -> float:
    """Draws everything above the two columns and returns the top of the column area."""
    accent, tint = (_GREEN, _GREEN_TINT) if page["false_positive"] else (_RED, _RED_TINT)
    brand, label = _encode("THREATLINT"), _encode("·   FINDING REVIEW SUMMARY")
    canvas.text(_LEFT, _TOP, brand, "B", 7.4, _INK, 1.1)
    canvas.text(_LEFT + _spaced_width(brand, "B", 7.4, 1.1) + 7, _TOP, label, "R", 7.4, _MUTED, 0.7)
    identifier = _encode(page["avit"] or page["id"])
    canvas.text(_PAGE_W - _RIGHT - _width(identifier, "B", 9.0), _TOP - 1, identifier, "B", 9.0)
    canvas.rule(_TOP + 13)
    top = _TOP + 24
    size = 17.0
    title = _wrap(page["title"], "B", size, _WIDTH)
    if len(title) > 2:
        size = 14.5
        title = _wrap(page["title"], "B", size, _WIDTH)[:3]
    for line in title:
        canvas.text(_LEFT, top, line, "B", size)
        top += size * 1.22
    top += 6
    badge = _encode(page["disposition"])
    badge_width = _spaced_width(badge, "B", 9.4, 0.6) + 22
    canvas.rect(_LEFT, top, badge_width, 20, fill=accent)
    canvas.text(_LEFT + 11, top + 5.6, badge, "B", 9.4, (1, 1, 1), 0.6)
    x = start = _LEFT + badge_width + 9
    chips = [f"Severity · {page['severity']}"] + ([f"Confidence · {page['confidence']}"] if page["confidence"] else [])
    chips += [_basis_chip(page["basis"])] if page["basis"] else []
    for chip in chips:
        data = _wrap(chip, "R", 7.8, _PAGE_W - _RIGHT - start - 16)[0]
        width = _width(data, "R", 7.8) + 16
        if x > start and x + width > _PAGE_W - _RIGHT:  # Wrap rather than run past the margin.
            x, top = start, top + 21
        canvas.rect(x, top + 2, width, 16, fill=(0.965, 0.973, 0.969), stroke=(0.80, 0.85, 0.82))
        canvas.text(x + 8, top + 6.6, data, "R", 7.8, (0.20, 0.26, 0.23))
        x += width + 7
    top += 31
    lines = _bottom_lines(page["bottom_line"])
    height = 24 + len(lines) * 10.2 * 1.38
    canvas.rect(_LEFT, top, _WIDTH, height, fill=tint)
    canvas.rect(_LEFT, top, 3.2, height, fill=accent)
    canvas.text(_LEFT + 15, top + 9, _encode("BOTTOM LINE"), "B", 6.8, accent, 0.9)
    for index, line in enumerate(lines):
        canvas.text(_LEFT + 15, top + 20 + index * 10.2 * 1.38, line, "R", 10.2)
    top += height + 12
    facts = [("Repository", page["repository"]), ("Location", page["location"]), ("Scanner rule", page["rule"]),
             ("Suggested owner", page["owner"]), ("Effort", page["effort"]), ("Reviewed", page["reviewed"])]
    cell = (_WIDTH - 2 * 16) / 3
    for row in range(2):
        row_height = 0.0
        for column in range(3):
            name, value = facts[row * 3 + column]
            x = _LEFT + column * (cell + 16)
            canvas.text(x, top, _encode(name.upper()), "R", 6.5, _FAINT, 0.6)
            values = _fact_lines(name, value, cell)
            for index, line in enumerate(values):
                canvas.text(x, top + 10 + index * 10.6, line, "B", 8.3)
            row_height = max(row_height, 10 + len(values) * 10.6)
        top += row_height + 7
    canvas.rule(top + 2)
    return top + 14


def _blocks(page: dict) -> tuple[list, list]:
    location = f" · {Path(page['location']).name}" if page["location"] else ""
    left = [("text", title, body) for title, body in page["left"] if body]
    if page["code"]:
        left.append(("code", f"Code reviewed{location}", page["code"]))
    right = [(page.get("fix_kind") or "diff", "Proposed fix (not applied)", page["fix"])] if page["fix"] else []
    right += [("text", title, body) for title, body in page["right"] if body]
    return left, right


def _measure(blocks: list, width: float, scale: float, keep: dict | None = None) -> tuple[float, list, dict]:
    """Lay out one column. `keep` caps the lines of a block; the result also reports each block's line count."""
    laid, height, counts = [], 0.0, {}
    body, code = 8.6 * scale, 7.1 * scale
    for index, (kind, title, content) in enumerate(blocks):
        heading = _wrap(title.upper(), "B", 7.0 * scale, width)[:2]
        if kind == "text":
            lines, leading = _wrap(content, "R", body, width), body * 1.42
        else:
            lines, leading = _wrap_code(content, code, width - 12), code * 1.42
        limit = (keep or {}).get(index)
        if limit is not None and len(lines) > limit:
            lines = lines[:limit]
            lines[-1] = lines[-1].rstrip(b" .,;:") + (_encode("…") if kind == "text" else b" ...")
        counts[index] = len(lines)
        if not lines:
            continue
        height += len(heading) * 9.0 * scale + 4 + len(lines) * leading + (10 if kind != "text" else 0) + 11 * scale
        laid.append((kind, heading, lines, leading, scale))
    return height, laid, counts


def _fit(blocks: list, width: float, available: float) -> list:
    """Shrink the column's type to 75%, then shorten its longest block a line at a time."""
    for step in range(6):
        height, laid, counts = _measure(blocks, width, 1.0 - step * 0.05)
        if height <= available:
            return laid
    keep: dict[int, int] = {}
    while height > available:
        index = max(counts, key=counts.get)
        if counts[index] <= 2:
            break
        keep[index] = counts[index] - 1
        height, laid, counts = _measure(blocks, width, 0.75, keep)
    return laid


def _draw_column(canvas: _Canvas, laid: list, x: float, top: float, width: float, accent) -> None:
    for kind, heading, lines, leading, scale in laid:
        for line in heading:
            canvas.text(x, top, line, "B", 7.0 * scale, (0.25, 0.31, 0.28))
            top += 9.0 * scale
        top += 4
        if kind == "text":
            for line in lines:
                canvas.text(x, top, line, "R", 8.6 * scale, (0.15, 0.19, 0.17))
                top += leading
        else:
            size = 7.1 * scale
            height = len(lines) * leading + 10
            canvas.rect(x, top, width, height, fill=_CODE_BG, stroke=(0.87, 0.90, 0.88), line=0.5)
            row = top + 5
            for line in lines:
                ink = _INK
                if kind == "diff" and line.startswith(b"+"):
                    canvas.rect(x + 0.5, row - 1.2, width - 1, leading, fill=_ADD_BG)
                    ink = _ADD_INK
                elif kind == "diff" and line.startswith(b"-"):
                    canvas.rect(x + 0.5, row - 1.2, width - 1, leading, fill=_DEL_BG)
                    ink = _DEL_INK
                canvas.text(x + 6, row, line, "C", size, ink)
                row += leading
            top += height
        top += 11 * scale


def render(page: dict) -> bytes:
    """The one-page PDF for a page model from summary()."""
    canvas = _Canvas()
    accent = _GREEN if page["false_positive"] else _RED
    columns_top = _header(canvas, page)
    column = (_WIDTH - _GUTTER) / 2
    note = _wrap(page["footer"], "R", 6.8, column + 40)[:2]
    footer_top = _PAGE_H - _BOTTOM - 7 - len(note) * 8.6  # A two-line note still ends above the bottom margin.
    available = footer_top - 8 - columns_top
    left, right = _blocks(page)
    _draw_column(canvas, _fit(left, column, available), _LEFT, columns_top, column, accent)
    _draw_column(canvas, _fit(right, column, available), _LEFT + column + _GUTTER, columns_top, column, accent)
    canvas.rule(footer_top)
    for index, line in enumerate(note):
        canvas.text(_LEFT, footer_top + 7 + index * 8.6, line, "R", 6.8, _FAINT)
    pointer = _encode(f"Full evidence: Word review attached to {page['avit'] or 'the record'}")
    canvas.text(_PAGE_W - _RIGHT - _width(pointer, "R", 6.8), footer_top + 7, pointer, "R", 6.8, _FAINT)
    return _pdf(b"\n".join(canvas.ops), f"{page['avit'] or page['id']} {page['disposition'].title()} summary")


def _pdf(content: bytes, title: str) -> bytes:
    stream = zlib.compress(content)
    fonts = [b"/Helvetica", b"/Helvetica-Bold", b"/Courier"]
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R /F2 6 0 R /F3 7 0 R >> >> >>",
        b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(stream) + stream + b"\nendstream",
        *[b"<< /Type /Font /Subtype /Type1 /BaseFont %s /Encoding /WinAnsiEncoding >>" % font for font in fonts],
        b"<< /Title %s /Producer (Threatlint) >>" % _literal(_encode(title)),
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, len(objects), xref)
    return bytes(out)


def build(report: str, avit: str = "", finding_id: str = "") -> bytes:
    """The one-page PDF for the finding that names `avit` (or `finding_id`)."""
    return render(summary(report, avit, finding_id))


def write(report_path: str, out_path: str, avit: str = "", finding_id: str = "") -> str:
    data = build(Path(report_path).read_text(encoding="utf-8"), avit, finding_id)
    Path(out_path).write_bytes(data)
    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="threatlint one-pager", description="Write the one-page PDF summary of a Finding Review.")
    parser.add_argument("report", help="Finding Review Markdown report")
    parser.add_argument("out", help="PDF to write")
    parser.add_argument("--avit", default="", help="Summarize the finding that names this AVIT")
    parser.add_argument("--finding", default="", help="Summarize this finding ID (for example FP-001)")
    args = parser.parse_args(argv)
    try:
        write(args.report, args.out, args.avit.strip().upper(), args.finding.strip())
    except (OnePagerError, OSError, UnicodeDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3 if isinstance(exc, NoFindings) else 1
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
