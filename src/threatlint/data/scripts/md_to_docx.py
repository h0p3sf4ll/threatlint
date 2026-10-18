#!/usr/bin/env python3
"""Convert a markdown threat model report to a formatted Word document.

Usage: md_to_docx.py <input.md> <output.docx>
"""

import re
import sys
from pathlib import Path

from docx import Document
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

# ---------------------------------------------------------------------------
# Heading colour palette (dark teal for H1/H2, slate for H3/H4)
# ---------------------------------------------------------------------------
H1_COLOR = RGBColor(0x1F, 0x49, 0x7D)   # deep navy
H2_COLOR = RGBColor(0x2E, 0x74, 0xB5)   # mid blue
H3_COLOR = RGBColor(0x00, 0x70, 0x4C)   # dark green
H4_COLOR = RGBColor(0x37, 0x37, 0x37)   # near-black


def _set_heading_color(paragraph, color):
    for run in paragraph.runs:
        run.font.color.rgb = color


def _apply_inline(para, text):
    """Add runs to *para* with **bold** and `code` formatting applied."""
    parts = re.split(r'(\*\*[^*\n]+\*\*|`[^`\n]+`|\*[^*\n]+\*)', text)
    for part in parts:
        if part.startswith("**") and part.endswith("**"):
            run = para.add_run(part[2:-2])
            run.bold = True
        elif part.startswith("`") and part.endswith("`"):
            run = para.add_run(part[1:-1])
            run.font.name = "Courier New"
            run.font.size = Pt(9)
        elif part.startswith("*") and part.endswith("*"):
            run = para.add_run(part[1:-1])
            run.italic = True
        else:
            para.add_run(part)


TABLE_SEPARATOR = re.compile(r"^\s*\|[-:\s|]+\|\s*$")
HORIZONTAL_RULE = re.compile(r"^[-*_]{3,}\s*$")
HEADING = re.compile(r"^(#{1,4})\s+(.*)")
BULLET = re.compile(r"^(\s*)[-*+]\s+(.*)")
NUMBERED = re.compile(r"^(\s*)\d+[.)]\s+(.*)")
HEADING_STYLES = {1: ("Heading 1", H1_COLOR), 2: ("Heading 2", H2_COLOR), 3: ("Heading 3", H3_COLOR), 4: ("Heading 4", H4_COLOR)}


def _fill_cell(cell, text, header):
    # Clear default paragraph and rebuild with inline formatting
    cell.paragraphs[0].clear()
    _apply_inline(cell.paragraphs[0], text)
    if header:
        for run in cell.paragraphs[0].runs:
            run.bold = True


def _add_table(doc, lines):
    """Parse a contiguous block of markdown table lines and add to doc."""
    # Skip the separator row (e.g., |---|---|)
    rows = [[c.strip() for c in line.strip().strip("|").split("|")]
            for line in lines if not TABLE_SEPARATOR.match(line)]
    if not rows:
        return

    ncols = max(len(r) for r in rows)
    table = doc.add_table(rows=len(rows), cols=ncols)
    table.style = "Table Grid"
    for ri, row in enumerate(rows):
        for ci in range(ncols):
            _fill_cell(table.cell(ri, ci), row[ci] if ci < len(row) else "", ri == 0)

    doc.add_paragraph()  # breathing room after table


def _add_code_block(doc, lines):
    if not lines:
        return
    p = doc.add_paragraph()
    run = p.add_run("\n".join(lines))
    run.font.name = "Courier New"
    run.font.size = Pt(9)
    p.paragraph_format.left_indent = Inches(0.4)
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after = Pt(4)


def _add_rule(doc):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(4)
    # Draw a thin bottom border on the paragraph
    pPr = p._p.get_or_add_pPr()
    pBdr = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), "4")
    bottom.set(qn("w:space"), "1")
    bottom.set(qn("w:color"), "AAAAAA")
    pBdr.append(bottom)
    pPr.append(pBdr)


def _add_heading(doc, match):
    style, color = HEADING_STYLES[len(match.group(1))]
    p = doc.add_paragraph(style=style)
    _apply_inline(p, match.group(2).strip())
    _set_heading_color(p, color)


def _add_bullet(doc, match):
    depth = len(match.group(1)) // 2
    p = doc.add_paragraph(style="List Bullet")
    _apply_inline(p, match.group(2))
    p.paragraph_format.left_indent = Inches(0.25 * (depth + 1))


def _add_numbered(doc, match):
    _apply_inline(doc.add_paragraph(style="List Number"), match.group(2))


def _add_text_line(doc, line):
    """Render one non-table, non-code line: rule, heading, list item, blank, or paragraph."""
    if HORIZONTAL_RULE.match(line.strip()):
        _add_rule(doc)
        return
    for pattern, render in ((HEADING, _add_heading), (BULLET, _add_bullet), (NUMBERED, _add_numbered)):
        match = pattern.match(line)
        if match:
            render(doc, match)
            return
    if line.strip():
        _apply_inline(doc.add_paragraph(), line)


class _Blocks:
    """Buffers multi-line blocks (code fences, tables) and flushes them in document order."""

    def __init__(self, doc):
        self.doc = doc
        self.in_code = False
        self.code = []
        self.table = []

    def feed(self, line):
        stripped = line.strip()
        if stripped.startswith("```"):
            if self.in_code:
                _add_code_block(self.doc, self.code)
            self.in_code, self.code = not self.in_code, []
            return
        if self.in_code:
            self.code.append(line)
            return
        if stripped.startswith("|"):
            self.table.append(line)
            return
        self._flush_table()
        _add_text_line(self.doc, line)

    def _flush_table(self):
        if self.table:
            _add_table(self.doc, self.table)
            self.table = []

    def close(self):
        self._flush_table()
        if self.in_code and self.code:
            _add_code_block(self.doc, self.code)


def convert(md_text: str, output_path: str) -> None:
    doc = Document()

    # Base style
    normal = doc.styles["Normal"]
    normal.font.name = "Aptos"
    normal.font.size = Pt(10)

    blocks = _Blocks(doc)
    for line in md_text.splitlines():
        blocks.feed(line)
    blocks.close()

    doc.save(output_path)
    print(f"Saved: {output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: md_to_docx.py <input.md> <output.docx>", file=sys.stderr)
        sys.exit(1)

    src = Path(sys.argv[1])
    if not src.exists():
        print(f"Input file not found: {src}", file=sys.stderr)
        sys.exit(1)

    convert(src.read_text(encoding="utf-8"), sys.argv[2])
