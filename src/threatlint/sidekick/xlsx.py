"""Minimal .xlsx writer and reader (stdlib zipfile + XML), so Sidekick reports need no extra dependency.

Writes one sheet with a styled header, 14-pt cells, auto-fit widths, hyperlinks and an Excel table
(TableStyleMedium2, auto-filter). Every text value is an inline string, never a formula, so a repository
or user name starting with `=` cannot run as a formula when the workbook is opened.
"""

from __future__ import annotations

import re
import zipfile
from xml.sax.saxutils import escape


def _col(index: int) -> str:
    name = ""
    index += 1
    while index:
        index, rest = divmod(index - 1, 26)
        name = chr(65 + rest) + name
    return name


def _clean(text: str) -> str:
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(text))


def write_xlsx(path: str, headers: list[str], rows: list[list], *, links: dict[int, int] | None = None, table_name: str = "Report") -> None:
    """`links` maps a column index to itself when that column holds URLs to render as hyperlinks."""
    links = links or {}
    widths = [len(h) for h in headers]
    for row in rows:
        for i, value in enumerate(row):
            widths[i] = max(widths[i], len(str(value)) if value is not None else 0)
    sheet = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
             '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
             'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">',
             "<cols>" + "".join(f'<col min="{i + 1}" max="{i + 1}" width="{min(80, w * 1.25 + 4):.1f}" customWidth="1"/>' for i, w in enumerate(widths)) + "</cols>",
             "<sheetData>"]
    def cell(ref: str, value, style: int) -> str:
        if value is None or value == "":
            return f'<c r="{ref}" s="{style}"/>'
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return f'<c r="{ref}" s="{style}" t="inlineStr"><is><t xml:space="preserve">{escape(_clean(value))}</t></is></c>'
        return f'<c r="{ref}" s="{style}"><v>{value}</v></c>'
    sheet.append('<row r="1">' + "".join(cell(f"{_col(i)}1", h, 1) for i, h in enumerate(headers)) + "</row>")
    hyperlinks = []
    for r, row in enumerate(rows, start=2):
        cells = []
        for i, value in enumerate(row):
            ref = f"{_col(i)}{r}"
            if i in links and value:
                hyperlinks.append((ref, str(value)))
                cells.append(cell(ref, value, 2))
            else:
                cells.append(cell(ref, value, 0))
        sheet.append(f'<row r="{r}">' + "".join(cells) + "</row>")
    sheet.append("</sheetData>")
    if hyperlinks:
        sheet.append("<hyperlinks>" + "".join(f'<hyperlink ref="{ref}" r:id="rId{n + 2}"/>' for n, (ref, _url) in enumerate(hyperlinks)) + "</hyperlinks>")
    if rows:
        sheet.append('<tableParts count="1"><tablePart r:id="rId1"/></tableParts>')
    sheet.append("</worksheet>")
    last = f"{_col(len(headers) - 1)}{len(rows) + 1}"
    sheet_rels = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
                  '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
    if rows:
        sheet_rels.append('<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/table" Target="../tables/table1.xml"/>')
    for n, (_ref, url) in enumerate(hyperlinks):
        sheet_rels.append(f'<Relationship Id="rId{n + 2}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="{escape(url, {chr(34): "&quot;"})}" TargetMode="External"/>')
    sheet_rels.append("</Relationships>")
    table = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             f'<table xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" id="1" name="{table_name}" displayName="{table_name}" ref="A1:{last}">'
             f'<autoFilter ref="A1:{last}"/><tableColumns count="{len(headers)}">'
             + "".join(f'<tableColumn id="{i + 1}" name="{escape(h)}"/>' for i, h in enumerate(headers))
             + '</tableColumns><tableStyleInfo name="TableStyleMedium2" showFirstColumn="0" showLastColumn="0" showRowStripes="1" showColumnStripes="0"/></table>')
    styles = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
              '<fonts count="3"><font><sz val="14"/><name val="Calibri"/></font><font><b/><sz val="14"/><name val="Calibri"/></font>'
              '<font><u/><sz val="14"/><color rgb="FF0563C1"/><name val="Calibri"/></font></fonts>'
              '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>'
              '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
              '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
              '<cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
              '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
              '<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs></styleSheet>')
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as book:
        book.writestr("[Content_Types].xml",
                      '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                      '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
                      '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                      '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                      '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
                      + ('<Override PartName="/xl/tables/table1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml"/>' if rows else "")
                      + "</Types>")
        book.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                      '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        book.writestr("xl/workbook.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                      'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>')
        book.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                      '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
                      '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
        book.writestr("xl/styles.xml", styles)
        book.writestr("xl/worksheets/sheet1.xml", "".join(sheet))
        book.writestr("xl/worksheets/_rels/sheet1.xml.rels", "".join(sheet_rels))
        if rows:
            book.writestr("xl/tables/table1.xml", table)


def read_xlsx(path: str) -> list[list]:
    """Rows of the first sheet as Python values (numbers, strings, None). Handles shared and inline strings."""
    import xml.etree.ElementTree as ET  # noqa: PLC0415  (parsing a user-supplied workbook; ElementTree resolves no external entities)
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    with zipfile.ZipFile(path) as book:
        names = book.namelist()
        shared = []
        if "xl/sharedStrings.xml" in names:
            root = ET.fromstring(book.read("xl/sharedStrings.xml"))
            shared = ["".join(t.text or "" for t in si.iter(f"{{{ns['m']}}}t")) for si in root.findall("m:si", ns)]
        sheet = next((n for n in ("xl/worksheets/sheet1.xml",) if n in names), None) or sorted(n for n in names if n.startswith("xl/worksheets/sheet"))[0]
        root = ET.fromstring(book.read(sheet))
    rows = []
    for row in root.iter(f"{{{ns['m']}}}row"):
        values = {}
        for c in row.findall("m:c", ns):
            ref = re.match(r"([A-Z]+)", c.get("r", "A")).group(1)
            index = 0
            for ch in ref:
                index = index * 26 + ord(ch) - 64
            kind, v = c.get("t"), c.find("m:v", ns)
            if kind == "s" and v is not None:
                value = shared[int(v.text)]
            elif kind == "inlineStr":
                value = "".join(t.text or "" for t in c.iter(f"{{{ns['m']}}}t"))
            elif v is not None and v.text is not None:
                text = v.text
                try:
                    value = int(text) if re.fullmatch(r"-?\d+", text) else float(text)
                except ValueError:
                    value = text
            else:
                value = None
            values[index - 1] = value
        if values:
            rows.append([values.get(i) for i in range(max(values) + 1)])
    return rows
