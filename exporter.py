"""exporter.py - write the comparison to an Excel (.xlsx) workbook."""
from __future__ import annotations

import json

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from osint_core import FIELDS, NA, comparison_rows

FONT = "Arial"
HEAD_FILL = PatternFill("solid", start_color="1F3864")
OK_FILL = PatternFill("solid", start_color="E2EFDA")
BAD_FILL = PatternFill("solid", start_color="FCE4D6")
NA_FONT = Font(name=FONT, size=10, color="808080", italic=True)
THIN = Side(style="thin", color="BFBFBF")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)


def _style_header(ws, row=1):
    for c in ws[row]:
        c.font = Font(name=FONT, bold=True, color="FFFFFF", size=11)
        c.fill = HEAD_FILL
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        c.border = BORDER


def _body_style(ws, first_row=2):
    for row in ws.iter_rows(min_row=first_row):
        for c in row:
            c.font = NA_FONT if c.value == NA else Font(name=FONT, size=10)
            c.alignment = Alignment(wrap_text=True, vertical="top")
            c.border = BORDER


def _widths(ws, widths):
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w


def export_xlsx(report: dict, path: str) -> None:
    wb = Workbook()

    # ---- Sheet 1: side-by-side comparison
    ws = wb.active
    ws.title = "Comparison"
    header, rows = comparison_rows(report)
    ws.append(header)
    for r in rows:
        ws.append(r)
    _style_header(ws)
    _body_style(ws)
    for c in ws[2][1:]:  # colour the status row
        c.fill = OK_FILL if str(c.value).startswith("OK") else BAD_FILL
    for c in ws["A"][1:]:
        c.font = Font(name=FONT, bold=True, size=10)
    _widths(ws, [30] + [42] * (len(header) - 1))
    ws.freeze_panes = "B2"

    # ---- Sheet 2: long-format findings (easy to filter / pivot)
    ws2 = wb.create_sheet("Findings")
    ws2.append(["Tool", "Attribute", "Value", "Status"])
    for tool, res in report["results"].items():
        for f in FIELDS:
            ws2.append([tool, f, res["fields"].get(f, NA), res["status"]])
    _style_header(ws2)
    _body_style(ws2)
    _widths(ws2, [18, 30, 80, 14])
    ws2.auto_filter.ref = ws2.dimensions
    ws2.freeze_panes = "A2"

    # ---- Sheet 3: coverage summary
    ws3 = wb.create_sheet("Coverage")
    ws3.append(["Tool", "Status", "Attributes with data", f"Attributes N/A (of {len(FIELDS)})", "Message"])
    for tool, res in report["results"].items():
        have = sum(1 for f in FIELDS if res["fields"].get(f, NA) != NA)
        ws3.append([tool, res["status"], have, len(FIELDS) - have, res["message"]])
    _style_header(ws3)
    _body_style(ws3)
    _widths(ws3, [18, 14, 20, 24, 70])

    # ---- Sheet 4: raw API responses (Excel cell limit = 32,767 chars)
    ws4 = wb.create_sheet("Raw JSON")
    ws4.append(["Tool", "Raw response (truncated to 30,000 chars)"])
    for tool, res in report["results"].items():
        text = json.dumps(res["raw"], indent=1, default=str) if res["raw"] is not None else ""
        ws4.append([tool, text[:30000]])
    _style_header(ws4)
    _body_style(ws4)
    _widths(ws4, [18, 120])

    # ---- Sheet 5: metadata / methodology
    ws5 = wb.create_sheet("Metadata")
    meta = [
        ("Target (host)", report["target"]),
        ("Apex domain used for domain-level APIs", report["domain"]),
        ("IPs resolved by local DNS", ", ".join(report["local_dns_ips"]) or NA),
        ("Collection time", report["collected_utc"]),
        ("Collection type", "Passive - only third-party OSINT APIs were queried; the target was not contacted."),
        ("Note", "'N/A' means the tool does not provide that data type or returned nothing; it is not proof of absence."),
        ("Note", "Findings are tool outputs and should be corroborated before being treated as verified."),
    ]
    ws5.append(["Item", "Value"])
    for m in meta:
        ws5.append(list(m))
    _style_header(ws5)
    _body_style(ws5)
    _widths(ws5, [40, 100])

    wb.save(path)
