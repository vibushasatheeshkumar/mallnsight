"""
Generates MallnSight_SourceCode.pdf — a formatted source code listing
for academic / internship submission.

Font   : Times-Roman / Times-Bold
Spacing: 1.5 line leading
Headers: Bold, underlined section dividers
"""

import os
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, HRFlowable
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# ─── Font sizes & leading (1.5 spacing) ───────────────────────────────────────

TITLE_SIZE      = 20
SUBTITLE_SIZE   = 13
HEADING_SIZE    = 12
BODY_SIZE       = 10
LEADING_MULT    = 1.5      # 1.5× line spacing

# ─── Styles ───────────────────────────────────────────────────────────────────

title_style = ParagraphStyle(
    "Title",
    fontName="Times-Bold",
    fontSize=TITLE_SIZE,
    leading=TITLE_SIZE * LEADING_MULT,
    alignment=TA_CENTER,
    spaceAfter=6,
)

subtitle_style = ParagraphStyle(
    "Subtitle",
    fontName="Times-Roman",
    fontSize=SUBTITLE_SIZE,
    leading=SUBTITLE_SIZE * LEADING_MULT,
    alignment=TA_CENTER,
    spaceAfter=4,
)

section_style = ParagraphStyle(
    "Section",
    fontName="Times-Bold",
    fontSize=HEADING_SIZE,
    leading=HEADING_SIZE * LEADING_MULT,
    spaceBefore=14,
    spaceAfter=4,
    textColor=colors.HexColor("#000000"),
)

filename_style = ParagraphStyle(
    "Filename",
    fontName="Times-Bold",
    fontSize=HEADING_SIZE,
    leading=HEADING_SIZE * LEADING_MULT,
    spaceBefore=10,
    spaceAfter=4,
)

code_style = ParagraphStyle(
    "Code",
    fontName="Times-Roman",
    fontSize=BODY_SIZE,
    leading=BODY_SIZE * LEADING_MULT,
    leftIndent=0,
    wordWrap="LTR",
)

# ─── Files to include ─────────────────────────────────────────────────────────

FILES = [
    # ── Backend ───────────────────────────────────────────────────
    ("Backend", [
        "app.py",
    ]),
    # ── Analysis Modules ──────────────────────────────────────────
    ("Analysis Modules", [
        "analysis/hash.py",
        "analysis/metadata.py",
        "analysis/pe_analysis.py",
        "analysis/entropy.py",
        "analysis/strings.py",
        "analysis/yara_scan.py",
        "analysis/scoring.py",
        "analysis/report.py",
        "analysis/history.py",
    ]),
    # ── YARA Rules ────────────────────────────────────────────────
    ("YARA Rules", [
        "yara_rules/suspicious_indicators.yar",
    ]),
    # ── Templates ─────────────────────────────────────────────────
    ("Templates (HTML)", [
        "templates/base.html",
        "templates/home.html",
        "templates/features.html",
        "templates/about.html",
        "templates/upload.html",
        "templates/dashboard.html",
        "templates/history.html",
        "templates/contact.html",
    ]),
    # ── Static Assets ─────────────────────────────────────────────
    ("Static Assets", [
        "static/css/style.css",
        "static/js/main.js",
    ]),
    # ── Tests ─────────────────────────────────────────────────────
    ("Tests", [
        "tests/test_app.py",
    ]),
    # ── Configuration ─────────────────────────────────────────────
    ("Configuration & Dependencies", [
        "requirements.txt",
        ".env.example",
        "Procfile",
        "runtime.txt",
    ]),
]

# ─── Helpers ──────────────────────────────────────────────────────────────────

def safe_xml(text):
    """Escape XML special characters so Paragraph doesn't choke on code."""
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def nbsp_indent(line):
    """Preserve leading whitespace using non-breaking spaces."""
    stripped = line.lstrip(" ")
    spaces   = len(line) - len(stripped)
    return " " * spaces + safe_xml(stripped)


def file_flowables(rel_path):
    """Return a list of Paragraph flowables for one source file."""
    flowables = []
    flowables.append(Paragraph(rel_path, filename_style))
    flowables.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.grey, spaceAfter=4))

    abs_path = os.path.join(os.path.dirname(__file__), rel_path)

    if not os.path.exists(abs_path):
        flowables.append(
            Paragraph(f"<i>[File not found: {rel_path}]</i>", code_style)
        )
        return flowables

    with open(abs_path, encoding="utf-8", errors="replace") as f:
        raw_lines = f.read().splitlines()

    for line in raw_lines:
        text = nbsp_indent(line) if line.strip() else " "
        flowables.append(Paragraph(text, code_style))

    return flowables


# ─── Build PDF ────────────────────────────────────────────────────────────────

def generate(output_path="MallnSight_SourceCode.pdf"):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2.5 * cm,
        rightMargin=2 * cm,
        topMargin=2.5 * cm,
        bottomMargin=2.5 * cm,
        title="MallnSight — Source Code Listing",
        author="Vibusha Satheesh Kumar",
    )

    story = []

    # ── Title page ────────────────────────────────────────────────
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("MallnSight", title_style))
    story.append(Paragraph(
        "Static Malware Analysis &amp; Threat Intelligence Platform",
        subtitle_style
    ))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("Source Code Listing", subtitle_style))
    story.append(Spacer(1, 0.5 * cm))
    story.append(HRFlowable(width="80%", thickness=1, color=colors.black))
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph(
        "Submitted by: <b>Vibusha Satheesh Kumar</b>", subtitle_style
    ))
    story.append(Paragraph(
        "Repository: https://github.com/vibushasatheeshkumar/mallnsight",
        subtitle_style
    ))
    story.append(PageBreak())

    # ── File sections ─────────────────────────────────────────────
    for section_name, file_list in FILES:
        story.append(Paragraph(section_name, section_style))
        story.append(HRFlowable(
            width="100%", thickness=1, color=colors.black, spaceAfter=6
        ))

        for rel_path in file_list:
            story.extend(file_flowables(rel_path))
            story.append(Spacer(1, 0.4 * cm))

        story.append(PageBreak())

    doc.build(story)
    print(f"Generated: {output_path}")


if __name__ == "__main__":
    generate()
