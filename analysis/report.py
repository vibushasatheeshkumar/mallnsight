import os
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")


def _table(rows, col_widths=None):
    table = Table(rows, colWidths=col_widths)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C2128")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#30363D")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F4F6")]),
    ]))
    return table


def generate_report(metadata, hashes, pe_info, entropy_info, strings_info, yara_info, score_info):
    """
    Render the analysis results into a PDF report and return its file path.
    """

    os.makedirs(REPORTS_DIR, exist_ok=True)

    base_name = os.path.splitext(metadata.get("name", "report"))[0]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    out_path = os.path.join(REPORTS_DIR, f"{base_name}_{timestamp}.pdf")

    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("MallnSight Static Analysis Report", styles["Title"]))
    story.append(Paragraph(
        datetime.now(timezone.utc).strftime("Generated %Y-%m-%d %H:%M UTC"),
        styles["Normal"]
    ))
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph(
        f"Verdict: {score_info['verdict']} (Risk score: {score_info['score']}/100)",
        styles["Heading2"]
    ))

    if score_info.get("reasons"):
        for reason in score_info["reasons"]:
            story.append(Paragraph(f"- {reason}", styles["Normal"]))

    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("File Information", styles["Heading2"]))
    story.append(_table([
        ["Property", "Value"],
        ["Filename", metadata.get("name", "")],
        ["Size (KB)", str(metadata.get("size", ""))],
        ["Extension", metadata.get("extension", "")],
        ["MIME Type", str(metadata.get("mime", ""))],
    ]))
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Hashes", styles["Heading2"]))
    story.append(_table([
        ["Type", "Value"],
        ["MD5", hashes.get("md5", "")],
        ["SHA1", hashes.get("sha1", "")],
        ["SHA256", hashes.get("sha256", "")],
    ], col_widths=[3 * cm, 12 * cm]))
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Entropy", styles["Heading2"]))
    story.append(Paragraph(
        f"Overall file entropy: {entropy_info.get('entropy')} / 8.0 "
        f"({entropy_info.get('verdict')})",
        styles["Normal"]
    ))
    story.append(Spacer(1, 0.5 * cm))

    if not pe_info.get("error"):
        story.append(Paragraph("PE Analysis", styles["Heading2"]))
        story.append(_table([
            ["Property", "Value"],
            ["Architecture", pe_info.get("architecture", "")],
            ["Compile Time", pe_info.get("compile_time", "")],
            ["Entry Point", pe_info.get("entry_point", "")],
            ["Image Base", pe_info.get("image_base", "")],
            ["Number of Sections", str(pe_info.get("number_of_sections", ""))],
        ]))
        story.append(Spacer(1, 0.5 * cm))

    if yara_info.get("matches"):
        story.append(Paragraph("YARA Matches", styles["Heading2"]))
        rows = [["Rule", "Severity", "Description"]]
        for m in yara_info["matches"]:
            rows.append([m["rule"], m["severity"], m["description"]])
        story.append(_table(rows, col_widths=[5 * cm, 3 * cm, 7 * cm]))
        story.append(Spacer(1, 0.5 * cm))

    if strings_info.get("suspicious"):
        story.append(Paragraph("Suspicious Strings", styles["Heading2"]))
        rows = [["Category", "Value"]]
        for s in strings_info["suspicious"]:
            rows.append([s["category"], s["value"]])
        story.append(_table(rows, col_widths=[6 * cm, 9 * cm]))

    doc = SimpleDocTemplate(out_path, pagesize=A4)
    doc.build(story)

    return out_path
