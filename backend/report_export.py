"""
report_export.py — Renders the full scan (metrics, security findings,
dependency vulns, git churn, dependency graph, and the AI review) into a
downloadable PDF report using reportlab.
"""

import io
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak, HRFlowable,
)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#c0392b"),
    "high": colors.HexColor("#e67e22"),
    "medium": colors.HexColor("#f1c40f"),
    "low": colors.HexColor("#95a5a6"),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="H1Custom", fontSize=20, spaceAfter=12, textColor=colors.HexColor("#1a1a2e")))
    styles.add(ParagraphStyle(name="H2Custom", fontSize=14, spaceBefore=16, spaceAfter=8, textColor=colors.HexColor("#16213e")))
    styles.add(ParagraphStyle(name="BodySmall", fontSize=9, leading=13))
    styles.add(ParagraphStyle(name="Mono", fontName="Courier", fontSize=8, leading=11))
    return styles


def build_pdf_report(
    project_name: str,
    analysis,
    security_findings: list[dict],
    dependency_findings: list[dict],
    git_result,
    dep_graph_result,
    review: dict,
) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
    )
    styles = _styles()
    story = []

    # --- Cover / title ---
    story.append(Paragraph(f"CodeSage AI Review: {project_name}", styles["H1Custom"]))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#e0e0e0")))
    story.append(Spacer(1, 12))

    metrics_table_data = [
        ["Total Files", str(analysis.total_files)],
        ["Total LOC", str(analysis.total_loc)],
        ["Avg. Complexity", str(analysis.avg_complexity)],
        ["Avg. Maintainability Index", str(analysis.avg_maintainability)],
        ["Estimated Tech Debt", f"{analysis.tech_debt_hours} hours"],
        ["Security Findings", str(len(security_findings))],
        ["Dependency Vulnerabilities", str(len(dependency_findings))],
    ]
    t = Table(metrics_table_data, colWidths=[220, 220])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f5f7")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1a1a2e")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    # --- AI review ---
    story.append(Paragraph("Executive Summary", styles["H2Custom"]))
    story.append(Paragraph(_escape(review.get("executive_summary", "Not generated.")), styles["Normal"]))

    story.append(Paragraph("Risk Assessment", styles["H2Custom"]))
    story.append(Paragraph(_escape(review.get("risk_assessment", "Not generated.")).replace("\n", "<br/>"), styles["Normal"]))

    story.append(Paragraph("Action Plan", styles["H2Custom"]))
    story.append(Paragraph(_escape(review.get("action_plan", "Not generated.")).replace("\n", "<br/>"), styles["Normal"]))
    story.append(PageBreak())

    # --- Complexity hotspots ---
    story.append(Paragraph("Complexity Hotspots", styles["H2Custom"]))
    hotspot_rows = [["File", "Complexity", "Maintainability", "LOC"]]
    for fm in analysis.hotspots[:12]:
        hotspot_rows.append([fm.path, str(fm.complexity), str(fm.maintainability_index), str(fm.loc)])
    story.append(_styled_table(hotspot_rows))
    story.append(Spacer(1, 16))

    # --- Security findings ---
    story.append(Paragraph("Security Findings", styles["H2Custom"]))
    if security_findings:
        for f in security_findings[:30]:
            color = SEVERITY_COLORS.get(f["severity"], colors.grey)
            story.append(Paragraph(
                f'<font color="{color.hexval()}"><b>[{f["severity"].upper()}]</b></font> '
                f'{_escape(f["description"])} — <font face="Courier">{_escape(f["file_path"])}:{f["line_number"]}</font>',
                styles["BodySmall"],
            ))
        if len(security_findings) > 30:
            story.append(Paragraph(f"...and {len(security_findings) - 30} more (see JSON export for full list).", styles["BodySmall"]))
    else:
        story.append(Paragraph("No security findings detected.", styles["BodySmall"]))
    story.append(Spacer(1, 16))

    # --- Dependency vulnerabilities ---
    story.append(Paragraph("Dependency Vulnerabilities", styles["H2Custom"]))
    if dependency_findings:
        dep_rows = [["Package", "Version", "CVE", "Severity", "Fix"]]
        for d in dependency_findings[:20]:
            dep_rows.append([d["package_name"], d["installed_version"], d["vulnerability_id"], d["severity"], d["fix_version"]])
        story.append(_styled_table(dep_rows))
    else:
        story.append(Paragraph("No known-vulnerable dependencies detected.", styles["BodySmall"]))
    story.append(Spacer(1, 16))

    # --- Git churn ---
    story.append(Paragraph("Git Churn Hotspots", styles["H2Custom"]))
    if git_result.available and git_result.churn:
        churn_rows = [["File", "Commits", "Authors", "Bus Factor Risk"]]
        for c in git_result.churn[:12]:
            churn_rows.append([c.file_path, str(c.commit_count), str(c.author_count), "Yes" if c.bus_factor_risk else "No"])
        story.append(_styled_table(churn_rows))
    else:
        story.append(Paragraph(git_result.reason_unavailable or "No git history available.", styles["BodySmall"]))

    # --- Dependency graph ---
    if dep_graph_result and dep_graph_result.image_bytes:
        story.append(PageBreak())
        story.append(Paragraph("Module Dependency Graph", styles["H2Custom"]))
        if dep_graph_result.cycles:
            cycle_text = "; ".join(" → ".join(cyc) for cyc in dep_graph_result.cycles[:5])
            story.append(Paragraph(f"<b>Circular imports detected:</b> {_escape(cycle_text)}", styles["BodySmall"]))
            story.append(Spacer(1, 8))
        img_buf = io.BytesIO(dep_graph_result.image_bytes)
        story.append(Image(img_buf, width=6.2 * inch, height=4.3 * inch))

    doc.build(story)
    buf.seek(0)
    return buf.read()


def _styled_table(rows: list[list[str]]) -> Table:
    t = Table(rows, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9f9fb")]),
    ]))
    return t


def _escape(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
