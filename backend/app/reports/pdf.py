from io import BytesIO
import json
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def scan_pdf(project: dict, scan: dict, components: list[dict], findings: list[dict]) -> bytes:
    stream = BytesIO()
    doc = SimpleDocTemplate(stream, pagesize=letter, title=f"DepShield report - {project['name']}")
    styles = getSampleStyleSheet()
    story = [Paragraph("DepShield Security Assessment", styles["Title"]), Paragraph(escape(project["name"]), styles["Heading2"]),
             Paragraph(f"Scan {escape(scan['id'])} · {escape(scan['created_at'])} · Status: {escape(scan['status'])}", styles["BodyText"]), Spacer(1, 12)]
    priority_counts = {}
    for finding in findings:
        key = finding.get("priority", "Unknown")
        priority_counts[key] = priority_counts.get(key, 0) + 1
    summary = [["Components", str(len(components))], ["Findings", str(len(findings))],
               ["Critical / High", str(sum(f.get("priority") in {"Critical", "High"} for f in findings))],
               ["Known exploited", str(sum(f.get("kev_status") == "known" for f in findings))],
               ["Priority breakdown", json.dumps(priority_counts, sort_keys=True)],
               ["Intelligence", json.dumps(scan.get("intelligence_status", {}), sort_keys=True)],
               ["AI explanation", "Not generated for this report"]]
    table = Table(summary, colWidths=[160, 360])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eef7")), ("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("PADDING", (0, 0), (-1, -1), 6)]))
    story += [table, Spacer(1, 14), Paragraph("Dependency inventory", styles["Heading2"])]
    inventory = [["Component", "Version evidence", "Ecosystem", "Directness", "Resolution", "Source manifest"]]
    for component in components:
        inventory.append([
            Paragraph(escape(component["name"]), styles["BodyText"]),
            Paragraph(escape(component.get("version") or component.get("version_constraint") or "Unpinned"), styles["BodyText"]),
            escape(component["ecosystem"]), escape(component["directness"]), escape(component["resolution"]),
            Paragraph(escape(component["manifest"]), styles["BodyText"]),
        ])
    inventory_table = Table(inventory, repeatRows=1, colWidths=[108, 75, 60, 52, 70, 103])
    inventory_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17243a")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 7), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 4)]))
    story += [inventory_table, Spacer(1, 14), Paragraph("Findings", styles["Heading2"])]
    rows = [["Package", "Advisory", "Severity", "Priority", "CVSS", "Risk", "KEV", "Fix evidence and references"]]
    for finding in findings:
        fixed = finding.get("fixed_versions", [])
        fix_text = "Fixed version: " + (", ".join(fixed) if fixed else "not supplied")
        references = finding.get("vulnerability", {}).get("references", [])
        source_links = "<br/>".join(escape(r.get("url", "")) for r in references[:2] if r.get("url"))
        detail = Paragraph(escape(fix_text) + ("<br/>" + source_links if source_links else ""), styles["BodyText"])
        rows.append([
            Paragraph(escape(f"{finding['component']['name']} {finding['component'].get('version') or ''}"), styles["BodyText"]),
            Paragraph(escape(finding["vulnerability"]["osv_id"]), styles["BodyText"]),
            escape(finding.get("official_severity", "Unknown")), escape(finding.get("priority", "Unknown")),
            str(finding.get("cvss") if finding.get("cvss") is not None else "Unknown"),
            str(finding.get("risk_score") if finding.get("risk_score") is not None else "Unknown"),
            escape(finding.get("kev_status", "unknown")), detail,
        ])
    if len(rows) == 1:
        rows.append([Paragraph("No findings returned by available sources", styles["BodyText"]), "", "", "", "", "", "", ""])
    findings_table = Table(rows, repeatRows=1, colWidths=[75, 55, 45, 47, 30, 35, 38, 143])
    findings_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17243a")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 7), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 4)]))
    story += [findings_table, Spacer(1, 12), Paragraph("Risk priority is a DepShield academic triage heuristic, separate from official severity. Manifest-declared versions may not be installed versions. A missing finding is not proof that a package is safe. Review source availability and advisory references before making changes.", styles["BodyText"])]
    doc.build(story)
    return stream.getvalue()
