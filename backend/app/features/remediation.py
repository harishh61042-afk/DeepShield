from html import escape
from io import BytesIO

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer


def build_remediation_plan(scan, findings: list[dict], ai_explanations: dict | None = None) -> dict:
    groups = {"urgent": [], "high": [], "routine": [], "needs_evidence": []}
    for row in findings:
        component = row["component"]
        versions = sorted({v.strip() for v in row.get("fixed_versions", []) if isinstance(v, str) and v.strip()})
        current = component.get("version")
        target = versions[0] if current and len(versions) == 1 else None
        can_recommend = bool(current and target)
        item = {
            "package": component["name"], "ecosystem": component["ecosystem"],
            "current_version": current, "version_evidence": component.get("resolution"),
            "vulnerability_id": row["vulnerability"]["osv_id"], "summary": row["vulnerability"].get("summary"),
            "official_severity": row.get("official_severity"), "priority": row.get("priority"),
            "affected_ranges": row.get("affected_ranges", []),
            "known_exploited": row.get("kev_status") == "known", "fixed_versions": versions,
            "recommended_target": target, "recommendation_status": "evidence_available" if can_recommend else "no_unambiguous_verified_target",
            "reason": (f"OSV identifies {target} as a fixed version for this exact package advisory." if can_recommend
                       else "No single fixed version is available from the stored advisory evidence; verify the upstream advisory before upgrading."),
            "ai_explanation": (ai_explanations or {}).get(row["id"]),
        }
        if not can_recommend:
            groups["needs_evidence"].append(item)
        elif item["known_exploited"] or item["priority"] == "Critical":
            groups["urgent"].append(item)
        elif item["priority"] == "High":
            groups["high"].append(item)
        else:
            groups["routine"].append(item)
    return {"scan_id": str(scan.id), "status": scan.status, "groups": groups,
            "limitations": ["Targets are reported only when OSV provides a single fixed-version value for a matched finding.",
                            "Validate compatibility, release notes and transitive impact before changing dependencies.",
                            "No files are changed and no packages are installed by DepShield."]}


def remediation_pdf(project_name: str, plan: dict) -> bytes:
    out = BytesIO()
    doc = SimpleDocTemplate(out, pagesize=letter, title=f"Remediation plan — {project_name}")
    styles = getSampleStyleSheet()
    story = [Paragraph(f"Remediation plan — {escape(project_name)}", styles["Title"]),
             Paragraph(f"Scan status: {escape(plan['status'])}", styles["Normal"]), Spacer(1, 12)]
    for title, key in (("Urgent", "urgent"), ("High priority", "high"), ("Routine", "routine"), ("Needs more evidence", "needs_evidence")):
        story.append(Paragraph(title, styles["Heading2"]))
        items = plan["groups"][key]
        if not items:
            story.append(Paragraph("No items", styles["BodyText"]))
        for item in items:
            target = f" → target {item['recommended_target']}" if item["recommended_target"] else " → target not verified"
            story.append(Paragraph(escape(f"{item['package']} {item['current_version'] or '(version unverified)'} — {item['vulnerability_id']}{target}"), styles["BodyText"]))
            story.append(Paragraph(escape(item["reason"]), styles["BodyText"]))
            story.append(Spacer(1, 5))
    story.extend([Spacer(1, 10), Paragraph("Recommendations are evidence summaries, not automatic upgrades. Check project compatibility and vendor guidance.", styles["Italic"])])
    doc.build(story)
    return out.getvalue()
