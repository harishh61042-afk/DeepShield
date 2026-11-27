import re
from html import escape
from urllib.parse import quote

import httpx
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.lib import colors
from io import BytesIO

KNOWN_LICENSES = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSD-4-Clause", "ISC", "MPL-2.0",
    "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
    "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later", "EPL-2.0", "Unlicense", "CC0-1.0", "Zlib", "Artistic-2.0",
}
_TOKEN = re.compile(r"(?<![A-Za-z0-9.-])(?:MIT|Apache-2\.0|BSD-[234]-Clause|ISC|MPL-2\.0|(?:A?GPL|LGPL)-[23](?:\.0|\.1)-(?:only|or-later)|EPL-2\.0|Unlicense|CC0-1\.0|Zlib|Artistic-2\.0)(?![A-Za-z0-9.-])", re.I)
_PACKAGE_PATTERNS = {
    "npm": re.compile(r"(?:@[A-Za-z0-9][A-Za-z0-9._-]{0,213}/)?[A-Za-z0-9][A-Za-z0-9._-]{0,213}\Z"),
    "PyPI": re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z"),
    "crates.io": re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z"),
}
_PACKAGE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+!_~-]{0,254}\Z")


def recognized_licenses(expression: str | None) -> list[str]:
    if not expression:
        return []
    found = {m.group(0) for m in _TOKEN.finditer(expression)}
    canonical = {value.casefold(): value for value in KNOWN_LICENSES}
    return sorted((canonical[value.casefold()] for value in found if value.casefold() in canonical), key=str.casefold)


def evaluate_license_policy(rows: list[dict], policy: dict) -> dict:
    allowed = {value.casefold() for value in (policy.get("allowed_licenses") or [])}
    restricted = {value.casefold() for value in (policy.get("restricted_licenses") or [])}
    violations, unknown = [], []
    for row in rows:
        identifiers = row["recognized_licenses"]
        if not identifiers:
            unknown.append(row)
            continue
        restricted_matches = sorted(value for value in set(identifiers) if value.casefold() in restricted)
        outside_allowlist = sorted(value for value in set(identifiers) if value.casefold() not in allowed) if allowed else []
        if restricted_matches or outside_allowlist:
            violations.append({**row, "restricted_matches": restricted_matches, "outside_allowlist": outside_allowlist})
    return {"violations": violations, "unknown": unknown,
            "status": "review_required" if violations or unknown else "clear",
            "disclaimer": "Automated license visibility is not legal advice. Unknown or ambiguous license evidence requires human review."}


def fetch_registry_license(ecosystem: str, package_name: str, version: str) -> dict:
    package_pattern = _PACKAGE_PATTERNS.get(ecosystem)
    if (not package_pattern or not package_pattern.fullmatch(package_name)
            or not _PACKAGE_VERSION.fullmatch(version)):
        return {"license": None, "status": "unavailable", "source_url": None}
    name, version_value = quote(package_name, safe="@/"), quote(version, safe="")
    headers = {"User-Agent": "DepShield/1.0 (license metadata lookup)"}
    if ecosystem == "npm":
        url = f"https://registry.npmjs.org/{name}/{version_value}"

        def select_value(data):
            return data.get("license")
    elif ecosystem == "PyPI":
        url = f"https://pypi.org/pypi/{name}/{version_value}/json"

        def select_value(data):
            info = data.get("info", {})
            declared = info.get("license")
            if isinstance(declared, str) and declared.strip():
                return declared
            classifiers = info.get("classifiers", [])
            values = [row.removeprefix("License :: ") for row in classifiers
                      if isinstance(row, str) and row.startswith("License :: ")]
            return "; ".join(values) or None
    elif ecosystem == "crates.io":
        url = f"https://crates.io/api/v1/crates/{name}/{version_value}"

        def select_value(data):
            return data.get("version", {}).get("license")
    try:
        response = httpx.get(url, headers=headers, timeout=4.0, follow_redirects=False)
        if response.status_code == 404:
            return {"license": None, "status": "unknown", "source_url": url}
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            return {"license": None, "status": "unavailable", "source_url": url}
        value = select_value(payload)
        if not isinstance(value, str) or not value.strip():
            return {"license": None, "status": "unknown", "source_url": url}
        return {"license": value.strip()[:500], "status": "available", "source_url": url}
    except (httpx.HTTPError, ValueError, TypeError, AttributeError):
        return {"license": None, "status": "unavailable", "source_url": url}


def license_pdf(project_name: str, scan_id: str, rows: list[dict], evaluation: dict) -> bytes:
    out = BytesIO()
    doc = SimpleDocTemplate(out, pagesize=letter, title=f"License inventory — {project_name}")
    styles = getSampleStyleSheet()
    story = [Paragraph(f"License inventory — {escape(project_name)}", styles["Title"]),
             Paragraph(f"Scan: {escape(scan_id)}", styles["Normal"]), Spacer(1, 12)]
    data = [["Package", "Version", "License evidence", "Source"]]
    for row in rows[:1000]:
        data.append([Paragraph(escape(str(row["name"])), styles["BodyText"]),
                     Paragraph(escape(str(row.get("version") or "unknown")), styles["BodyText"]),
                     Paragraph(escape(str(row.get("license") or "UNKNOWN")), styles["BodyText"]),
                     Paragraph(escape(str(row.get("evidence_source") or "none")), styles["BodyText"])])
    table = Table(data, repeatRows=1, colWidths=[170, 70, 180, 90])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F5D65E")),
                               ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#202127")),
                               ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D8D8D2")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FBF4E5")])]))
    story.extend([table, Spacer(1, 12), Paragraph(escape(evaluation["disclaimer"]), styles["Italic"])])
    doc.build(story)
    return out.getvalue()
