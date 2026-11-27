from datetime import datetime, timezone

PRIORITY_ORDER = {"Unknown": -1, "Low": 0, "Medium": 1, "High": 2, "Critical": 3}
DEFAULT_POLICY = {
    "max_allowed_priority": "High", "fail_on_kev": True,
    "partial_behavior": "warning", "unavailable_behavior": "warning",
    "fail_on_unknown_license": False, "allowed_licenses": [], "restricted_licenses": [],
}


def evaluate_scan_policy(scan, findings: list[dict], policy: dict, license_result: dict | None = None) -> dict:
    configured = {**DEFAULT_POLICY, **(policy or {})}
    failures, warnings, checks = [], [], []
    threshold = PRIORITY_ORDER[configured["max_allowed_priority"]]
    over = [row for row in findings if PRIORITY_ORDER.get(row.get("priority", "Unknown"), -1) > threshold]
    checks.append({"name": "priority_threshold", "passed": not over, "count": len(over), "limit": configured["max_allowed_priority"]})
    if over:
        failures.append(f"{len(over)} finding(s) exceed the permitted {configured['max_allowed_priority']} priority")
    known_kev = [row for row in findings if row.get("kev_status") == "known"]
    checks.append({"name": "known_exploited", "passed": not known_kev or not configured["fail_on_kev"], "count": len(known_kev)})
    if known_kev and configured["fail_on_kev"]:
        failures.append(f"{len(known_kev)} finding(s) match the CISA Known Exploited Vulnerabilities catalog")
    unknown = [row for row in findings if row.get("priority", "Unknown") == "Unknown"]
    if unknown:
        warnings.append(f"{len(unknown)} finding(s) have unknown priority evidence")
    if scan.status != "completed":
        behavior = configured["partial_behavior"]
        message = f"Scan status is {scan.status}; absence of findings is not conclusive"
        checks.append({"name": "scan_completeness", "passed": behavior != "fail", "status": scan.status})
        (failures if behavior == "fail" else warnings).append(message)
    intelligence = scan.intelligence_status or {}
    unreliable = [source for source in ("osv", "cisa_kev") if intelligence.get(source) not in {"available", "cached"}]
    if unreliable:
        behavior = configured["unavailable_behavior"]
        checks.append({"name": "intelligence_sources", "passed": behavior != "fail", "sources": unreliable})
        message = "Required intelligence evidence is incomplete: " + ", ".join(unreliable)
        (failures if behavior == "fail" else warnings).append(message)
    else:
        checks.append({"name": "intelligence_sources", "passed": True, "sources": []})
    if license_result:
        license_failures = license_result.get("violations", [])
        unknown_licenses = license_result.get("unknown", [])
        if license_failures:
            failures.append(f"{len(license_failures)} component(s) violate the project license policy")
        if unknown_licenses:
            message = f"{len(unknown_licenses)} component(s) have unknown or ambiguous license evidence"
            (failures if configured["fail_on_unknown_license"] else warnings).append(message)
        checks.append({"name": "license_compliance", "passed": not license_failures and (not unknown_licenses or not configured["fail_on_unknown_license"]),
                       "violations": len(license_failures), "unknown": len(unknown_licenses)})
    status = "FAIL" if failures else "WARNING" if warnings else "PASS"
    return {"status": status, "scan_id": str(scan.id), "project_id": str(scan.project_id),
            "evaluated_at": datetime.now(timezone.utc).isoformat(), "policy": configured,
            "checks": checks, "failures": failures, "warnings": warnings}
