def score_finding(cvss: float | None, kev: bool | None, directness: str, fixed_versions: list[str]) -> tuple[int | None, str, dict]:
    """Academic triage heuristic; separate from the advisory's official severity."""
    factors = {
        "cvss_points": round(max(0.0, min(float(cvss), 10.0)) * 6) if cvss is not None else None,
        "known_exploited_points": 25 if kev is True else (0 if kev is False else None),
        "direct_dependency_points": 10 if directness == "direct" else (0 if directness == "transitive" else None),
        "verified_fix_points": 5 if fixed_versions else 0,
    }
    if cvss is None:
        return None, "Unknown", factors
    score = min(100, factors["cvss_points"] + (factors["known_exploited_points"] or 0) + (factors["direct_dependency_points"] or 0) + factors["verified_fix_points"])
    priority = "Critical" if score >= 85 else "High" if score >= 65 else "Medium" if score >= 40 else "Low"
    return score, priority, factors


def official_severity(cvss: float | None) -> str:
    if cvss is None:
        return "Unknown"
    return "Critical" if cvss >= 9 else "High" if cvss >= 7 else "Medium" if cvss >= 4 else "Low"
