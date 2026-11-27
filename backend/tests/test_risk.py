from app.risk.scoring import official_severity, score_finding


def test_risk_heuristic_caps_at_one_hundred():
    score, priority, factors = score_finding(10.0, True, "direct", ["2.0"])
    assert score == 100
    assert priority == "Critical"
    assert factors["known_exploited_points"] == 25


def test_missing_cvss_stays_unknown():
    score, priority, factors = score_finding(None, True, "direct", [])
    assert score is None
    assert priority == "Unknown"
    assert factors["cvss_points"] is None


def test_official_severity_is_distinct_from_custom_score():
    assert official_severity(9.8) == "Critical"
    assert official_severity(None) == "Unknown"

