from app.ai.explanations import explain
from app.core.config import settings


def test_ollama_disabled_returns_labeled_deterministic_explanation(monkeypatch):
    monkeypatch.setattr(settings, "ollama_enabled", False)
    result = explain(
        {"osv_id": "OSV-TEST-1", "aliases": [], "summary": "A test advisory.", "references": [{"url": "https://example.test/advisory"}]},
        {"name": "sample-package", "version": "1.0.0", "ecosystem": "npm"},
        {"priority": "Medium", "risk_score": 54, "kev_status": "unknown", "fixed_versions": []},
    )
    assert result.generated_by == "deterministic_fallback"
    assert result.references == ["https://example.test/advisory"]
    assert "sample-package 1.0.0" in result.explanation
