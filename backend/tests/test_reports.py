from app.reports.pdf import scan_pdf


def test_pdf_report_generates_with_untrusted_text_escaped():
    payload = scan_pdf(
        {"name": "<script>unsafe & project</script>"},
        {"id": "scan-123", "created_at": "2026-11-26T12:00:00+00:00", "status": "completed", "intelligence_status": {"osv": "available"}},
        [{"name": "<img>package", "version": None, "version_constraint": ">=1", "ecosystem": "PyPI", "directness": "direct", "resolution": "declared_unverified", "manifest": "requirements.txt"}],
        [],
    )
    assert payload.startswith(b"%PDF-")
