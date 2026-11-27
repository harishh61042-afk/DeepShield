import httpx
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import create_engine

from app.core.database import Base
from app.intelligence import kev, osv
from app.models.entities import IntelligenceCache


def test_osv_malformed_batch_is_unavailable_not_clean(monkeypatch):
    monkeypatch.setattr(osv, "_post_with_retry", lambda *args, **kwargs: {"results": [{"vulns": "unexpected"}]})
    components = [{"name": "demo", "version": "1.0", "ecosystem": "npm", "resolution": "resolved"}]
    result, status = osv.query_components(components)
    assert result == {0: []}
    assert status == "unavailable"


def test_osv_query_fetches_full_records_and_follows_batch_pagination(monkeypatch):
    responses = iter(
        [
            {"results": [{"vulns": [{"id": "OSV-QA-1", "modified": "2026-01-01T00:00:00Z"}], "next_page_token": "page-2"}]},
            {"results": [{"vulns": [{"id": "OSV-QA-2", "modified": "2026-01-02T00:00:00Z"}]}]},
        ]
    )
    requests = []

    def post(client, url, body, **kwargs):
        requests.append(body["queries"])
        return next(responses)

    def full_record(client, advisory_id, **kwargs):
        return {"id": advisory_id, "affected": [], "summary": f"Full {advisory_id} record", "aliases": [], "references": []}

    monkeypatch.setattr(osv, "_post_with_retry", post)
    monkeypatch.setattr(osv, "_get_advisory_with_retry", full_record)
    monkeypatch.setattr(osv, "_advisory_cache", {})
    components = [{"name": "demo", "version": "1.0", "ecosystem": "npm", "resolution": "resolved"}]

    found, status = osv.query_components(components)

    assert status == "available"
    assert [item["id"] for item in found[0]] == ["OSV-QA-1", "OSV-QA-2"]
    assert found[0][0]["summary"] == "Full OSV-QA-1 record"
    assert "page_token" not in requests[0][0]
    assert requests[1][0]["page_token"] == "page-2"


def test_osv_uses_querybatch_ids_to_fetch_full_advisory_record(monkeypatch):
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path))
        if request.method == "POST":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "OSV-QA-GET", "modified": "2026-01-01"}]}]})
        return httpx.Response(200, json={"id": "OSV-QA-GET", "summary": "Full record", "affected": [], "aliases": [], "references": []})

    original_client = httpx.Client
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(osv.httpx, "Client", lambda *args, **kwargs: original_client(transport=transport, *args, **kwargs))
    monkeypatch.setattr(osv, "_advisory_cache", {})
    components = [{"name": "demo", "version": "1.0", "ecosystem": "npm", "resolution": "resolved"}]

    found, status = osv.query_components(components)

    assert status == "available"
    assert found[0][0]["summary"] == "Full record"
    assert seen == [("POST", "/v1/querybatch"), ("GET", "/v1/vulns/OSV-QA-GET")]


def test_osv_keeps_match_id_and_marks_partial_when_detail_fetch_fails(monkeypatch):
    monkeypatch.setattr(osv, "_post_with_retry", lambda *args, **kwargs: {"results": [{"vulns": [{"id": "CVE-2099-0001", "modified": "2026-01-01"}]}]})

    def unavailable(*args, **kwargs):
        raise osv.IntelligenceUnavailable("offline")

    monkeypatch.setattr(osv, "_get_advisory_with_retry", unavailable)
    monkeypatch.setattr(osv, "_advisory_cache", {})
    components = [{"name": "demo", "version": "1.0", "ecosystem": "npm", "resolution": "resolved"}]

    found, status = osv.query_components(components)

    assert status == "partial"
    assert found[0][0]["id"] == "CVE-2099-0001"
    assert osv.cve_ids(found[0][0]) == ["CVE-2099-0001"]


def test_osv_cache_deduplicates_same_package_from_multiple_manifests(monkeypatch):
    engine = create_engine("sqlite+pysqlite://", poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    advisory = {"id": "OSV-QA-1", "aliases": [], "affected": [], "references": []}
    monkeypatch.setattr(osv, "query_components", lambda components, deadline=None: ({0: [advisory]}, "available"))
    components = [
        {"name": "Demo-Package", "version": "1.0.0", "ecosystem": "PyPI", "resolution": "declared_unverified", "manifest": "one/requirements.txt"},
        {"name": "demo-package", "version": "1.0.0", "ecosystem": "PyPI", "resolution": "declared_unverified", "manifest": "two/requirements.txt"},
    ]
    try:
        with factory() as db:
            found, status = osv.query_components_cached(db, components)
            assert status == "available"
            assert found == {0: [advisory], 1: [advisory]}
            rows = db.scalars(select(IntelligenceCache)).all()
            assert len(rows) == 1
    finally:
        engine.dispose()


def test_nvd_malformed_response_is_unavailable(monkeypatch):
    original_client = httpx.Client
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"vulnerabilities": "bad-shape"}))
    monkeypatch.setattr(osv.httpx, "Client", lambda *args, **kwargs: original_client(transport=transport, *args, **kwargs))
    monkeypatch.setattr(osv, "_nvd_cache", {})
    monkeypatch.setattr(osv, "_nvd_last_call", 0.0)
    assert osv.nvd_enrich("CVE-2099-0001") == {"_unavailable": True}


def test_nvd_extracts_cvss_cwe_and_english_description(monkeypatch):
    payload = {
        "vulnerabilities": [{
            "cve": {
                "descriptions": [{"lang": "en", "value": "Example vulnerability"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                "published": "2026-01-01T00:00:00.000",
                "lastModified": "2026-02-01T00:00:00.000",
            },
        }],
    }
    original_client = httpx.Client
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=payload))
    monkeypatch.setattr(osv.httpx, "Client", lambda *args, **kwargs: original_client(transport=transport, *args, **kwargs))
    monkeypatch.setattr(osv, "_nvd_cache", {})
    monkeypatch.setattr(osv, "_nvd_last_call", 0.0)

    result = osv.nvd_enrich("CVE-2099-0002")

    assert result["cvss"] == 9.8
    assert result["severity"] == "CRITICAL"
    assert result["cwes"] == ["CWE-79"]
    assert result["description"] == "Example vulnerability"


def test_kev_malformed_document_is_unavailable(monkeypatch):
    original_client = httpx.Client
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=[]))
    monkeypatch.setattr(kev.httpx, "Client", lambda *args, **kwargs: original_client(transport=transport, *args, **kwargs))
    monkeypatch.setattr(kev, "_cache", None)
    assert kev.load_kev() == (set(), "unavailable")
