from collections.abc import Iterator
import json
from datetime import datetime, timezone
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main
from app.core.database import Base, get_db
from app.models.entities import Component, Finding, Notification, PasswordResetToken, Scan, ScanJob, SessionRecord, User, Vulnerability
from app.scan_jobs import enqueue_scan_job


@pytest.fixture
def test_sessions() -> Iterator[sessionmaker]:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    try:
        yield factory
    finally:
        engine.dispose()


@pytest.fixture
def client(test_sessions: sessionmaker) -> Iterator[TestClient]:
    def override_get_db():
        db = test_sessions()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[get_db] = override_get_db
    main._limits.clear()
    try:
        with TestClient(main.app, raise_server_exceptions=False) as test_client:
            yield test_client
    finally:
        main.app.dependency_overrides.clear()
        main._limits.clear()


def get_csrf(client: TestClient) -> str:
    response = client.get("/api/v1/auth/csrf")
    assert response.status_code == 200
    return response.json()["csrf_token"]


def register_user(client: TestClient, email: str) -> None:
    csrf = get_csrf(client)
    response = client.post(
        "/api/v1/auth/register",
        headers={"X-CSRF-Token": csrf},
        json={
            "email": email,
            "display_name": "QA User",
            "password": "a-long-test-password-123",
            "accept_terms": True,
        },
    )
    assert response.status_code == 202


def login_user(client: TestClient, email: str, password: str = "a-long-test-password-123") -> dict:
    csrf = get_csrf(client)
    response = client.post(
        "/api/v1/auth/login",
        headers={"X-CSRF-Token": csrf},
        json={"email": email, "password": password},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_authentication_register_login_logout_and_relogin(client: TestClient, test_sessions: sessionmaker):
    register_user(client, "qa@example.com")
    register_user(client, "qa@example.com")  # Duplicate registration is intentionally non-enumerating.

    csrf = get_csrf(client)
    bad_login = client.post(
        "/api/v1/auth/login",
        headers={"X-CSRF-Token": csrf},
        json={"email": "qa@example.com", "password": "wrong-password"},
    )
    assert bad_login.status_code == 401
    assert bad_login.json() == {"detail": "Email or password is incorrect"}

    signed_in = login_user(client, "qa@example.com")
    assert client.get("/api/v1/auth/me").json()["user"]["email"] == "qa@example.com"
    logout = client.post(
        "/api/v1/auth/logout",
        headers={"X-CSRF-Token": signed_in["csrf_token"]},
    )
    assert logout.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401

    login_user(client, "qa@example.com")
    with test_sessions() as db:
        users = db.scalars(select(User).where(User.email == "qa@example.com")).all()
        assert len(users) == 1
        assert users[0].password_hash != "a-long-test-password-123"


def test_upload_creates_persisted_scan_components_and_cancel_state(client: TestClient, test_sessions: sessionmaker):
    register_user(client, "scan@example.com")
    signed_in = login_user(client, "scan@example.com")
    csrf = signed_in["csrf_token"]
    project = client.post(
        "/api/v1/projects",
        headers={"X-CSRF-Token": csrf},
        json={"name": "QA project", "description": "isolated test", "ecosystem": "python"},
    )
    assert project.status_code == 201, project.text
    project_id = project.json()["id"]

    upload = client.post(
        f"/api/v1/projects/{project_id}/scans",
        headers={"X-CSRF-Token": csrf},
        files={"file": ("requirements.txt", b"Django==4.2.4\nrequests>=2.31,<3\n", "text/plain")},
    )
    assert upload.status_code == 202, upload.text
    scan_id = upload.json()["id"]
    assert upload.json()["component_count"] == 2

    with test_sessions() as db:
        scan_uuid = UUID(scan_id)
        scan = db.get(Scan, scan_uuid)
        components = db.scalars(select(Component).where(Component.scan_id == scan_uuid)).all()
        job = db.scalar(select(ScanJob).where(ScanJob.scan_id == scan_uuid))
        assert scan is not None and scan.status == "queued"
        assert {component.name for component in components} == {"Django", "requests"}
        assert job is not None and job.status == "queued"
        first_job_id = job.id
        duplicate, inserted = enqueue_scan_job(db, scan)
        assert not inserted and duplicate.id == first_job_id
        assert db.scalar(select(func.count(ScanJob.id)).where(ScanJob.scan_id == scan_uuid)) == 1
        db.commit()

    cancelled = client.post(f"/api/v1/scans/{scan_id}/cancel", headers={"X-CSRF-Token": csrf})
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert client.get(f"/api/v1/scans/{scan_id}").json()["status"] == "cancelled"
    with test_sessions() as db:
        job = db.scalar(select(ScanJob).where(ScanJob.scan_id == UUID(scan_id)))
        assert job is not None and job.status == "cancelled" and job.locked_at is None

    processing_upload = client.post(
        f"/api/v1/projects/{project_id}/scans",
        headers={"X-CSRF-Token": csrf},
        files={"file": ("requirements.txt", b"requests==2.31.0\n", "text/plain")},
    )
    assert processing_upload.status_code == 202, processing_upload.text
    processing_id = UUID(processing_upload.json()["id"])
    with test_sessions() as db:
        scan = db.get(Scan, processing_id)
        job = db.scalar(select(ScanJob).where(ScanJob.scan_id == processing_id))
        assert scan is not None and job is not None
        scan.status = "processing"
        job.status = "processing"
        job.locked_at = datetime.now(timezone.utc)
        db.commit()
    processing_cancel = client.post(f"/api/v1/scans/{processing_id}/cancel", headers={"X-CSRF-Token": csrf})
    assert processing_cancel.status_code == 200
    with test_sessions() as db:
        scan = db.get(Scan, processing_id)
        job = db.scalar(select(ScanJob).where(ScanJob.scan_id == processing_id))
        assert scan is not None and scan.status == "cancelled"
        assert job is not None and job.status == "cancelled" and job.locked_at is None


def test_upload_validation_rejects_unsupported_empty_and_malformed_files(client: TestClient):
    register_user(client, "upload@example.com")
    signed_in = login_user(client, "upload@example.com")
    project = client.post(
        "/api/v1/projects",
        headers={"X-CSRF-Token": signed_in["csrf_token"]},
        json={"name": "Upload QA", "ecosystem": "mixed"},
    ).json()
    csrf = signed_in["csrf_token"]

    for filename, contents in (
        ("package.json", b'{"dependencies":{"left-pad":"1.0.0"}}'),
        ("requirements.txt", b""),
        ("package-lock.json", b'{"lockfileVersion":3,"packages":{"node_modules/x":{"version":"1","dependencies":["bad"]}}}'),
    ):
        response = client.post(
            f"/api/v1/projects/{project['id']}/scans",
            headers={"X-CSRF-Token": csrf},
            files={"file": (filename, contents, "application/octet-stream")},
        )
        assert response.status_code == 422, (filename, response.text)


def test_upload_enforces_configured_file_size_limit(client: TestClient, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "max_upload_bytes", 10)
    register_user(client, "large-upload@example.com")
    signed_in = login_user(client, "large-upload@example.com")
    project = client.post(
        "/api/v1/projects",
        headers={"X-CSRF-Token": signed_in["csrf_token"]},
        json={"name": "Size limit", "ecosystem": "python"},
    ).json()
    response = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        headers={"X-CSRF-Token": signed_in["csrf_token"]},
        files={"file": ("requirements.txt", b"x" * 11, "text/plain")},
    )
    assert response.status_code == 413


def test_live_health_and_openapi_are_available(client: TestClient):
    assert client.get("/health/live").json() == {"status": "alive", "service": "api"}
    schema = client.get("/openapi.json")
    assert schema.status_code == 200
    assert "/api/v1/projects/{project_id}/scans" in schema.json()["paths"]


def test_csrf_and_project_ownership_are_enforced(client: TestClient):
    register_user(client, "owner@example.com")
    signed_in = login_user(client, "owner@example.com")
    denied = client.post(
        "/api/v1/projects",
        json={"name": "No token", "ecosystem": "python"},
    )
    assert denied.status_code == 403
    project = client.post(
        "/api/v1/projects",
        headers={"X-CSRF-Token": signed_in["csrf_token"]},
        json={"name": "Private project", "ecosystem": "python"},
    ).json()
    client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": signed_in["csrf_token"]})
    register_user(client, "other@example.com")
    login_user(client, "other@example.com")
    assert client.get(f"/api/v1/projects/{project['id']}").status_code == 404


def test_password_reset_is_single_use_and_revokes_existing_sessions(client: TestClient, test_sessions: sessionmaker, monkeypatch):
    from app.core.config import settings

    deliveries = []
    monkeypatch.setattr(settings, "smtp_host", "test-smtp")
    monkeypatch.setattr(main, "_send_reset_email", lambda email, raw: deliveries.append((email, raw)))
    register_user(client, "reset@example.com")
    signed_in = login_user(client, "reset@example.com")
    reset_response = client.post(
        "/api/v1/auth/password-reset",
        headers={"X-CSRF-Token": signed_in["csrf_token"]},
        json={"email": "reset@example.com"},
    )
    assert reset_response.status_code == 202
    assert reset_response.json() == {"message": "If an active account matches that address, password reset instructions will be sent."}
    client.post(
        "/api/v1/auth/password-reset",
        headers={"X-CSRF-Token": signed_in["csrf_token"]},
        json={"email": "reset@example.com"},
    )
    assert len(deliveries) == 2

    reset = client.post(
        "/api/v1/auth/password-reset/complete",
        headers={"X-CSRF-Token": signed_in["csrf_token"]},
        json={"token": deliveries[0][1], "new_password": "a-new-test-password-456"},
    )
    assert reset.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401
    with test_sessions() as db:
        tokens = db.scalars(select(PasswordResetToken)).all()
        session = db.scalar(select(SessionRecord))
        assert len(tokens) == 2 and all(token.used_at is not None for token in tokens)
        assert session is not None and session.revoked_at is not None

    csrf = get_csrf(client)
    stale_reset = client.post(
        "/api/v1/auth/password-reset/complete",
        headers={"X-CSRF-Token": csrf},
        json={"token": deliveries[1][1], "new_password": "another-new-password-789"},
    )
    assert stale_reset.status_code == 400

    csrf = get_csrf(client)
    old_login = client.post(
        "/api/v1/auth/login",
        headers={"X-CSRF-Token": csrf},
        json={"email": "reset@example.com", "password": "a-long-test-password-123"},
    )
    assert old_login.status_code == 401
    login_user(client, "reset@example.com", password="a-new-test-password-456")


def test_password_change_revokes_sessions_and_pending_reset_tokens(client: TestClient, test_sessions: sessionmaker, monkeypatch):
    from app.core.config import settings

    deliveries = []
    monkeypatch.setattr(settings, "smtp_host", "test-smtp")
    monkeypatch.setattr(main, "_send_reset_email", lambda email, raw: deliveries.append((email, raw)))
    register_user(client, "change-password@example.com")
    signed_in = login_user(client, "change-password@example.com")
    client.post(
        "/api/v1/auth/password-reset",
        headers={"X-CSRF-Token": signed_in["csrf_token"]},
        json={"email": "change-password@example.com"},
    )
    assert len(deliveries) == 1

    changed = client.post(
        "/api/v1/auth/password",
        headers={"X-CSRF-Token": signed_in["csrf_token"]},
        json={"current_password": "a-long-test-password-123", "new_password": "a-changed-test-password-789"},
    )
    assert changed.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401
    with test_sessions() as db:
        token = db.scalar(select(PasswordResetToken))
        assert token is not None and token.used_at is not None

    csrf = get_csrf(client)
    stale_reset = client.post(
        "/api/v1/auth/password-reset/complete",
        headers={"X-CSRF-Token": csrf},
        json={"token": deliveries[0][1], "new_password": "another-new-password-789"},
    )
    assert stale_reset.status_code == 400
    login_user(client, "change-password@example.com", password="a-changed-test-password-789")


def test_shared_project_access_is_read_only_even_for_developer_role(client: TestClient):
    register_user(client, "owner2@example.com")
    owner = login_user(client, "owner2@example.com")
    project = client.post(
        "/api/v1/projects",
        headers={"X-CSRF-Token": owner["csrf_token"]},
        json={"name": "Shared project", "ecosystem": "python"},
    ).json()
    register_user(client, "reader@example.com")
    grant = client.post(
        f"/api/v1/projects/{project['id']}/members",
        headers={"X-CSRF-Token": owner["csrf_token"]},
        json={"email": "reader@example.com"},
    )
    assert grant.status_code == 201

    client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": owner["csrf_token"]})
    reader = login_user(client, "reader@example.com")
    assert client.get(f"/api/v1/projects/{project['id']}").status_code == 200
    update = client.patch(
        f"/api/v1/projects/{project['id']}",
        headers={"X-CSRF-Token": reader["csrf_token"]},
        json={"name": "Unauthorized rename"},
    )
    assert update.status_code == 403
    members = client.get(f"/api/v1/projects/{project['id']}/members")
    assert members.status_code == 403


def test_security_center_sbom_policy_remediation_license_monitoring_and_notification_apis(
    client: TestClient, test_sessions: sessionmaker, monkeypatch,
):
    from app.api import features as feature_api

    register_user(client, "security-center@example.com")
    signed_in = login_user(client, "security-center@example.com")
    csrf = signed_in["csrf_token"]
    project_response = client.post("/api/v1/projects", headers={"X-CSRF-Token": csrf},
                                   json={"name": "Feature project", "description": "", "ecosystem": "javascript"})
    assert project_response.status_code == 201
    project_id = project_response.json()["id"]

    def bom(version: str):
        return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "components": [{"type": "library", "name": "demo-lib", "version": version,
                                "purl": f"pkg:npm/demo-lib@{version}", "bom-ref": f"pkg:npm/demo-lib@{version}"}]}

    imported = []
    for version in ("1.0.0", "1.1.0"):
        response = client.post(f"/api/v1/projects/{project_id}/sboms/import", headers={"X-CSRF-Token": csrf},
                               files={"file": (f"{version}.cdx.json", json.dumps(bom(version)), "application/json")})
        assert response.status_code == 201, response.text
        imported.append(response.json()["id"])
    compare = client.post(f"/api/v1/projects/{project_id}/sboms/compare",
                          json={"left": {"kind": "imported", "id": imported[0]},
                                "right": {"kind": "imported", "id": imported[1]}})
    assert compare.status_code == 200 and compare.json()["counts"]["changed"] == 1
    monkeypatch.setattr(feature_api, "query_components_cached", lambda db, components: (
        {0: [{"id": "OSV-IMPORT-TEST", "summary": "Fixture advisory", "aliases": [], "references": []}]}, "available"))
    matches = client.post(f"/api/v1/projects/{project_id}/sboms/{imported[0]}/vulnerabilities",
                          headers={"X-CSRF-Token": csrf})
    assert matches.status_code == 200 and matches.json()["items"][0]["version_confirmed_installed"] is False

    policy = {"max_allowed_priority": "Medium", "fail_on_kev": True, "partial_behavior": "fail",
              "unavailable_behavior": "warning", "fail_on_unknown_license": False,
              "allowed_licenses": ["MIT"], "restricted_licenses": []}
    assert client.put(f"/api/v1/projects/{project_id}/security-policy", headers={"X-CSRF-Token": csrf}, json=policy).status_code == 200

    with test_sessions() as db:
        owner = db.scalar(select(User).where(User.email == "security-center@example.com"))
        scan = Scan(project_id=UUID(project_id), requested_by=owner.id, status="completed", stage="Completed",
                    source_filename="package-lock.json", source_sha256="c" * 64, source_bytes=40,
                    intelligence_status={"osv": "available", "cisa_kev": "available"},
                    sbom_json={**bom("1.0.0"), "metadata": {"component": {"type": "application", "name": "Feature project"}}},
                    completed_at=datetime.now(timezone.utc))
        db.add(scan)
        db.flush()
        component = Component(scan_id=scan.id, name="demo-lib", version="1.0.0", ecosystem="npm",
                              purl="pkg:npm/demo-lib@1.0.0", directness="direct", resolution="resolved",
                              manifest="package-lock.json", license="MIT", dependencies=[])
        vulnerability = Vulnerability(osv_id="OSV-REMEDIATION-TEST", aliases=[], summary="Evidence fixture",
                                      details="", references=[], cwes=[])
        db.add_all([component, vulnerability])
        db.flush()
        db.add(Finding(scan_id=scan.id, component_id=component.id, vulnerability_id=vulnerability.id,
                       kev_status="known", priority="High", official_severity="High", fixed_versions=["1.1.0"],
                       affected_ranges=[{"type": "SEMVER", "events": [{"introduced": "0", "fixed": "1.1.0"}]}],
                       risk_score=80, risk_factors={}))
        alert = Notification(user_id=owner.id, project_id=UUID(project_id), event_key="api-test-alert",
                             event_type="new_vulnerability", title="New vulnerability", message="Review the finding.", payload={})
        db.add(alert)
        db.commit()
        scan_id, alert_id = str(scan.id), str(alert.id)

    result = client.post(f"/api/v1/scans/{scan_id}/policy/evaluate", headers={"X-CSRF-Token": csrf})
    assert result.status_code == 200 and result.json()["status"] == "FAIL"
    plan = client.get(f"/api/v1/scans/{scan_id}/remediation")
    assert plan.status_code == 200 and plan.json()["groups"]["urgent"][0]["recommended_target"] == "1.1.0"
    inventory = client.get(f"/api/v1/projects/{project_id}/licenses")
    assert inventory.status_code == 200 and inventory.json()["items"][0]["evidence_status"] == "declared_unverified"
    monkeypatch.setattr(feature_api, "fetch_registry_license", lambda ecosystem, name, version: {
        "license": "MIT", "status": "available", "source_url": "https://registry.npmjs.org/demo-lib/1.0.0"})
    refreshed = client.post(f"/api/v1/projects/{project_id}/licenses/refresh", headers={"X-CSRF-Token": csrf})
    assert refreshed.status_code == 200 and refreshed.json()["items"][0]["verified_metadata"] is True
    assert client.get(f"/api/v1/projects/{project_id}/licenses/report.pdf").headers["content-type"] == "application/pdf"
    schedule = client.put(f"/api/v1/projects/{project_id}/monitoring/schedule", headers={"X-CSRF-Token": csrf},
                          json={"interval_hours": 6, "active": True})
    assert schedule.status_code == 200 and schedule.json()["active"] is True
    paused = client.put(f"/api/v1/projects/{project_id}/monitoring/schedule", headers={"X-CSRF-Token": csrf},
                        json={"interval_hours": 12, "active": False})
    assert paused.status_code == 200 and not paused.json()["active"]
    assert client.post(f"/api/v1/notifications/{alert_id}/read", headers={"X-CSRF-Token": csrf}).status_code == 200

    with TestClient(main.app, raise_server_exceptions=False) as other:
        register_user(other, "other-center@example.com")
        other_session = login_user(other, "other-center@example.com")
        assert other.get(f"/api/v1/projects/{project_id}/sboms").status_code == 404
        assert other.get(f"/api/v1/projects/{project_id}/security-policy").status_code == 404
        assert other.post(f"/api/v1/notifications/{alert_id}/read",
                          headers={"X-CSRF-Token": other_session["csrf_token"]}).status_code == 404
